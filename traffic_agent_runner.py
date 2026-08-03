"""流量分析 Agent 运行器 — QThread + agent-core ReAct（DeepSeek /anthropic）。"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Callable

import httpx
from PyQt6.QtCore import QThread, pyqtSignal

from ai_config import load_ai_config, resolve_agent_base_url
from traffic_agent_tools import SessionData, build_traffic_tools

from agent_core import Agent, LLMClient

logger = logging.getLogger(__name__)

TRAFFIC_SYSTEM_PROMPT = """你是 TrafficEye 流量安全研判 Agent。

工作方式:
1. 必须先用只读工具取证，禁止编造未在工具结果中出现的 IP、URL、规则或匹配内容。
2. 可用工具：
   - risk：summary / list / get（内存中的安全风险统计）
   - stats：overview / top_urls / top_ips / url_detail（访问统计）
   - search：按关键字搜 URL / IP / 风险（内存）
   - artifact：读取分析落盘文件。list 查看；read/search 可读 PCAP 明文流量(traffic) 与统计 JSON(stats_json)
3. 研判顺序建议：
   - 先 risk.summary / risk.list 看规则命中
   - 若有 PCAP 明文，用 artifact.list → artifact.search / artifact.read 核对报文上下文
   - 再用 stats 补充访问面
4. 大文件不要整文件读：用 search 定位，再 read(offset/length) 取片段。
5. 调查够用就收工；不要无意义重复同一工具调用。
6. 最终用中文输出，结构固定为：
   【结论】
   【依据】（引用具体等级/规则/URL/IP，必要时引用流量文件片段）
   【建议】
7. 若工具显示无风险，也要明确说明；可结合明文流量做观察建议。
"""

SECURITY_REVIEW_GOAL = (
    "请对当前已完成的流量/日志分析结果做一次安全研判。"
    "先 risk.summary，再对严重与高危 risk.list；"
    "若 artifact.list 显示有 traffic（PCAP 明文），对高危相关关键字做 artifact.search，"
    "必要时 artifact.read 查看报文上下文；再用 stats.overview / top_urls 补充。"
    "最后按【结论】【依据】【建议】输出中文报告；不要编造工具未返回的数据。"
)


def _proxy_url(cfg: dict) -> str | None:
    if not cfg.get("use_http_proxy"):
        return None
    p = str(cfg.get("http_proxy") or "").strip()
    if not p:
        return None
    if not p.startswith("http"):
        p = f"http://{p}"
    return p


class ProxiedLLMClient(LLMClient):
    """支持可选 HTTP 代理的 Anthropic Messages 客户端."""

    def __init__(self, *args: Any, proxy: str | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.proxy = proxy

    async def chat_raw(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        url = f"{self.base_url}/v1/messages"
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": messages,
            "system": system,
        }
        if tools:
            payload["tools"] = tools
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "anthropic-version": "2023-06-01",
        }
        async with httpx.AsyncClient(timeout=self.timeout, proxy=self.proxy) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                raise RuntimeError(
                    f"LLM API error [{resp.status_code}]: {resp.text[:500]}"
                )
            return resp.json()


class TrafficAgent(Agent):
    """流量研判专用工具 schema + 可取消 ReAct 循环."""

    def __init__(
        self,
        *args: Any,
        cancel_check: Callable[[], bool] | None = None,
        on_step: Callable[[str], None] | None = None,
        **kwargs: Any,
    ) -> None:
        kwargs.setdefault("system_prompt", TRAFFIC_SYSTEM_PROMPT)
        kwargs.setdefault("verbose", False)
        super().__init__(*args, **kwargs)
        self._cancel_check = cancel_check or (lambda: False)
        self._on_step = on_step

    def _emit(self, msg: str) -> None:
        if self._on_step:
            try:
                self._on_step(msg)
            except Exception:
                pass

    def _build_tool_schemas(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "risk",
                "description": (
                    "只读查询安全风险。summary=等级统计；"
                    "list 可按 level 过滤；get 需 index。"
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["summary", "list", "get"],
                        },
                        "level": {
                            "type": "string",
                            "description": "list 时过滤：严重/高危/中危/低危/信息",
                        },
                        "index": {"type": "integer", "description": "get 时风险下标"},
                        "limit": {"type": "integer"},
                        "offset": {"type": "integer"},
                    },
                    "required": ["action"],
                },
            },
            {
                "name": "stats",
                "description": (
                    "只读访问统计。overview / top_urls / top_ips / url_detail。"
                    "url_detail 需要 url。"
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["overview", "top_urls", "top_ips", "url_detail"],
                        },
                        "url": {"type": "string"},
                        "limit": {"type": "integer"},
                    },
                    "required": ["action"],
                },
            },
            {
                "name": "search",
                "description": "关键字搜索 URL / IP / 风险。需要 query。",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["query"],
                        },
                        "query": {"type": "string", "description": "搜索关键字"},
                        "limit": {"type": "integer"},
                    },
                    "required": ["action"],
                },
            },
            {
                "name": "artifact",
                "description": (
                    "只读分析落盘文件。list 列出；info/read/search。"
                    "which=traffic 读 PCAP 明文；which=stats_json 读统计 JSON。"
                    "search 需 query；read 可用 offset/length 分页。"
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["list", "info", "read", "search"],
                        },
                        "which": {
                            "type": "string",
                            "description": "traffic | stats_json",
                        },
                        "path": {"type": "string", "description": "可选，list 返回的路径"},
                        "query": {"type": "string", "description": "search 关键字"},
                        "offset": {"type": "integer", "description": "read 起始字符偏移"},
                        "length": {"type": "integer", "description": "read 长度，最大约 10000"},
                        "limit": {"type": "integer"},
                    },
                    "required": ["action"],
                },
            },
        ]

    async def _execute(self, tool_name: str, action: str, inputs: dict) -> str:
        try:
            tool = self._tools.get(tool_name)
            if tool is None:
                return (
                    f"Error: Tool '{tool_name}' not found. "
                    f"Available: {self._tools.list_tools()}"
                )
            args = {k: v for k, v in inputs.items() if k != "action"}
            if action:
                await tool.validate(action, **args)
            result = await tool.execute(action, **args)
            result_str = json.dumps(result, ensure_ascii=False)
            limit = 12000
            if tool_name == "artifact":
                limit = 14000
            if len(result_str) > limit:
                result_str = (
                    result_str[:limit]
                    + f"...(truncated, total {len(result_str)} chars; 请缩小 limit 或分页)"
                )
            return result_str
        except Exception as e:
            return f"Error: {e}"

    async def run(self, goal: str) -> str:
        if self._cancel_check():
            raise RuntimeError("已取消")

        system = self._build_system_prompt()
        messages: list[dict[str, Any]] = [{"role": "user", "content": goal}]
        tools = self._build_tool_schemas()
        await self._tools.initialize_all()
        seen_calls: dict[str, int] = {}

        for step in range(1, self.max_steps + 1):
            if self._cancel_check():
                await self._tools.shutdown_all()
                raise RuntimeError("已取消")

            self._emit(f"[step {step}] 思考中…")
            try:
                response = await self._call_llm(system, messages, tools)
            except Exception as e:
                logger.error("LLM call failed at step %d: %s", step, e)
                self._emit(f"[step {step}] API 错误，重试: {e}")
                await asyncio.sleep(2)
                if self._cancel_check():
                    await self._tools.shutdown_all()
                    raise RuntimeError("已取消")
                continue

            thought, tool_calls, _stop = self._parse(response)
            messages.append({"role": "assistant", "content": response.get("content", [])})

            if not tool_calls:
                self._emit(f"[step {step}] 完成")
                await self._tools.shutdown_all()
                return thought or "任务完成。"

            tool_results = []
            for tc in tool_calls:
                if self._cancel_check():
                    await self._tools.shutdown_all()
                    raise RuntimeError("已取消")
                tool_name = tc["name"]
                tool_input = tc.get("input", {}) or {}
                action = tool_input.get("action", "")
                sig = json.dumps(
                    {"t": tool_name, "a": action, "i": tool_input},
                    ensure_ascii=False,
                    sort_keys=True,
                )
                seen_calls[sig] = seen_calls.get(sig, 0) + 1
                if seen_calls[sig] >= 3:
                    self._emit(f"[step {step}] ⚠ 重复调用 {tool_name}.{action}，跳过")
                    result = json.dumps(
                        {
                            "error": "同一调用已执行多次，请综合已有结果给出结论，勿再重复。",
                        },
                        ensure_ascii=False,
                    )
                else:
                    self._emit(f"[step {step}] 🔧 {tool_name}.{action or 'query'}")
                    result = await self._execute(tool_name, action, tool_input)
                    preview = result.replace("\n", " ")[:220]
                    self._emit(f"  → {preview}")
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tc.get("id", ""),
                        "content": result,
                    }
                )
            messages.append({"role": "user", "content": tool_results})

        await self._tools.shutdown_all()
        return "已达最大步数。请根据已有工具结果自行整理结论，或缩小问题后再试。"


class AgentWorker(QThread):
    """后台运行流量 Agent，不阻塞 GUI."""

    log = pyqtSignal(str)
    finished_ok = pyqtSignal(str)
    failed = pyqtSignal(str)

    def __init__(
        self,
        goal: str,
        session: SessionData,
        cfg: dict | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self.goal = (goal or "").strip()
        self.session = session
        self.cfg = dict(cfg or load_ai_config())
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        try:
            api_key = str(self.cfg.get("api_key") or "").strip()
            if not api_key:
                self.failed.emit("请先在 AI 配置中填写 DeepSeek API Key（config/ai.yaml）")
                return
            if not self.goal:
                self.failed.emit("请输入 Agent 任务")
                return

            data = self.session.url_stats()
            has_file = bool(
                (self.session.stats_json_path() and os.path.isfile(self.session.stats_json_path()))
                or (self.session.traffic_file_path() and os.path.isfile(self.session.traffic_file_path()))
            )
            if not data and not has_file:
                self.failed.emit("暂无分析数据。请先完成流量/日志分析后再启动 Agent。")
                return

            if self.session.stats_json_path():
                self.log.emit(f"统计文件: {self.session.stats_json_path()}")
            if self.session.traffic_file_path():
                self.log.emit(f"流量明文: {self.session.traffic_file_path()}")

            base = resolve_agent_base_url(self.cfg)
            model = str(self.cfg.get("model") or "deepseek-chat").strip()
            try:
                max_steps = int(self.cfg.get("agent_max_steps") or 30)
            except (TypeError, ValueError):
                max_steps = 30
            max_steps = max(3, min(max_steps, 60))

            proxy = _proxy_url(self.cfg)
            self.log.emit(f"模型: {model}")
            self.log.emit(f"Agent 端点: {base}/v1/messages")
            if proxy:
                self.log.emit(f"代理: {proxy}")

            llm = ProxiedLLMClient(
                api_key=api_key,
                base_url=base,
                model=model,
                max_tokens=4096,
                temperature=0.2,
                timeout=180.0,
                proxy=proxy,
            )
            agent = TrafficAgent(
                llm=llm,
                max_steps=max_steps,
                system_prompt=TRAFFIC_SYSTEM_PROMPT,
                cancel_check=lambda: self._cancelled,
                on_step=lambda m: self.log.emit(m),
            )
            for tool in build_traffic_tools(self.session):
                agent.register_tool(tool)

            result = asyncio.run(agent.run(self.goal))
            if self._cancelled:
                self.failed.emit("已取消")
                return
            self.finished_ok.emit(result)
        except RuntimeError as e:
            msg = str(e)
            if "已取消" in msg or self._cancelled:
                self.failed.emit("已取消")
            else:
                self.failed.emit(msg)
        except Exception as e:
            logger.exception("AgentWorker failed")
            self.failed.emit(str(e))
