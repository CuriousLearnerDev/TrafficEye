"""流量分析 Agent 工具 — 只读查询 url_stats / 风险，不改内容."""

from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import unquote

from agent_core.tools.base import BaseTool, ToolMetadata

MAX_LIST = 40
MAX_SEARCH = 30
MAX_CONTEXT = 800
MAX_FILE_CHUNK = 10_000
MAX_FILE_SEARCH_HITS = 25
MAX_SEARCH_CONTEXT = 400


def _clip(text: str, n: int) -> str:
    s = text or ""
    if len(s) <= n:
        return s
    return s[:n] + f"…(+{len(s) - n})"


def _ci_contains(hay: str, needle: str) -> bool:
    if not needle:
        return True
    return needle.casefold() in (hay or "").casefold()


def _short_ip(ip_key: str) -> str:
    if not ip_key:
        return ""
    for sep in ("：",):
        if sep in ip_key:
            return ip_key.split(sep, 1)[0].strip()
    # 形如 1.2.3.4:归属 且非纯 IPv6
    if ":" in ip_key and ip_key.count(":") == 1 and not ip_key.replace(".", "").replace(":", "").isdigit():
        left, right = ip_key.split(":", 1)
        if left.count(".") == 3:
            return left.strip()
    return ip_key


def _norm_severity(level: Any) -> str:
    text = str(level or "").strip()
    if not text:
        return "未知"
    lower = text.lower()
    mapping = [
        (("严重", "critical"), "严重"),
        (("高危", "high"), "高危"),
        (("中危", "medium", "中"), "中危"),
        (("低危", "low"), "低危"),
        (("信息", "info"), "信息"),
    ]
    for keys, norm in mapping:
        if any(k in lower or k in text for k in keys):
            return norm
    return text


@dataclass
class SessionData:
    """GUI 注入的只读分析数据 + 落盘产物路径."""

    url_stats_provider: Callable[[], dict] = field(default_factory=lambda: (lambda: {}))
    # 最近一次分析产物（绝对路径）
    stats_json_provider: Callable[[], str] = field(default_factory=lambda: (lambda: ""))
    traffic_file_provider: Callable[[], str] = field(default_factory=lambda: (lambda: ""))
    output_dir_provider: Callable[[], str] = field(default_factory=lambda: (lambda: "output"))

    def url_stats(self) -> dict:
        try:
            data = self.url_stats_provider() or {}
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def stats_json_path(self) -> str:
        try:
            return str(self.stats_json_provider() or "").strip()
        except Exception:
            return ""

    def traffic_file_path(self) -> str:
        try:
            return str(self.traffic_file_provider() or "").strip()
        except Exception:
            return ""

    def output_dir(self) -> str:
        try:
            d = str(self.output_dir_provider() or "output").strip() or "output"
            return os.path.abspath(d)
        except Exception:
            return os.path.abspath("output")


def collect_risks(url_stats: dict) -> list[dict]:
    """扁平化风险列表，带稳定 index."""
    risks: list[dict] = []
    seen = set()
    for url, stats in (url_stats or {}).items():
        if url == "_global_stats" or not isinstance(stats, dict):
            continue
        for src_ip, ip_stats in (stats.get("source_ips") or {}).items():
            if not isinstance(ip_stats, dict):
                continue
            for danger in ip_stats.get("danger") or []:
                if isinstance(danger, dict):
                    level = _norm_severity(danger.get("severity", "中危"))
                    item = {
                        "ip": src_ip,
                        "ip_short": _short_ip(src_ip),
                        "url": url,
                        "url_display": unquote(url),
                        "type": danger.get("rule_type") or "未知",
                        "level": level,
                        "rule": danger.get("rule_name") or "未知规则",
                        "content": danger.get("context") or danger.get("matched") or "",
                        "position": danger.get("position", (0, 0)),
                    }
                else:
                    item = {
                        "ip": src_ip,
                        "ip_short": _short_ip(src_ip),
                        "url": url,
                        "url_display": unquote(url),
                        "type": "未知",
                        "level": "中危",
                        "rule": str(danger),
                        "content": "",
                        "position": (0, 0),
                    }
                key = (item["ip_short"], item["url"], item["rule"], item["level"])
                if key in seen:
                    continue
                seen.add(key)
                item["index"] = len(risks)
                risks.append(item)
    return risks


class RiskTool(BaseTool):
    """只读查询安全风险."""

    def __init__(self, session: SessionData) -> None:
        super().__init__()
        self._session = session

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="risk",
            description=(
                "只读查询当前分析结果中的安全风险。"
                "summary=各等级计数；list=按等级列出；get=按 index 取详情。"
            ),
            actions=["summary", "list", "get"],
            tags=["security", "readonly"],
        )

    async def execute(self, action: str, **kwargs: Any) -> Any:
        risks = collect_risks(self._session.url_stats())
        if action == "summary":
            by_sev: dict[str, int] = defaultdict(int)
            by_type: dict[str, int] = defaultdict(int)
            for r in risks:
                by_sev[r["level"]] += 1
                by_type[r["type"]] += 1
            return {
                "total": len(risks),
                "by_severity": dict(by_sev),
                "by_type": dict(sorted(by_type.items(), key=lambda x: -x[1])[:20]),
                "unique_ips": len({r["ip_short"] for r in risks}),
                "unique_urls": len({r["url"] for r in risks}),
            }
        if action == "list":
            level = str(kwargs.get("level") or kwargs.get("severity") or "").strip()
            limit = int(kwargs.get("limit") or MAX_LIST)
            limit = max(1, min(limit, 100))
            offset = int(kwargs.get("offset") or 0)
            items = risks
            if level and level not in ("所有", "全部", "all"):
                items = [r for r in items if level in r["level"] or r["level"] == _norm_severity(level)]
            # 严重优先
            order = {"严重": 0, "高危": 1, "中危": 2, "低危": 3, "信息": 4}
            items = sorted(items, key=lambda r: (order.get(r["level"], 9), r["url"]))
            page = items[offset: offset + limit]
            return {
                "total_matched": len(items),
                "offset": offset,
                "count": len(page),
                "items": [
                    {
                        "index": r["index"],
                        "level": r["level"],
                        "type": r["type"],
                        "rule": r["rule"],
                        "ip": r["ip_short"],
                        "url": _clip(r["url_display"], 200),
                    }
                    for r in page
                ],
            }
        if action == "get":
            idx = int(kwargs.get("index") if kwargs.get("index") is not None else -1)
            if idx < 0 or idx >= len(risks):
                return {"error": f"index 越界，有效范围 0..{max(0, len(risks) - 1)}"}
            r = risks[idx]
            return {
                "index": r["index"],
                "level": r["level"],
                "type": r["type"],
                "rule": r["rule"],
                "ip": r["ip"],
                "url": r["url_display"],
                "position": r["position"],
                "content": _clip(str(r["content"]), MAX_CONTEXT * 2),
            }
        return {"error": f"未知 action: {action}，可用: summary|list|get"}


class StatsTool(BaseTool):
    """只读查询 URL/IP 访问统计."""

    def __init__(self, session: SessionData) -> None:
        super().__init__()
        self._session = session

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="stats",
            description=(
                "只读查询访问统计。"
                "overview=总量；top_urls / top_ips=排行；url_detail=某 URL 明细。"
            ),
            actions=["overview", "top_urls", "top_ips", "url_detail"],
            tags=["traffic", "readonly"],
        )

    async def execute(self, action: str, **kwargs: Any) -> Any:
        data = self._session.url_stats()
        urls = {k: v for k, v in data.items() if k != "_global_stats" and isinstance(v, dict)}

        if action == "overview":
            ip_set = set()
            total_req = 0
            danger_urls = 0
            for url, st in urls.items():
                total_req += int(st.get("count") or 0)
                if int(st.get("danger_count") or 0) > 0:
                    danger_urls += 1
                for ip in (st.get("source_ips") or {}):
                    ip_set.add(_short_ip(ip))
            return {
                "unique_urls": len(urls),
                "unique_ips": len(ip_set),
                "total_requests": total_req,
                "urls_with_risk": danger_urls,
            }

        if action == "top_urls":
            limit = max(1, min(int(kwargs.get("limit") or 20), 50))
            ranked = sorted(
                urls.items(),
                key=lambda kv: int((kv[1] or {}).get("count") or 0),
                reverse=True,
            )[:limit]
            return {
                "items": [
                    {
                        "url": _clip(unquote(u), 200),
                        "count": int(st.get("count") or 0),
                        "danger_count": int(st.get("danger_count") or 0),
                        "ip_count": len(st.get("source_ips") or {}),
                    }
                    for u, st in ranked
                ]
            }

        if action == "top_ips":
            limit = max(1, min(int(kwargs.get("limit") or 20), 50))
            ip_counts: dict[str, int] = defaultdict(int)
            for st in urls.values():
                for ip, ip_st in (st.get("source_ips") or {}).items():
                    if isinstance(ip_st, dict):
                        ip_counts[_short_ip(ip)] += int(ip_st.get("count") or 0)
                    else:
                        ip_counts[_short_ip(ip)] += 1
            ranked = sorted(ip_counts.items(), key=lambda x: -x[1])[:limit]
            return {"items": [{"ip": ip, "count": c} for ip, c in ranked]}

        if action == "url_detail":
            query = str(kwargs.get("url") or kwargs.get("query") or "").strip()
            if not query:
                return {"error": "需要 url 参数"}
            matched = None
            for u, st in urls.items():
                if query == u or query in u or query in unquote(u):
                    matched = (u, st)
                    break
            if not matched:
                return {"error": "未找到匹配 URL", "hint": "可用 search 工具先找 URL"}
            u, st = matched
            ips = []
            for ip, ip_st in list((st.get("source_ips") or {}).items())[:30]:
                if not isinstance(ip_st, dict):
                    ips.append({"ip": _short_ip(ip), "count": 1})
                    continue
                ips.append({
                    "ip": _short_ip(ip),
                    "count": int(ip_st.get("count") or 0),
                    "status_codes": dict(list((ip_st.get("status_codes") or {}).items())[:10]),
                    "danger_n": len(ip_st.get("danger") or []),
                })
            return {
                "url": unquote(u),
                "count": int(st.get("count") or 0),
                "danger_count": int(st.get("danger_count") or 0),
                "ips": ips,
            }

        return {"error": f"未知 action: {action}，可用: overview|top_urls|top_ips|url_detail"}


class SearchTool(BaseTool):
    """关键字搜索 URL / IP / 风险."""

    def __init__(self, session: SessionData) -> None:
        super().__init__()
        self._session = session

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="search",
            description="在 URL、来源 IP、风险规则与匹配内容中按关键字搜索。需要 query。",
            actions=["query"],
            tags=["search", "readonly"],
        )

    async def execute(self, action: str, **kwargs: Any) -> Any:
        q = str(kwargs.get("query") or kwargs.get("q") or "").strip()
        if not q and action not in ("query", "search", ""):
            q = str(action or "").strip()
        if not q:
            return {"error": "需要 query 关键字"}

        limit = max(1, min(int(kwargs.get("limit") or MAX_SEARCH), 50))
        data = self._session.url_stats()
        url_hits = []
        ip_hits = []
        risk_hits = []

        for url, st in data.items():
            if url == "_global_stats" or not isinstance(st, dict):
                continue
            disp = unquote(url)
            if _ci_contains(disp, q) or _ci_contains(url, q):
                url_hits.append({
                    "url": _clip(disp, 200),
                    "count": int(st.get("count") or 0),
                    "danger_count": int(st.get("danger_count") or 0),
                })
            for ip, ip_st in (st.get("source_ips") or {}).items():
                if _ci_contains(ip, q) or _ci_contains(_short_ip(ip), q):
                    ip_hits.append({
                        "ip": _short_ip(ip),
                        "url": _clip(disp, 160),
                        "count": int((ip_st or {}).get("count") or 0) if isinstance(ip_st, dict) else 1,
                    })

        for r in collect_risks(data):
            blob = " ".join([r["url_display"], r["ip"], r["type"], r["rule"], str(r["content"])])
            if _ci_contains(blob, q):
                risk_hits.append({
                    "index": r["index"],
                    "level": r["level"],
                    "type": r["type"],
                    "rule": r["rule"],
                    "ip": r["ip_short"],
                    "url": _clip(r["url_display"], 160),
                    "snippet": _clip(str(r["content"]), 160),
                })

        return {
            "query": q,
            "urls": url_hits[:limit],
            "ips": ip_hits[:limit],
            "risks": risk_hits[:limit],
            "counts": {
                "urls": len(url_hits),
                "ips": len(ip_hits),
                "risks": len(risk_hits),
            },
        }

    async def validate(self, action: str, **kwargs: Any) -> bool:
        # 允许 action=query，或把关键字误放在 action
        if action in self.metadata.actions or kwargs.get("query") or kwargs.get("q"):
            return True
        if action and action not in ("query", "search"):
            return True
        raise ValueError(
            f"Tool 'search' 需要 query。Available actions: {self.metadata.actions}"
        )


class ArtifactTool(BaseTool):
    """只读读取分析落盘文件：统计 JSON、PCAP 明文流量等."""

    def __init__(self, session: SessionData) -> None:
        super().__init__()
        self._session = session

    @property
    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="artifact",
            description=(
                "只读访问分析产物文件。"
                "list=当前可用文件；info=文件信息；"
                "read=按偏移读内容（PCAP 明文/日志文本/JSON）；"
                "search=在明文流量文件中搜关键字。"
                "优先读当前会话的 stats_json 与 traffic（PCAP 明文）。"
            ),
            actions=["list", "info", "read", "search"],
            tags=["file", "pcap", "readonly"],
        )

    def _known_files(self) -> list[dict[str, Any]]:
        items = []
        stats = self._session.stats_json_path()
        traffic = self._session.traffic_file_path()
        if stats:
            items.append({"role": "stats_json", "path": os.path.abspath(stats)})
        if traffic:
            items.append({"role": "traffic", "path": os.path.abspath(traffic)})

        # 补充 output 目录下最近的相关文件（只列文件名，避免乱读）
        out = self._session.output_dir()
        if os.path.isdir(out):
            try:
                names = sorted(os.listdir(out), reverse=True)
            except Exception:
                names = []
            for name in names[:30]:
                low = name.lower()
                if not (low.endswith(".json") or low.endswith(".txt")):
                    continue
                if not (
                    low.startswith("output_")
                    or "pcap" in low
                    or "traffic" in low
                ):
                    continue
                full = os.path.abspath(os.path.join(out, name))
                if any(os.path.abspath(i["path"]) == full for i in items):
                    continue
                role = "other"
                if "traffic" in low:
                    role = "traffic_candidate"
                elif low.endswith(".json"):
                    role = "stats_candidate"
                items.append({"role": role, "path": full})
        return items

    def _resolve_path(self, which: str = "", path: str = "") -> str:
        """解析要读的文件：which=stats_json|traffic|path 显式路径（须在白名单内）."""
        which = (which or "").strip().lower()
        path = (path or "").strip()
        if which in ("stats", "stats_json", "json", "result"):
            p = self._session.stats_json_path()
            if p:
                return os.path.abspath(p)
        if which in ("traffic", "pcap", "full_traffic", "plain"):
            p = self._session.traffic_file_path()
            if p:
                return os.path.abspath(p)
            # 尝试从 stats 名推导 output_pcap_X.json → output_pcap_traffic_X.txt
            stats = self._session.stats_json_path()
            if stats:
                base = os.path.basename(stats)
                if "output_pcap_" in base and base.endswith(".json"):
                    cand = os.path.join(
                        os.path.dirname(stats),
                        base.replace("output_pcap_", "output_pcap_traffic_", 1).replace(
                            ".json", ".txt"
                        ),
                    )
                    if os.path.isfile(cand):
                        return os.path.abspath(cand)

        if path:
            abs_p = os.path.abspath(path)
            allowed = {os.path.abspath(i["path"]) for i in self._known_files()}
            out_root = self._session.output_dir()
            under_output = abs_p.startswith(out_root + os.sep) or abs_p == out_root
            if abs_p in allowed or under_output:
                return abs_p
            return ""

        # 默认：有 traffic 用 traffic，否则 stats
        t = self._session.traffic_file_path()
        if t and os.path.isfile(t):
            return os.path.abspath(t)
        s = self._session.stats_json_path()
        if s and os.path.isfile(s):
            return os.path.abspath(s)
        return ""

    async def execute(self, action: str, **kwargs: Any) -> Any:
        if action == "list":
            rows = []
            for it in self._known_files():
                p = it["path"]
                exists = os.path.isfile(p)
                size = os.path.getsize(p) if exists else 0
                rows.append({
                    "role": it["role"],
                    "path": p,
                    "exists": exists,
                    "size": size,
                    "name": os.path.basename(p),
                })
            return {
                "current_stats_json": self._session.stats_json_path() or None,
                "current_traffic": self._session.traffic_file_path() or None,
                "files": rows,
                "hint": "PCAP 明文用 which=traffic；统计结果用 which=stats_json",
            }

        which = str(kwargs.get("which") or kwargs.get("role") or "").strip()
        path = str(kwargs.get("path") or kwargs.get("file") or "").strip()
        target = self._resolve_path(which, path)

        if action == "info":
            if not target:
                return {"error": "未找到可读取文件。请先完成分析，或 artifact.list 查看。"}
            if not os.path.isfile(target):
                return {"error": f"文件不存在: {target}"}
            size = os.path.getsize(target)
            return {
                "path": target,
                "name": os.path.basename(target),
                "size": size,
                "ext": os.path.splitext(target)[1].lower(),
                "is_traffic": "traffic" in os.path.basename(target).lower(),
            }

        if action == "read":
            if not target:
                return {"error": "未找到可读取文件。用 artifact.list 后指定 which/path。"}
            if not os.path.isfile(target):
                return {"error": f"文件不存在: {target}"}
            offset = max(0, int(kwargs.get("offset") or 0))
            length = int(kwargs.get("length") or MAX_FILE_CHUNK)
            length = max(200, min(length, MAX_FILE_CHUNK))
            try:
                with open(target, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(0, os.SEEK_END)
                    total = f.tell()
                    f.seek(min(offset, total))
                    content = f.read(length)
            except Exception as e:
                return {"error": f"读取失败: {e}"}
            return {
                "path": target,
                "offset": offset,
                "length": len(content),
                "total_chars_approx": total,
                "next_offset": offset + len(content),
                "eof": offset + len(content) >= total,
                "content": content,
            }

        if action == "search":
            q = str(kwargs.get("query") or kwargs.get("q") or "").strip()
            if not q:
                return {"error": "需要 query"}
            # 搜索默认优先明文流量
            if not which and not path:
                target = self._resolve_path("traffic", "") or target
            if not target:
                return {"error": "没有可搜索的流量/结果文件"}
            if not os.path.isfile(target):
                return {"error": f"文件不存在: {target}"}
            limit = max(1, min(int(kwargs.get("limit") or MAX_FILE_SEARCH_HITS), 40))
            hits = []
            try:
                with open(target, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
                low = text.casefold()
                needle = q.casefold()
                start = 0
                while len(hits) < limit:
                    idx = low.find(needle, start)
                    if idx < 0:
                        break
                    a = max(0, idx - 120)
                    b = min(len(text), idx + len(q) + 120)
                    hits.append({
                        "offset": idx,
                        "snippet": _clip(text[a:b].replace("\n", " "), MAX_SEARCH_CONTEXT),
                    })
                    start = idx + max(1, len(q))
            except Exception as e:
                return {"error": f"搜索失败: {e}"}

            return {
                "path": target,
                "query": q,
                "count": len(hits),
                "hits": hits,
                "hint": "可用 artifact.read 并带 offset 查看该位置上下文",
            }

        return {"error": f"未知 action: {action}，可用: list|info|read|search"}


def build_traffic_tools(session: SessionData) -> list[BaseTool]:
    return [
        RiskTool(session),
        StatsTool(session),
        SearchTool(session),
        ArtifactTool(session),
    ]
