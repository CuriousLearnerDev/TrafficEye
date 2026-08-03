"""AI Agent 配置（DeepSeek Anthropic Messages）。"""

from __future__ import annotations

import os
from typing import Any

import yaml

ROOT = os.path.dirname(os.path.abspath(__file__))
AI_CONFIG_PATH = os.path.join(ROOT, "config", "ai.yaml")
LEGACY_CONFIG_PATH = os.path.join(ROOT, "config.yaml")

DEFAULT: dict[str, Any] = {
    "provider": "deepseek",
    "api_key": "",
    "base_url": "https://api.deepseek.com/v1",
    "model": "deepseek-chat",
    "http_proxy": "127.0.0.1:7897",
    "use_http_proxy": False,
    "agent_base_url": "",
    "agent_max_steps": 30,
}


def resolve_agent_base_url(cfg: dict) -> str:
    """Agent 用 Anthropic 兼容端点；DeepSeek 默认推成 /anthropic。"""
    explicit = str(cfg.get("agent_base_url") or "").strip().rstrip("/")
    if explicit:
        return explicit
    base = str(cfg.get("base_url") or "").strip().rstrip("/")
    if not base:
        return "https://api.deepseek.com/anthropic"
    low = base.lower()
    if "deepseek.com" in low:
        if low.endswith("/v1"):
            return base[: -len("/v1")] + "/anthropic"
        if low.endswith("/anthropic"):
            return base
        return base + "/anthropic"
    if low.endswith("/v1"):
        return base
    return base


def _legacy_deepseek_key() -> str:
    if not os.path.isfile(LEGACY_CONFIG_PATH):
        return ""
    try:
        with open(LEGACY_CONFIG_PATH, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return str(data.get("deepseek_api_key") or "").strip()
    except Exception:
        return ""


def load_ai_config() -> dict:
    cfg = dict(DEFAULT)
    if os.path.isfile(AI_CONFIG_PATH):
        try:
            with open(AI_CONFIG_PATH, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            if isinstance(data, dict):
                cfg.update({k: v for k, v in data.items() if k in DEFAULT or k in data})
        except Exception:
            pass
    if not str(cfg.get("api_key") or "").strip():
        legacy = _legacy_deepseek_key()
        if legacy:
            cfg["api_key"] = legacy
    return cfg


def save_ai_config(cfg: dict) -> None:
    os.makedirs(os.path.dirname(AI_CONFIG_PATH), exist_ok=True)
    out = dict(DEFAULT)
    out.update(cfg or {})
    with open(AI_CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(out, f, allow_unicode=True, default_flow_style=False)


def _proxy_url(cfg: dict) -> str | None:
    if not cfg.get("use_http_proxy"):
        return None
    p = str(cfg.get("http_proxy") or "").strip()
    if not p:
        return None
    if not p.startswith("http"):
        p = f"http://{p}"
    return p


def test_agent_connection(cfg: dict, timeout: float = 25.0) -> tuple[bool, str]:
    """向 Agent 端点发一条极短 messages 请求，验证 Key / URL / 代理。"""
    import httpx

    api_key = str(cfg.get("api_key") or "").strip()
    if not api_key:
        return False, "请先填写 API Key"
    model = str(cfg.get("model") or "deepseek-chat").strip() or "deepseek-chat"
    base = resolve_agent_base_url(cfg)
    url = f"{base.rstrip('/')}/v1/messages"
    proxy = _proxy_url(cfg)
    payload = {
        "model": model,
        "max_tokens": 16,
        "temperature": 0,
        "messages": [{"role": "user", "content": "ping"}],
        "system": "Reply with exactly: ok",
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "anthropic-version": "2023-06-01",
    }
    try:
        with httpx.Client(timeout=timeout, proxy=proxy) as client:
            resp = client.post(url, json=payload, headers=headers)
        if resp.status_code != 200:
            detail = (resp.text or "")[:280].replace("\n", " ")
            return False, f"HTTP {resp.status_code} · {url}\n{detail}"

        data = resp.json()
        # Anthropic 风格：content 为块列表
        text = ""
        content = data.get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    text += str(block.get("text") or "")
        elif isinstance(content, str):
            text = content
        preview = (text or str(data.get("stop_reason") or "ok")).strip()[:80]
        proxy_hint = f" · 代理 {proxy}" if proxy else ""
        return True, f"连接成功 · {model}{proxy_hint}\n端点: {url}\n回复: {preview or '(空)'}"
    except httpx.TimeoutException:
        return False, f"连接超时（{timeout}s）· {url}"
    except Exception as e:
        return False, f"连接失败 · {url}\n{e}"
