"""LLMClient — unified LLM API interface.

Supports Anthropic-compatible APIs (DeepSeek, Claude, etc.).
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class LLMClient:
    """Unified LLM client for Anthropic-compatible APIs.

    Usage:
        llm = LLMClient(
            api_key="sk-...",
            base_url="https://api.deepseek.com/anthropic",
            model="deepseek-v4-pro",
        )
        response = await llm.chat([
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Hello"},
        ])
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.anthropic.com",
        model: str = "claude-sonnet-5-20251001",
        max_tokens: int = 4096,
        temperature: float = 0.3,
        timeout: float = 180.0,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout = timeout

    async def chat_raw(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Send messages with native tool_use support. Returns raw API response dict.

        Args:
            system: System prompt string.
            messages: List of {"role": "user|assistant", "content": ...}
            tools: Optional list of Anthropic-format tool schemas.

        Returns:
            Raw API response dict with "content" and "stop_reason" keys.
        """
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

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(url, json=payload, headers=headers)

            if resp.status_code != 200:
                raise RuntimeError(
                    f"LLM API error [{resp.status_code}]: {resp.text[:500]}"
                )

            return resp.json()

    async def chat(self, messages: list[dict[str, Any]]) -> str:
        """Send messages to the LLM and return the text response.

        Args:
            messages: List of {"role": "system|user|assistant", "content": "..."}

        Returns:
            The LLM's text response.
        """
        url = f"{self.base_url}/v1/messages"

        # Extract system message if present
        system = ""
        api_messages: list[dict[str, Any]] = []
        for msg in messages:
            if msg["role"] == "system":
                system = msg["content"]
            else:
                api_messages.append(msg)

        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": api_messages,
        }
        if system:
            payload["system"] = system

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "anthropic-version": "2023-06-01",
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(url, json=payload, headers=headers)

            if resp.status_code != 200:
                raise RuntimeError(
                    f"LLM API error [{resp.status_code}]: {resp.text[:500]}"
                )

            data = resp.json()
            return self._extract_text(data)

    def _extract_text(self, data: dict) -> str:
        """Extract text from API response, handling DeepSeek thinking blocks."""
        content = data.get("content", [])
        if isinstance(content, str):
            return content

        text_parts = []
        thinking_parts = []

        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    t = block.get("type", "")
                    if t == "text" and "text" in block:
                        text_parts.append(block["text"])
                    elif t == "thinking" and "thinking" in block:
                        thinking_parts.append(block["thinking"])

        if text_parts:
            return "\n".join(text_parts)
        if thinking_parts:
            return "\n".join(thinking_parts)

        # Fallback: OpenAI format
        if "choices" in data:
            return data["choices"][0].get("message", {}).get("content", "")

        logger.warning("LLMClient: unknown response format: %s",
                       json.dumps(data, ensure_ascii=False)[:300])
        return ""

    def __repr__(self) -> str:
        return f"<LLMClient(model={self.model}, base_url={self.base_url})>"
