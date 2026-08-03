"""Agent — pure ReAct loop with native tool_use (like Claude Code).

Thought → Tool Call → Tool Result → Thought → ...

LLM outputs native tool_use blocks. No text parsing needed.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from agent_core.core.llm_client import LLMClient
from agent_core.tools.base import BaseTool
from agent_core.tools.registry import ToolRegistry

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


class Agent:
    """Autonomous agent with native tool_use — just like Claude Code.

    Usage:
        llm = LLMClient(api_key="...", base_url="...", model="...")
        agent = Agent(llm=llm)
        agent.register_tool(HttpTool())
        result = await agent.run("Scan target.com")
    """

    SYSTEM_PROMPT = "You are an autonomous security agent. For each finding, form a hypothesis, test it, observe the result, and decide your next move based on what you learn."

    def __init__(
        self,
        llm: LLMClient,
        max_steps: int = 50,
        system_prompt: str | None = None,
        verbose: bool = True,
        debug: bool = False,
    ) -> None:
        self.llm = llm
        self.max_steps = max_steps
        self.verbose = verbose
        self.debug = debug
        self._system_prompt = system_prompt or self.SYSTEM_PROMPT
        self._tools: ToolRegistry = ToolRegistry()

    def register_tool(self, tool: BaseTool) -> None:
        self._tools.register(tool)

    def _build_tool_schemas(self) -> list[dict[str, Any]]:
        """Build Anthropic-format tool schemas from registered tools."""
        schemas = []
        for name in self._tools.list_tools():
            tool = self._tools.get(name)
            if not tool:
                continue
            # Build input_schema from action names
            # Each action is a potential use, so we use a generic approach:
            # required: ["tool", "action"] + tool-specific args can be in properties
            schemas.append({
                "name": name,
                "description": tool.metadata.description,
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "description": f"Action to perform. One of: {tool.metadata.actions}",
                            "enum": tool.metadata.actions,
                        },
                        **{
                            arg: {"type": "string", "description": f"Argument: {arg}"}
                            for arg in ["url", "target", "prompt", "text", "content", "system", "path"]
                            if arg not in ["action"]
                        },
                    },
                    "required": ["action"],
                },
            })
        return schemas

    async def run(self, goal: str) -> str:
        """Run the ReAct loop until completion."""
        system = self._build_system_prompt()

        messages: list[dict[str, Any]] = [
            {"role": "user", "content": goal},
        ]
        tools = self._build_tool_schemas()

        await self._tools.initialize_all()

        for step in range(1, self.max_steps + 1):
            if self.debug:
                print(f"\n{'█' * 60}")
                print(f"📤 Step {step}")
                for i, msg in enumerate(messages[-2:]):
                    content = str(msg.get("content", ""))
                    if len(content) > 500:
                        content = content[:500] + "..."
                    print(f"  [{i}] <{msg['role']}>: {content[:300]}")
                print(f"{'█' * 60}")

            # Call LLM with tools
            try:
                response = await self._call_llm(system, messages, tools)
            except Exception as e:
                logger.error("LLM call failed at step %d: %s", step, e)
                if self.verbose:
                    print(f"\n  ⚠️ LLM API 错误: {e}")
                    print(f"  等待 3 秒后重试...")
                await asyncio.sleep(3)
                continue

            # Parse native tool_use or text
            thought, tool_calls, stop_reason = self._parse(response)

            if self.debug:
                print(f"📥 thought={thought[:200] if thought else 'none'}")
                for tc in tool_calls:
                    print(f"📥 tool_use: {tc['name']}.{tc['input'].get('action', '?')}")
                print(f"{'█' * 60}")

            # Store assistant response in history
            messages.append({
                "role": "assistant",
                "content": response.get("content", []),
            })

            # Check if done (no tool calls, model is responding)
            if not tool_calls:
                # Model is just talking — it's done
                if self.verbose:
                    print(f"\n  ✅ Agent finished at step {step}")
                await self._tools.shutdown_all()
                return thought or "Task completed."

            # Execute all tool calls and collect results
            tool_results = []
            for tc in tool_calls:
                tool_name = tc["name"]
                tool_input = tc.get("input", {})
                action = tool_input.get("action", "")

                if self.verbose:
                    print(f"\n{'─' * 50}")
                    print(f"  Step {step}/{self.max_steps}")
                    if thought:
                        print(f"  💭 {thought[:200]}")
                    print(f"  🔧 {tool_name}.{action}")
                    print(f"{'─' * 50}")

                result = await self._execute(tool_name, action, tool_input)

                if self.verbose:
                    preview = result[:300].replace("\n", " ")
                    print(f"  📡 {preview}...")

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tc.get("id", ""),
                    "content": result,
                })

            # All tool_results in ONE user message (Anthropic requirement)
            messages.append({"role": "user", "content": tool_results})

        await self._tools.shutdown_all()
        return "Max steps reached."

    async def _call_llm(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Call LLM with native tool_use support. Returns raw API response."""
        return await self.llm.chat_raw(system, messages, tools)

    def _parse(self, response: dict) -> tuple[str, list[dict], str]:
        """Parse LLM response: extract thought, tool_calls, stop_reason."""
        content = response.get("content", [])
        if isinstance(content, str):
            return content, [], "end_turn"

        thought = ""
        tool_calls = []
        stop_reason = response.get("stop_reason", "")

        for block in content:
            t = block.get("type", "")
            if t == "text":
                thought += block.get("text", "")
            elif t == "thinking":
                thought += block.get("thinking", "")
            elif t == "tool_use":
                tool_calls.append(block)

        return thought.strip(), tool_calls, stop_reason

    async def _execute(self, tool_name: str, action: str, inputs: dict) -> str:
        """Execute a tool and return formatted result."""
        try:
            tool = self._tools.get(tool_name)
            if tool is None:
                return f"Error: Tool '{tool_name}' not found. Available: {self._tools.list_tools()}"

            # Filter out non-arg keys (action is a meta-key, rest are args)
            args = {k: v for k, v in inputs.items() if k != "action"}
            if action:
                await tool.validate(action, **args)
            result = await tool.execute(action, **args)

            result_str = json.dumps(result, ensure_ascii=False)
            if len(result_str) > 3000:
                result_str = result_str[:3000] + f"...(truncated, {len(result_str)} chars)"

            return result_str
        except Exception as e:
            return f"Error: {e}"

    def _build_system_prompt(self) -> str:
        """Minimal system prompt with tool list."""
        tool_names = ", ".join(self._tools.list_tools())
        return f"{self._system_prompt}\nAvailable tools: {tool_names}."
