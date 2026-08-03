"""Agent Core — pure ReAct AI Agent framework.

Thought → Action → Observation → Thought → Action → ...

LLM does all cognition. The framework only routes tool calls.
No phases, no rule engines, no event bus — just the ReAct loop.

Usage:
    from agent_core import Agent, LLMClient
    from agent_core.tools import BaseTool, ToolMetadata

    class MyTool(BaseTool):
        metadata = ToolMetadata(name="my_tool", description="...", actions=["do"])
        async def execute(self, action, **kwargs):
            return {"result": "done"}

    llm = LLMClient(api_key="sk-...", base_url="...", model="...")
    agent = Agent(llm=llm, max_steps=10)
    agent.register_tool(MyTool())
    result = await agent.run("My goal")
    print(result)
"""

from agent_core.core.agent import Agent
from agent_core.core.llm_client import LLMClient
from agent_core.tools.base import BaseTool, ToolMetadata
from agent_core.tools.manager import ToolManager
from agent_core.tools.registry import ToolRegistry

__version__ = "0.2.0"
__all__ = [
    # Core
    "Agent",
    "LLMClient",
    # Tools
    "BaseTool",
    "ToolMetadata",
    "ToolManager",
    "ToolRegistry",
]
