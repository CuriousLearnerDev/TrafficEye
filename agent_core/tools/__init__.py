"""Pluggable tool management system.

All tool execution goes through ToolManager — the Agent never
calls tools directly. Tools are registered via plugins.
"""

from agent_core.tools.base import BaseTool, ToolMetadata
from agent_core.tools.registry import ToolRegistry
from agent_core.tools.manager import ToolManager

__all__ = [
    "BaseTool",
    "ToolMetadata",
    "ToolRegistry",
    "ToolManager",
]
