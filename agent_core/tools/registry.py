"""ToolRegistry — manages all registered tools."""

from __future__ import annotations

import logging
from typing import Any

from agent_core.tools.base import BaseTool, ToolMetadata

logger = logging.getLogger(__name__)


class ToolRegistry:
    """Registry of all available tools.

    Tools are registered by name. The registry is the single source of
    truth for which tools are available. The Agent queries the registry
    to discover capabilities, and ToolManager uses it to route execution.
    """

    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        """Register a tool instance.

        Args:
            tool: The tool to register.

        Raises:
            ValueError: If a tool with the same name is already registered.
        """
        name = tool.metadata.name
        if name in self._tools:
            raise ValueError(f"Tool '{name}' is already registered")
        self._tools[name] = tool
        logger.info("Registered tool: %s (actions: %s)", name, tool.metadata.actions)

    def unregister(self, name: str) -> BaseTool | None:
        """Remove a tool from the registry.

        Args:
            name: Name of the tool to remove.

        Returns:
            The removed tool, or None if not found.
        """
        tool = self._tools.pop(name, None)
        if tool:
            logger.info("Unregistered tool: %s", name)
        return tool

    def get(self, name: str) -> BaseTool | None:
        """Get a tool by name.

        Args:
            name: Tool name.

        Returns:
            The tool instance or None.
        """
        return self._tools.get(name)

    def list_tools(self) -> list[str]:
        """Get all registered tool names."""
        return list(self._tools.keys())

    def list_metadata(self) -> list[ToolMetadata]:
        """Get metadata for all registered tools."""
        return [tool.metadata for tool in self._tools.values()]

    def get_available_actions(self) -> dict[str, list[str]]:
        """Get all tools and their actions.

        Returns:
            Dict mapping tool name -> list of action names.
        """
        return {name: tool.metadata.actions for name, tool in self._tools.items()}

    async def initialize_all(self) -> None:
        """Initialize all registered tools."""
        for name, tool in self._tools.items():
            try:
                await tool.initialize()
                logger.debug("Initialized tool: %s", name)
            except Exception:
                logger.exception("Failed to initialize tool: %s", name)

    async def shutdown_all(self) -> None:
        """Shut down all registered tools."""
        for name, tool in self._tools.items():
            try:
                await tool.shutdown()
                logger.debug("Shut down tool: %s", name)
            except Exception:
                logger.exception("Failed to shut down tool: %s", name)

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)

    def __repr__(self) -> str:
        return f"<ToolRegistry({len(self._tools)} tools: {list(self._tools.keys())})>"
