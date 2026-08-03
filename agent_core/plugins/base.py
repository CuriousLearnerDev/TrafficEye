"""Base plugin class — tool extension mechanism."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from agent_core.tools.base import BaseTool
from agent_core.tools.registry import ToolRegistry


@dataclass
class PluginMetadata:
    """Metadata describing a plugin."""
    name: str
    version: str = "0.1.0"
    description: str = ""
    author: str = ""
    dependencies: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


class AgentPlugin(ABC):
    """Base class for all agent plugins.

    A plugin provides tools to the agent via get_tools().

    Lifecycle:
        __init__ -> mount -> (agent runs) -> unmount -> shutdown
    """

    def __init__(self) -> None:
        self._mounted = False
        self._registry: ToolRegistry | None = None

    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Plugin metadata."""
        ...

    @property
    def registry(self) -> ToolRegistry:
        """Access the tool registry (available after mount)."""
        if self._registry is None:
            raise RuntimeError("Plugin not mounted")
        return self._registry

    @property
    def is_mounted(self) -> bool:
        """Whether this plugin is currently mounted."""
        return self._mounted

    async def mount(self, registry: ToolRegistry) -> None:
        """Mount the plugin with access to the tool registry.

        Args:
            registry: The agent's tool registry.
        """
        self._registry = registry
        for tool in self.get_tools():
            registry.register(tool)
        self._mounted = True
        await self.on_mount()

    async def on_mount(self) -> None:
        """Override for initialization after mount."""
        pass

    async def unmount(self) -> None:
        """Called when plugin is unloaded."""
        await self.on_unmount()
        self._mounted = False
        self._registry = None

    async def on_unmount(self) -> None:
        """Override for cleanup before unmount."""
        pass

    async def shutdown(self) -> None:
        """Final cleanup."""
        pass

    def get_tools(self) -> list[BaseTool]:
        """Return tools this plugin provides. Override this."""
        return []

    def __repr__(self) -> str:
        status = "mounted" if self._mounted else "unmounted"
        return f"<{self.__class__.__name__}({self.metadata.name}) [{status}]>"
