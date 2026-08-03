"""PluginLoader — discovers and loads plugins."""

from __future__ import annotations

import importlib
import importlib.metadata
import logging
import sys
from pathlib import Path
from typing import Any

from agent_core.plugins.base import AgentPlugin
from agent_core.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

PLUGIN_ENTRY_POINT_GROUP = "agent_core.plugins"


class PluginLoader:
    """Discovers, loads, and manages agent plugins."""

    def __init__(self) -> None:
        self._plugins: dict[str, AgentPlugin] = {}

    def register(self, plugin: AgentPlugin) -> None:
        """Register a plugin instance."""
        name = plugin.metadata.name
        if name in self._plugins:
            logger.warning("Plugin '%s' already registered, replacing", name)
        self._plugins[name] = plugin
        logger.info("Plugin registered: %s v%s", name, plugin.metadata.version)

    def get(self, name: str) -> AgentPlugin | None:
        """Get a loaded plugin by name."""
        return self._plugins.get(name)

    def list_plugins(self) -> list[str]:
        """Get all loaded plugin names."""
        return list(self._plugins.keys())

    async def mount_all(self, tool_registry: ToolRegistry) -> None:
        """Mount all registered plugins into the tool registry."""
        for name, plugin in self._plugins.items():
            try:
                await plugin.mount(tool_registry)
                logger.info("Plugin '%s' mounted", name)
            except Exception:
                logger.exception("Failed to mount plugin '%s'", name)

    async def unmount_all(self) -> None:
        """Unmount all plugins."""
        for name, plugin in self._plugins.items():
            try:
                await plugin.unmount()
                logger.info("Plugin '%s' unmounted", name)
            except Exception:
                logger.exception("Failed to unmount plugin '%s'", name)

    async def shutdown_all(self) -> None:
        """Shut down all plugins."""
        for name, plugin in self._plugins.items():
            try:
                await plugin.shutdown()
            except Exception:
                logger.exception("Failed to shutdown plugin '%s'", name)
        self._plugins.clear()

    @classmethod
    def discover_entry_points(cls) -> list[type[AgentPlugin]]:
        """Discover plugins via setuptools entry points."""
        discovered: list[type[AgentPlugin]] = []
        try:
            entry_points = importlib.metadata.entry_points(group=PLUGIN_ENTRY_POINT_GROUP)
            for ep in entry_points:
                try:
                    plugin_cls = ep.load()
                    if issubclass(plugin_cls, AgentPlugin):
                        discovered.append(plugin_cls)
                        logger.info("Discovered plugin: %s", ep.name)
                except Exception:
                    logger.exception("Failed to load plugin: %s", ep.name)
        except Exception:
            logger.debug("No entry points for group '%s'", PLUGIN_ENTRY_POINT_GROUP)
        return discovered

    def load_from_entry_points(self) -> int:
        """Load all entry-point plugins. Returns count loaded."""
        count = 0
        for plugin_cls in self.discover_entry_points():
            try:
                self.register(plugin_cls())
                count += 1
            except Exception:
                logger.exception("Failed to instantiate: %s", plugin_cls.__name__)
        return count
