"""Plugin system for extending the Agent Core."""

from agent_core.plugins.base import AgentPlugin, PluginMetadata
from agent_core.plugins.loader import PluginLoader

__all__ = ["AgentPlugin", "PluginMetadata", "PluginLoader"]
