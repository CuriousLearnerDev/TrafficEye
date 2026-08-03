"""Base class for all tools.

Every tool must extend BaseTool. The Agent never imports tools directly —
all tool access goes through ToolManager.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolMetadata:
    """Metadata describing a tool's capabilities."""
    name: str
    description: str
    actions: list[str] = field(default_factory=list)
    version: str = "0.1.0"
    author: str = ""
    requires_auth: bool = False
    tags: list[str] = field(default_factory=list)


class BaseTool(ABC):
    """Abstract base for all pluggable tools.

    Subclass this to create a new tool:

        class HttpTool(BaseTool):
            metadata = ToolMetadata(
                name="http",
                description="HTTP client for web requests",
                actions=["get", "post", "put", "delete"],
            )

            async def execute(self, action: str, **kwargs) -> Any:
                ...
    """

    def __init__(self) -> None:
        self._initialized = False

    @property
    @abstractmethod
    def metadata(self) -> ToolMetadata:
        """Return this tool's metadata."""
        ...

    @abstractmethod
    async def execute(self, action: str, **kwargs: Any) -> Any:
        """Execute an action on this tool.

        Args:
            action: The action to perform (e.g., 'get', 'scan', 'click').
            **kwargs: Action-specific arguments.

        Returns:
            The tool's output (tool decides the format).

        Raises:
            ValueError: If the action is not supported.
            RuntimeError: If execution fails.
        """
        ...

    async def initialize(self) -> None:
        """Optional initialization before first use."""
        self._initialized = True

    async def shutdown(self) -> None:
        """Optional cleanup when the agent shuts down."""
        pass

    async def validate(self, action: str, **kwargs: Any) -> bool:
        """Validate arguments before execution.

        Override to add tool-specific validation logic.

        Args:
            action: The action to validate.
            **kwargs: Arguments to validate.

        Returns:
            True if valid.

        Raises:
            ValueError: If arguments are invalid.
        """
        if action not in self.metadata.actions:
            raise ValueError(
                f"Tool '{self.metadata.name}' does not support action '{action}'. "
                f"Available: {self.metadata.actions}"
            )
        return True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}({self.metadata.name} v{self.metadata.version})>"
