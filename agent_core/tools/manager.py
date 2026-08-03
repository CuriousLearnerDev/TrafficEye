"""ToolManager — single interface for tool execution.

All tool access goes through: ToolManager.execute(tool_name, action, args) -> Result
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from agent_core.models.task import Task, TaskStatus
from agent_core.models.result import Result, ResultStatus
from agent_core.tools.base import BaseTool
from agent_core.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


class ToolManager:
    """Centralized tool execution manager.

    Responsibilities:
    - Route execution to the correct tool
    - Validate arguments before execution
    - Handle timeouts
    - Return standardized Result objects
    """

    def __init__(
        self,
        registry: ToolRegistry | None = None,
        default_timeout: float = 60.0,
    ) -> None:
        self.registry = registry if registry is not None else ToolRegistry()
        self.default_timeout = default_timeout
        self._execution_count: int = 0
        self._error_count: int = 0

    async def execute(self, task: Task) -> Result:
        """Execute a task on the appropriate tool.

        Args:
            task: The Task to execute (contains tool name, action, args).

        Returns:
            A Result object with the execution outcome.
        """
        self._execution_count += 1
        start_time = time.monotonic()

        # Get the tool
        tool = self.registry.get(task.tool)
        if tool is None:
            return self._failure_result(
                task,
                f"Tool '{task.tool}' not found. Available: {self.registry.list_tools()}",
                start_time,
            )

        # Validate
        try:
            await tool.validate(task.action, **task.args)
        except ValueError as e:
            return self._failure_result(task, f"Validation error: {e}", start_time)

        # Execute with timeout
        timeout = task.timeout_seconds or self.default_timeout
        try:
            data = await asyncio.wait_for(
                tool.execute(task.action, **task.args),
                timeout=timeout,
            )
            duration_ms = (time.monotonic() - start_time) * 1000

            result = Result(
                task_id=task.id,
                status=ResultStatus.SUCCESS,
                data=data,
                duration_ms=duration_ms,
                tool_name=task.tool,
                tool_action=task.action,
                retry_count=task.retry_count,
            )

            logger.info(
                "Task %s: %s.%s -> SUCCESS (%.0fms)",
                task.id, task.tool, task.action, duration_ms,
            )
            return result

        except asyncio.TimeoutError:
            duration_ms = (time.monotonic() - start_time) * 1000
            return self._failure_result(
                task,
                f"Task timed out after {timeout}s",
                start_time,
                result_status=ResultStatus.TIMEOUT,
            )

        except Exception as e:
            duration_ms = (time.monotonic() - start_time) * 1000
            self._error_count += 1
            logger.exception(
                "Task %s: %s.%s -> FAILURE: %s",
                task.id, task.tool, task.action, e,
            )
            return self._failure_result(task, str(e), start_time)

    def _failure_result(
        self,
        task: Task,
        error: str,
        start_time: float,
        result_status: ResultStatus = ResultStatus.FAILURE,
    ) -> Result:
        duration_ms = (time.monotonic() - start_time) * 1000
        return Result(
            task_id=task.id,
            status=result_status,
            error=error,
            duration_ms=duration_ms,
            tool_name=task.tool,
            tool_action=task.action,
            retry_count=task.retry_count,
        )

    async def validate_task(self, task: Task) -> tuple[bool, str]:
        """Validate that a task can be executed.

        Returns:
            (is_valid, error_message)
        """
        tool = self.registry.get(task.tool)
        if tool is None:
            return False, f"Tool '{task.tool}' not found. Available: {self.registry.list_tools()}"

        if task.action not in tool.metadata.actions:
            return False, (
                f"Action '{task.action}' not supported by '{task.tool}'. "
                f"Available: {tool.metadata.actions}"
            )

        try:
            await tool.validate(task.action, **task.args)
        except ValueError as e:
            return False, str(e)

        return True, ""

    @property
    def stats(self) -> dict[str, int]:
        return {
            "executions": self._execution_count,
            "errors": self._error_count,
            "tools_registered": len(self.registry),
        }

    def get_capabilities(self) -> dict[str, list[str]]:
        """Get all available tools and their actions."""
        return self.registry.get_available_actions()

    async def initialize(self) -> None:
        """Initialize all tools in the registry."""
        await self.registry.initialize_all()
        logger.info("ToolManager initialized with %d tools", len(self.registry))

    async def shutdown(self) -> None:
        """Shut down all tools."""
        await self.registry.shutdown_all()
        logger.info("ToolManager shut down. Stats: %s", self.stats)
