"""Result data model.

Result wraps the output of a Task execution by the Act phase.
It is produced by ToolManager.execute().
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, ConfigDict

try:
    from enum import StrEnum
except ImportError:  # Python < 3.11
    class StrEnum(str, Enum):  # type: ignore[no-redef]
        pass


class ResultStatus(StrEnum):
    """Outcome status of a task execution."""
    SUCCESS = "success"
    PARTIAL = "partial"      # Partially completed
    FAILURE = "failure"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class Result(BaseModel):
    """Output of a task execution.

    Act passes a Task to ToolManager, which returns this Result.
    It contains the raw output plus metadata for Learn and Reflection.
    """

    model_config = ConfigDict(extra="forbid", frozen=False)

    id: UUID = Field(default_factory=uuid4, description="Unique result ID")
    task_id: UUID = Field(..., description="ID of the task that produced this result")
    status: ResultStatus = Field(..., description="Execution outcome")
    data: Any = Field(default=None, description="Raw output data from the tool")
    error: str | None = Field(default=None, description="Error message if status is FAILURE")
    duration_ms: float = Field(default=0.0, ge=0.0, description="Execution duration in milliseconds")
    retry_count: int = Field(default=0, ge=0, description="Retry attempt that produced this result")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this result was produced",
    )
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional context")
    tool_name: str = Field(default="", description="Name of the tool that was executed")
    tool_action: str = Field(default="", description="Action that was performed")

    @property
    def is_success(self) -> bool:
        """Whether execution was fully successful."""
        return self.status == ResultStatus.SUCCESS

    @property
    def is_terminal(self) -> bool:
        """Whether this is a terminal result (no further retries expected)."""
        return self.status in {ResultStatus.SUCCESS, ResultStatus.CANCELLED}
