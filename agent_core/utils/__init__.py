"""Logging configuration for the Agent Core."""

from __future__ import annotations

import logging
import sys


def setup_logging(
    level: int = logging.INFO,
    format_string: str | None = None,
    log_file: str | None = None,
) -> logging.Logger:
    """Configure logging for the Agent Core.

    Args:
        level: Log level (default INFO).
        format_string: Custom format string.
        log_file: Optional file to write logs to.

    Returns:
        The root agent_core logger.
    """
    if format_string is None:
        format_string = (
            "%(asctime)s [%(levelname)-7s] %(name)-25s | %(message)s"
        )

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]

    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=level,
        format=format_string,
        handlers=handlers,
    )

    # Set agent_core logger
    logger = logging.getLogger("agent_core")
    logger.setLevel(level)

    # Quiet down noisy libraries
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger for a specific module.

    Args:
        name: Module name (e.g., 'agent_core.core.thinker').

    Returns:
        Configured logger.
    """
    return logging.getLogger(name)
