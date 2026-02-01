"""Logging configuration for nothx."""

import json
import logging
import sys
import uuid
from datetime import datetime
from typing import Any

from .config import get_config_dir


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging.

    Outputs logs as JSON objects for easy parsing by log aggregation tools.
    Includes extra fields passed via the `extra` parameter.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data: dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add correlation ID if set
        if hasattr(record, "correlation_id"):
            log_data["correlation_id"] = record.correlation_id

        # Add any extra fields (filter out standard LogRecord attributes)
        standard_attrs = {
            "name",
            "msg",
            "args",
            "created",
            "filename",
            "funcName",
            "levelname",
            "levelno",
            "lineno",
            "module",
            "msecs",
            "pathname",
            "process",
            "processName",
            "relativeCreated",
            "stack_info",
            "exc_info",
            "exc_text",
            "thread",
            "threadName",
            "message",
            "correlation_id",
        }

        for key, value in record.__dict__.items():
            if key not in standard_attrs and not key.startswith("_"):
                log_data[key] = value

        return json.dumps(log_data, default=str)


class ContextFilter(logging.Filter):
    """Filter that adds context information to log records.

    Adds correlation_id for tracing requests across the system.
    """

    def __init__(self, correlation_id: str | None = None):
        super().__init__()
        self.correlation_id = correlation_id or str(uuid.uuid4())[:8]

    def filter(self, record: logging.LogRecord) -> bool:
        """Add correlation_id to log record."""
        record.correlation_id = self.correlation_id
        return True


# Global context filter for correlation ID tracking
_context_filter: ContextFilter | None = None


def set_correlation_id(correlation_id: str | None = None) -> str:
    """Set a correlation ID for the current logging context.

    Args:
        correlation_id: ID to use, or None to generate a new one

    Returns:
        The correlation ID being used
    """
    global _context_filter
    if _context_filter is None:
        _context_filter = ContextFilter(correlation_id)
        logging.getLogger("nothx").addFilter(_context_filter)
    else:
        _context_filter.correlation_id = correlation_id or str(uuid.uuid4())[:8]
    return _context_filter.correlation_id


def setup_logging(
    level: int = logging.INFO,
    log_to_file: bool = False,
    verbose: bool = False,
    json_format: bool = False,
    debug: bool = False,
) -> logging.Logger:
    """
    Set up logging for nothx.

    Args:
        level: Logging level (default: INFO)
        log_to_file: Whether to also log to a file
        verbose: If True, set level to DEBUG and show all logs on console
        json_format: If True, use JSON format for structured logging
        debug: If True, set level to DEBUG (same as verbose)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("nothx")

    # Clear existing handlers to allow reconfiguration
    logger.handlers.clear()

    if verbose or debug:
        level = logging.DEBUG

    logger.setLevel(level)

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)

    if verbose or debug:
        # In verbose/debug mode, show all logs on console
        console_handler.setLevel(logging.DEBUG)
    else:
        # Normal mode: only warnings and above to avoid cluttering CLI output
        console_handler.setLevel(logging.WARNING)

    if json_format:
        console_handler.setFormatter(JSONFormatter())
    else:
        if verbose or debug:
            console_format = logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%H:%M:%S",
            )
        else:
            console_format = logging.Formatter("%(levelname)s: %(message)s")
        console_handler.setFormatter(console_format)

    logger.addHandler(console_handler)

    # File handler (if enabled)
    if log_to_file:
        log_dir = get_config_dir() / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "nothx.log"

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)

        if json_format:
            file_handler.setFormatter(JSONFormatter())
        else:
            file_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            file_handler.setFormatter(file_format)

        logger.addHandler(file_handler)

    # Initialize correlation ID tracking
    set_correlation_id()

    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """
    Get a logger instance.

    Args:
        name: Optional name for child logger (e.g., "classifier", "imap")

    Returns:
        Logger instance
    """
    if name:
        return logging.getLogger(f"nothx.{name}")
    return logging.getLogger("nothx")
