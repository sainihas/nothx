"""Logging configuration for nothx."""

import logging
import sys

from .config import get_config_dir


def setup_logging(
    level: int = logging.INFO, log_to_file: bool = False, verbose: bool = False
) -> logging.Logger:
    """
    Set up logging for nothx.

    Args:
        level: Logging level (default: INFO)
        log_to_file: Whether to also log to a file
        verbose: If True, set level to DEBUG

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("nothx")

    # Avoid adding handlers multiple times
    if logger.handlers:
        return logger

    if verbose:
        level = logging.DEBUG

    logger.setLevel(level)

    # Console handler (only warnings and above to avoid cluttering CLI output)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.WARNING)
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
        file_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)

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
