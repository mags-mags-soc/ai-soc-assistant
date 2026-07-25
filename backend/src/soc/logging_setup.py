"""Structured, reusable logging setup used across all sprints."""

from __future__ import annotations

import logging
from pathlib import Path

_CONFIGURED = False


def setup_logging(logs_dir: Path, level: str = "INFO") -> logging.Logger:
    """Configure root logging once and return the 'soc' logger."""
    global _CONFIGURED
    logger = logging.getLogger("soc")

    if _CONFIGURED:
        return logger

    logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = logs_dir / "soc.log"

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(fmt)

    logger.setLevel(getattr(logging, level, logging.INFO))
    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
    logger.propagate = False

    _CONFIGURED = True
    return logger
