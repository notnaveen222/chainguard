"""Logging configuration.

Uses ``rich`` for readable console output during development and demos — the
scan pipeline emits a lot of per-package progress, and colour-coded severity
makes a live demo far easier to follow.
"""

from __future__ import annotations

import logging
from typing import Optional

from rich.logging import RichHandler

_CONFIGURED = False


def setup_logging(level: Optional[str] = None) -> None:
    """Install the root logging handler. Safe to call more than once."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    from chainguard.config import get_settings

    resolved = (level or get_settings().log_level).upper()

    logging.basicConfig(
        level=resolved,
        format="%(message)s",
        datefmt="%H:%M:%S",
        handlers=[
            RichHandler(
                rich_tracebacks=True,
                markup=False,
                show_path=False,
                omit_repeated_times=False,
            )
        ],
    )

    # These libraries are extremely chatty at DEBUG and drown out our own output.
    for noisy in ("httpx", "httpcore", "urllib3", "matplotlib", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger for ``name``."""
    setup_logging()
    return logging.getLogger(name)
