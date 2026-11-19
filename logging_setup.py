"""Logging configuration (key=value structured messages on stderr)."""
from __future__ import annotations

import logging

_FORMAT = "%(asctime)s level=%(levelname)s logger=%(name)s %(message)s"


def configure_logging(level: str = "INFO") -> None:
    """Configure root logging once; later calls only adjust the level."""
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(format=_FORMAT, datefmt="%Y-%m-%dT%H:%M:%S%z")
    root.setLevel(getattr(logging, str(level).upper(), logging.INFO))
