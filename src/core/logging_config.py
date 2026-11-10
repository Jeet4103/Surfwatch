# src/logging_config.py
import logging
import sys

from src.core.config import get_settings


def setup_logging() -> None:
  settings = get_settings()
  handler = logging.StreamHandler(sys.stdout)
  handler.setFormatter(logging.Formatter(settings.log_format))

  root = logging.getLogger()
  root.handlers.clear()
  root.addHandler(handler)
  root.setLevel(settings.log_level.upper())
