"""Central logging setup.

Rule for the whole project: log steps, sizes, counts and hashes only.
Never log passwords, passphrases, file content or customer data.
"""
from __future__ import annotations

import logging
import sys

APP_LOGGER_NAME = "sftp_fastapi"
_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"


def setup_logging(level: str = "INFO", log_file: str = "") -> None:
    root = logging.getLogger(APP_LOGGER_NAME)
    if root.handlers:  # already configured (e.g. uvicorn --reload)
        return
    root.setLevel(getattr(logging, level, logging.INFO))
    root.propagate = False

    formatter = logging.Formatter(_FORMAT)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    root.addHandler(console)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    # Third-party libraries can log protocol details at DEBUG level
    # (python-gnupg can log gpg output). Keep them quiet.
    for noisy in ("paramiko", "gnupg", "mysql.connector"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"{APP_LOGGER_NAME}.{name}")
