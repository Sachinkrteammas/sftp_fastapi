"""Loads and validates all settings from environment variables / .env.

Secrets are declared with repr=False so they never appear if a Settings
object is printed or logged by accident.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the project root. Real environment variables win over .env.
load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
VALID_MODES = ("preview", "save")


class ConfigError(Exception):
    """Raised when required configuration is missing or invalid."""


def _str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _int(name: str, default: int) -> int:
    raw = _str(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a whole number") from exc


def _bool(name: str, default: bool) -> bool:
    raw = _str(name).lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    # SFTP
    sftp_host: str
    sftp_port: int
    sftp_username: str
    sftp_password: str = field(repr=False)
    sftp_private_key: str
    sftp_private_key_passphrase: str = field(repr=False)
    sftp_interactive_response: str = field(repr=False)
    sftp_remote_file: str
    sftp_known_hosts: str
    sftp_strict_host_key_checking: bool
    sftp_timeout_seconds: int
    sftp_max_file_mb: int
    # GPG
    gpg_passphrase: str = field(repr=False)
    gpg_home: str
    file_encoding: str
    # Dialer DB
    dialer_db_host: str
    dialer_db_port: int
    dialer_db_user: str
    dialer_db_password: str = field(repr=False)
    dialer_db_name: str
    dialer_target_table: str
    history_table: str
    # App
    process_mode: str
    preview_rows: int
    api_key: str = field(repr=False)
    log_level: str
    log_file: str

    @property
    def is_save_mode(self) -> bool:
        return self.process_mode == "save"

    @property
    def db_configured(self) -> bool:
        return all((self.dialer_db_host, self.dialer_db_user,
                    self.dialer_db_name, self.dialer_target_table))


def _validate(s: Settings) -> None:
    missing = [name for name, value in (
        ("SFTP_HOST", s.sftp_host),
        ("SFTP_USERNAME", s.sftp_username),
        ("SFTP_REMOTE_FILE", s.sftp_remote_file),
    ) if not value]
    if not s.sftp_password and not s.sftp_private_key:
        missing.append("SFTP_PASSWORD or SFTP_PRIVATE_KEY")

    if s.process_mode not in VALID_MODES:
        raise ConfigError(f"PROCESS_MODE must be one of: {', '.join(VALID_MODES)}")

    if s.is_save_mode:
        missing += [name for name, value in (
            ("DIALER_DB_HOST", s.dialer_db_host),
            ("DIALER_DB_USER", s.dialer_db_user),
            ("DIALER_DB_NAME", s.dialer_db_name),
            ("DIALER_TARGET_TABLE", s.dialer_target_table),
        ) if not value]

    if missing:
        # Only variable NAMES are reported, never values.
        raise ConfigError(f"Missing required settings: {', '.join(missing)}")

    for name, value in (("DIALER_TARGET_TABLE", s.dialer_target_table),
                        ("HISTORY_TABLE", s.history_table)):
        if value and not _IDENTIFIER.match(value):
            raise ConfigError(f"{name} may only contain letters, digits and underscore")

    if not 1 <= s.sftp_port <= 65535:
        raise ConfigError("SFTP_PORT must be between 1 and 65535")
    if s.sftp_private_key and not Path(s.sftp_private_key).expanduser().is_file():
        raise ConfigError("SFTP_PRIVATE_KEY file not found")
    if s.sftp_max_file_mb <= 0:
        raise ConfigError("SFTP_MAX_FILE_MB must be greater than 0")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings(
        sftp_host=_str("SFTP_HOST"),
        sftp_port=_int("SFTP_PORT", 22),
        sftp_username=_str("SFTP_USERNAME"),
        sftp_password=os.getenv("SFTP_PASSWORD", ""),  # not stripped: spaces may be part of a password
        sftp_private_key=_str("SFTP_PRIVATE_KEY"),
        sftp_private_key_passphrase=os.getenv("SFTP_PRIVATE_KEY_PASSPHRASE", ""),
        sftp_interactive_response=os.getenv("SFTP_INTERACTIVE_RESPONSE", ""),
        sftp_remote_file=_str("SFTP_REMOTE_FILE"),
        sftp_known_hosts=_str("SFTP_KNOWN_HOSTS", "~/.ssh/known_hosts"),
        sftp_strict_host_key_checking=_bool("SFTP_STRICT_HOST_KEY_CHECKING", True),
        sftp_timeout_seconds=_int("SFTP_TIMEOUT_SECONDS", 30),
        sftp_max_file_mb=_int("SFTP_MAX_FILE_MB", 200),
        gpg_passphrase=os.getenv("GPG_PASSPHRASE", ""),
        gpg_home=_str("GPG_HOME"),
        file_encoding=_str("FILE_ENCODING", "utf-8-sig"),
        dialer_db_host=_str("DIALER_DB_HOST"),
        dialer_db_port=_int("DIALER_DB_PORT", 3306),
        dialer_db_user=_str("DIALER_DB_USER"),
        dialer_db_password=os.getenv("DIALER_DB_PASSWORD", ""),
        dialer_db_name=_str("DIALER_DB_NAME"),
        dialer_target_table=_str("DIALER_TARGET_TABLE"),
        history_table=_str("HISTORY_TABLE", "sftp_file_history"),
        process_mode=_str("PROCESS_MODE", "preview").lower(),
        preview_rows=_int("PREVIEW_ROWS", 20),
        api_key=os.getenv("API_KEY", ""),
        log_level=_str("LOG_LEVEL", "INFO").upper(),
        log_file=_str("LOG_FILE"),
    )
    _validate(settings)
    return settings
