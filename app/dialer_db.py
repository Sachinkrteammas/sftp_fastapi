"""Dialer MySQL access with mysql-connector-python.

All values use parameterized SQL (%s). Table and column names cannot be
parameters in SQL, so they are validated as plain identifiers in config.py
and processor.py and wrapped in backticks.
"""
from __future__ import annotations

import re
from typing import Any

import mysql.connector
from mysql.connector import errorcode

from .config import get_settings
from .logger import get_logger
from .models import SbiRecord

log = get_logger("dialer_db")

BATCH_SIZE = 1000
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


class DatabaseNotConfiguredError(Exception):
    """DIALER_DB_* settings are empty."""


class DatabaseConnectionError(Exception):
    """Cannot connect / log in to the Dialer DB."""


class DatabaseInsertError(Exception):
    """Insert failed; the whole transaction was rolled back."""


class DuplicateFileError(Exception):
    """This exact file content was already processed successfully."""


def _quote(identifier: str) -> str:
    if not _IDENTIFIER.match(identifier):
        raise DatabaseInsertError(f"Invalid SQL identifier: {identifier!r}")
    return f"`{identifier}`"


def connect_db() -> mysql.connector.MySQLConnection:
    settings = get_settings()
    if not settings.db_configured:
        raise DatabaseNotConfiguredError("Dialer DB settings are not configured in .env")
    try:
        conn = mysql.connector.connect(
            host=settings.dialer_db_host,
            port=settings.dialer_db_port,
            user=settings.dialer_db_user,
            password=settings.dialer_db_password,
            database=settings.dialer_db_name,
            charset="utf8mb4",
            autocommit=False,
            connection_timeout=15,
        )
    except mysql.connector.Error as exc:
        # Log only the MySQL error number, never connection details.
        log.error("Database connection failed (mysql errno: %s)", exc.errno)
        if exc.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            raise DatabaseConnectionError("Dialer DB login failed (check DB user/password)") from exc
        if exc.errno == errorcode.ER_BAD_DB_ERROR:
            raise DatabaseConnectionError("Dialer DB database name does not exist") from exc
        raise DatabaseConnectionError("Could not connect to Dialer DB") from exc
    log.info("Database connection successful")
    return conn


def _history_ddl(table: str) -> str:
    return f"""
        CREATE TABLE IF NOT EXISTS {table} (
            id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            file_name     VARCHAR(255)    NOT NULL,
            file_hash     CHAR(64)        NOT NULL,
            record_count  INT UNSIGNED    NOT NULL DEFAULT 0,
            status        VARCHAR(20)     NOT NULL,
            processed_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
            error_message VARCHAR(500)    NULL,
            UNIQUE KEY uq_file_hash (file_hash)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """


def check_already_processed(file_hash: str) -> bool:
    """Create the history table if needed and check whether this hash succeeded before."""
    table = _quote(get_settings().history_table)
    conn = connect_db()
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute(_history_ddl(table))
        cursor.execute(f"SELECT status FROM {table} WHERE file_hash = %s", (file_hash,))
        row = cursor.fetchone()
        return bool(row and row[0] == "SUCCESS")
    except mysql.connector.Error as exc:
        log.error("History check failed (mysql errno: %s)", exc.errno)
        raise DatabaseInsertError("Could not read processing history table") from exc
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()


def insert_records(records: list[dict[str, Any]], *, file_name: str, file_hash: str) -> int:
    """Save all records (SbiRecord model) AND the SUCCESS history row in ONE transaction.

    Either everything is committed, or everything is rolled back, so a file
    can never be marked SUCCESS without its rows (and vice versa).
    The target table is created first if it does not exist.
    """
    if not records:
        return 0
    settings = get_settings()
    target = _quote(settings.dialer_target_table)
    history = _quote(settings.history_table)

    conn = connect_db()
    cursor = None
    inserted = 0
    try:
        cursor = conn.cursor()
        # DDL commits implicitly in MySQL, so create the table before the transaction
        SbiRecord.create_table(cursor, target)
        conn.start_transaction()

        # Lock this hash's history row (or its gap) so a parallel run cannot also insert
        cursor.execute(f"SELECT status FROM {history} WHERE file_hash = %s FOR UPDATE", (file_hash,))
        row = cursor.fetchone()
        if row and row[0] == "SUCCESS":
            raise DuplicateFileError("File already processed")

        inserted = SbiRecord.save_all(cursor, target, records, source_file=file_name,
                                      batch_size=BATCH_SIZE)

        cursor.execute(
            f"""INSERT INTO {history}
                    (file_name, file_hash, record_count, status, processed_at, error_message)
                VALUES (%s, %s, %s, 'SUCCESS', NOW(), NULL)
                ON DUPLICATE KEY UPDATE
                    file_name = VALUES(file_name),
                    record_count = VALUES(record_count),
                    processed_at = NOW(),
                    error_message = NULL,
                    status = 'SUCCESS'""",
            (file_name, file_hash, inserted),
        )
        conn.commit()
        log.info("Number of records inserted: %s (transaction committed)", inserted)
        return inserted
    except DuplicateFileError:
        conn.rollback()
        raise
    except mysql.connector.Error as exc:
        conn.rollback()
        log.error("Insert failed, transaction rolled back (mysql errno: %s)", exc.errno)
        if exc.errno == errorcode.ER_NO_SUCH_TABLE:
            raise DatabaseInsertError("Dialer target table or history table does not exist") from exc
        if exc.errno == errorcode.ER_BAD_FIELD_ERROR:
            raise DatabaseInsertError("Dialer target table is missing a column of the SbiRecord model") from exc
        raise DatabaseInsertError("Database insert failed; all changes were rolled back") from exc
    except Exception:
        conn.rollback()
        raise
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()


def mark_failed(*, file_name: str, file_hash: str, error_message: str) -> None:
    """Record a FAILED attempt. Never overwrites an existing SUCCESS row. Best effort."""
    try:
        history = _quote(get_settings().history_table)
        conn = connect_db()
    except Exception:
        log.warning("Could not record FAILED status in history (database unavailable)")
        return
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute(_history_ddl(history))
        # MySQL applies SET assignments left to right, so status must be last.
        cursor.execute(
            f"""INSERT INTO {history}
                    (file_name, file_hash, record_count, status, processed_at, error_message)
                VALUES (%s, %s, 0, 'FAILED', NOW(), %s)
                ON DUPLICATE KEY UPDATE
                    error_message = IF(status = 'SUCCESS', error_message, VALUES(error_message)),
                    processed_at  = IF(status = 'SUCCESS', processed_at, NOW()),
                    status        = IF(status = 'SUCCESS', status, 'FAILED')""",
            (file_name, file_hash, error_message[:500]),
        )
        conn.commit()
        log.info("Processing history updated: status=FAILED")
    except mysql.connector.Error as exc:
        conn.rollback()
        log.warning("Could not record FAILED status (mysql errno: %s)", exc.errno)
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()


def get_history(limit: int = 20) -> list[dict[str, Any]]:
    history = _quote(get_settings().history_table)
    conn = connect_db()
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(_history_ddl(history))
        cursor.execute(
            f"""SELECT id, file_name, file_hash, record_count, status, processed_at, error_message
                FROM {history} ORDER BY id DESC LIMIT %s""",
            (limit,),
        )
        rows = cursor.fetchall()
        for row in rows:
            if row.get("processed_at") is not None:
                row["processed_at"] = row["processed_at"].isoformat(sep=" ")
        return rows
    except mysql.connector.Error as exc:
        log.error("History read failed (mysql errno: %s)", exc.errno)
        raise DatabaseInsertError("Could not read processing history") from exc
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()
