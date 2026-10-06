"""Second database: VICIdial (e.g. asterisk.vicidial_list).

Every saved SBI record also becomes one dialer lead in VICIDIAL_TABLE, using
LEAD_MAPPING below. Values are copied as text; a value longer than its
vicidial_list column is cut to fit (with a warning) instead of failing the run.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

import mysql.connector
from mysql.connector import errorcode

from .config import get_settings
from .logger import get_logger

log = get_logger("vicidial_db")

# (vicidial_list column, SBI file column). SBI columns missing from the file are saved as "".
LEAD_MAPPING: Tuple[Tuple[str, str], ...] = (
    ("first_name", "embo_name"),
    ("title", "billing_cycle"),
    ("last_name", "cur_bal"),
    ("address1", "address1"),          # not in the SBI file today -> ""
    ("address2", "address2"),          # not in the SBI file today -> ""
    ("address3", "nrr"),
    ("vendor_lead_code", "account_no"),
    ("source_id", "account_no"),
    ("postal_code", "total_amount_due"),
    ("phone_number", "mobile_no"),
    ("alt_phone", "resi_phone"),
    ("city", "additional_phone_1"),
    ("email", "additional_phone_2"),
    ("security_phrase", "additional_phone_3"),
)


class VicidialConnectionError(Exception):
    """Cannot connect / log in to the VICIdial DB."""


class VicidialInsertError(Exception):
    """Inserting leads into vicidial_list failed; its transaction was rolled back."""


def _fixed_values() -> Dict[str, Any]:
    """Columns that get the same value for every lead (entry_date is NOW() in SQL)."""
    s = get_settings()
    return {
        "list_id": s.vicidial_list_id,
        "status": "NEW",
        "called_since_last_reset": "N",
        "phone_code": s.vicidial_phone_code,
        "gmt_offset_now": s.vicidial_gmt_offset,
    }


def connect() -> mysql.connector.MySQLConnection:
    s = get_settings()
    try:
        conn = mysql.connector.connect(
            host=s.vicidial_db_host,
            port=s.vicidial_db_port,
            user=s.vicidial_db_user,
            password=s.vicidial_db_password,
            database=s.vicidial_db_name,
            charset="utf8mb4",
            autocommit=False,
            connection_timeout=15,
        )
    except mysql.connector.Error as exc:
        log.error("VICIdial DB connection failed (mysql errno: %s)", exc.errno)
        if exc.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            raise VicidialConnectionError("VICIdial DB login failed (check VICIDIAL_DB_USER/PASSWORD)") from exc
        if exc.errno == errorcode.ER_BAD_DB_ERROR:
            raise VicidialConnectionError("VICIdial DB database name does not exist") from exc
        raise VicidialConnectionError("Could not connect to VICIdial DB "
                                      "(check VICIDIAL_DB_HOST, port and firewall)") from exc
    log.info("VICIdial DB connection successful")
    return conn


def _column_lengths(cursor, table: str, columns: List[str]) -> Dict[str, Any]:
    """Max text length of each column (None = not a text column). Errors if a column is missing."""
    s = get_settings()
    cursor.execute(
        """SELECT COLUMN_NAME, CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s""",
        (s.vicidial_db_name, table),
    )
    lengths = {name.lower(): length for name, length in cursor.fetchall()}
    if not lengths:
        raise VicidialInsertError(f"VICIdial table {table} does not exist in {s.vicidial_db_name}")
    missing = [c for c in columns if c not in lengths]
    if missing:
        raise VicidialInsertError(f"VICIdial table {table} has no column(s): {', '.join(missing)}")
    return {c: lengths[c] for c in columns}


def build_leads(records: List[Dict[str, Any]], lengths: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Turn SBI records into vicidial_list rows (mapped + fixed columns)."""
    fixed = _fixed_values()
    leads, cut = [], {}
    for record in records:
        lead = {}
        for column, source in LEAD_MAPPING:
            value = record.get(source)
            value = "" if value is None else str(value)
            limit = lengths.get(column)
            if limit and len(value) > limit:
                cut[column] = cut.get(column, 0) + 1
                value = value[:limit]
            lead[column] = value
        lead.update(fixed)
        leads.append(lead)
    for column, count in cut.items():
        log.warning("VICIdial: %s value(s) cut to %s characters to fit column %s",
                    count, lengths[column], column)
    return leads


def insert_leads(conn, records: List[Dict[str, Any]], batch_size: int = 1000) -> int:
    """Insert one lead per record in ONE transaction on `conn` and commit it."""
    if not records:
        return 0
    table = get_settings().vicidial_table  # validated as a plain identifier in config.py
    columns = [c for c, _ in LEAD_MAPPING] + list(_fixed_values())
    cursor = conn.cursor()
    try:
        lengths = _column_lengths(cursor, table, columns)
        leads = build_leads(records, lengths)
        sql = (f"INSERT INTO `{table}` ({', '.join(f'`{c}`' for c in columns)}, `entry_date`) "
               f"VALUES ({', '.join(['%s'] * len(columns))}, NOW())")
        conn.start_transaction()
        inserted = 0
        for start in range(0, len(leads), batch_size):
            rows = [tuple(lead[c] for c in columns) for lead in leads[start:start + batch_size]]
            cursor.executemany(sql, rows)
            inserted += max(cursor.rowcount, 0)
        conn.commit()
        log.info("VICIdial: %s leads inserted into %s (list_id %s)",
                 inserted, table, get_settings().vicidial_list_id)
        return inserted
    except mysql.connector.Error as exc:
        conn.rollback()
        log.error("VICIdial insert failed, rolled back (mysql errno: %s)", exc.errno)
        raise VicidialInsertError("Inserting leads into VICIdial failed; nothing was saved") from exc
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
