"""Model for one row of SBI's allocation file, stored in DIALER_TARGET_TABLE.

The columns are the CSV header names exactly as SBI sends them (lowercased).
Every value is stored as text, exactly as in the file, so nothing is lost or
reformatted (dates, amounts, phone numbers with +/-).
"""
from __future__ import annotations

from typing import Any, Dict, List, Sequence

from .logger import get_logger

log = get_logger("models")


class SbiRecord:
    COLUMNS: Sequence[str] = (
        "account_no", "billing_cycle", "block_1", "block_2", "cd", "delq1",
        "cibil_score", "cibil_enquiry_date_", "credit_limit", "cur_bal",
        "cur_bal_plus_dpi_", "date_last_pmt", "embo_name", "emp_phone",
        "last_settlement_date_broken_", "last_action_code", "last_ptp_date",
        "mobile_no", "nrr", "nsf_date", "resi_phone", "total_amount_due",
        "total_cur_due", "vintage_", "additional_phone_1", "additional_phone_2",
        "additional_phone_3", "region", "next_rev_date", "promo_code",
        "date_charge_off", "product_classification_flag", "promo_code_description",
        "ntc_flag", "new_to_card_flag", "employee_flag",
        "account_classification_flag_1", "account_classification_flag_2",
        "account_classification_flag_3", "account_classification_flag_4",
        "account_classification_flag_5", "account_classification_flag_6",
        "account_classification_flag_7", "accounts_classification",
        "call_table_name", "additional_phone_4", "agency_name",
        "dummy1", "dummy2", "dummy3", "dummy4", "time_zone",
    )
    # Columns that may hold long text (TEXT instead of VARCHAR(255))
    LONG_TEXT: Sequence[str] = ("promo_code_description",)

    @classmethod
    def create_table_sql(cls, table: str) -> str:
        """CREATE TABLE IF NOT EXISTS for `table` (already quoted with backticks)."""
        columns = ",\n            ".join(
            f"`{c}` {'TEXT' if c in cls.LONG_TEXT else 'VARCHAR(255)'} NULL" for c in cls.COLUMNS)
        return f"""
        CREATE TABLE IF NOT EXISTS {table} (
            `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            {columns},
            `source_file` VARCHAR(255) NOT NULL,
            `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            KEY `idx_account_no` (`account_no`),
            KEY `idx_mobile_no` (`mobile_no`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """

    @classmethod
    def create_table(cls, cursor, table: str) -> None:
        """Create the table if it does not exist yet (no-op otherwise)."""
        cursor.execute(cls.create_table_sql(table))

    @classmethod
    def save_all(cls, cursor, table: str, records: List[Dict[str, Any]], *,
                 source_file: str, batch_size: int = 1000) -> int:
        """Insert every record with every column value. Runs inside the caller's transaction.

        Columns missing from a file are stored as NULL. Columns SBI adds later
        that are not in COLUMNS are skipped with a warning (add them to COLUMNS
        and to the table to keep them).
        """
        if not records:
            return 0
        extra = [c for c in records[0] if c not in cls.COLUMNS]
        if extra:
            log.warning("File has columns not in the SbiRecord model, not saved: %s", ", ".join(extra))

        names = list(cls.COLUMNS) + ["source_file"]
        column_sql = ", ".join(f"`{c}`" for c in names)
        placeholders = ", ".join(["%s"] * len(names))
        sql = f"INSERT INTO {table} ({column_sql}) VALUES ({placeholders})"

        inserted = 0
        for start in range(0, len(records), batch_size):
            rows = [tuple(r.get(c) for c in cls.COLUMNS) + (source_file,)
                    for r in records[start:start + batch_size]]
            cursor.executemany(sql, rows)
            inserted += max(cursor.rowcount, 0)
        return inserted
