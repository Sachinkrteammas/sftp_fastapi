"""Reads the decrypted CSV text from memory, validates and transforms it."""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field

import pandas as pd

from .logger import get_logger

log = get_logger("processor")

# ---------------------------------------------------------------------------
# Edit these to match your file and your Dialer table.
# Left side  = column name in the CSV (lowercase)
# Right side = column name in DIALER_TARGET_TABLE
COLUMN_MAPPING: dict[str, str] = {
    "phone": "phone",
    "name": "name",
    "city": "city",
}
# CSV columns that must exist in the header
REQUIRED_SOURCE_COLUMNS: tuple[str, ...] = ("phone", "name")
# Target columns that must not be empty in a row (row is skipped otherwise)
REQUIRED_VALUES: tuple[str, ...] = ("phone", "name")
# Max length per target column (values are cut to fit the DB column)
MAX_LENGTHS: dict[str, int] = {"phone": 20, "name": 100, "city": 100}
PHONE_MIN_DIGITS = 7
PHONE_MAX_DIGITS = 15
# ---------------------------------------------------------------------------


class InvalidCSVError(Exception):
    """Decrypted content could not be parsed as CSV."""


class MissingColumnsError(Exception):
    """Required columns are missing from the CSV header."""


class NoValidRecordsError(Exception):
    """CSV was readable but no row passed validation."""


@dataclass
class ProcessResult:
    records: list[dict[str, str]] = field(repr=False)  # customer data: never log
    records_read: int
    records_valid: int
    records_skipped: int
    source_columns: list[str]
    target_columns: list[str]


def read_csv(decrypted_data: str) -> pd.DataFrame:
    if not decrypted_data.strip():
        raise InvalidCSVError("Decrypted file is empty")
    try:
        df = pd.read_csv(
            io.StringIO(decrypted_data),   # in memory, no file on disk
            dtype=str,                     # keep phone numbers as text (leading zeros)
            keep_default_na=False,         # empty cells -> "" instead of NaN
            skip_blank_lines=True,
            skipinitialspace=True,
        )
    except pd.errors.EmptyDataError as exc:
        raise InvalidCSVError("Decrypted file has no CSV data") from exc
    except (pd.errors.ParserError, csv.Error, UnicodeError, ValueError) as exc:
        raise InvalidCSVError("Decrypted file is not a valid CSV") from exc

    df.columns = [str(c).strip().lower() for c in df.columns]
    return df


def validate_columns(df: pd.DataFrame) -> None:
    missing = [c for c in REQUIRED_SOURCE_COLUMNS if c not in df.columns]
    if missing:
        # Column NAMES are safe to return; they are not customer data.
        raise MissingColumnsError(
            f"CSV is missing required columns: {', '.join(missing)}. "
            f"Found columns: {', '.join(df.columns)}")


def transform(df: pd.DataFrame) -> list[dict[str, str]]:
    out = pd.DataFrame(index=df.index)
    for source, target in COLUMN_MAPPING.items():
        values = df[source] if source in df.columns else pd.Series("", index=df.index)
        out[target] = values.astype(str).str.strip()

    out["phone"] = out["phone"].str.replace(r"\D", "", regex=True)

    valid = out["phone"].str.len().between(PHONE_MIN_DIGITS, PHONE_MAX_DIGITS)
    for column in REQUIRED_VALUES:
        valid &= out[column] != ""
    out = out[valid]

    out = out.drop_duplicates(subset=["phone"], keep="first")

    for column, max_len in MAX_LENGTHS.items():
        if column in out.columns:
            out[column] = out[column].str.slice(0, max_len)

    return out.to_dict(orient="records")


def process_csv(decrypted_data: str) -> ProcessResult:
    log.info("CSV processing started")
    df = read_csv(decrypted_data)
    records_read = len(df)
    log.info("Number of records found: %s (columns: %s)", records_read, ", ".join(df.columns))

    validate_columns(df)
    records = transform(df)
    skipped = records_read - len(records)
    log.info("Valid records: %s, skipped (invalid/empty/duplicate): %s", len(records), skipped)

    if not records:
        raise NoValidRecordsError("CSV contains no valid records after validation")

    return ProcessResult(
        records=records,
        records_read=records_read,
        records_valid=len(records),
        records_skipped=skipped,
        source_columns=list(df.columns),
        target_columns=list(COLUMN_MAPPING.values()),
    )


def print_preview(decrypted_data: str, result: ProcessResult, max_rows: int) -> None:
    """PREVIEW MODE ONLY: print decrypted data to the server console for checking.

    Uses print(), not the logger, so customer data never goes into log files.
    Do not use preview mode in production.
    """
    limit = None if max_rows <= 0 else max_rows
    lines = decrypted_data.splitlines()
    shown = lines if limit is None else lines[: limit + 1]  # +1 for header line

    bar = "=" * 70
    print(f"\n{bar}\nDECRYPTED FILE CONTENT (raw) - showing {len(shown)} of {len(lines)} lines\n{bar}")
    for line in shown:
        print(line)

    processed = pd.DataFrame(result.records)
    rows = processed if limit is None else processed.head(limit)
    print(f"\n{bar}\nPROCESSED RECORDS (ready for Dialer DB) - showing {len(rows)} of {len(processed)}\n{bar}")
    print(rows.to_string(index=False))
    print(f"\nread={result.records_read} valid={result.records_valid} "
          f"skipped={result.records_skipped}\n{bar}\n", flush=True)
