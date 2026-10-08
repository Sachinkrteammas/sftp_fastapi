"""FastAPI entry point and the SFTP -> decrypt -> CSV -> Dialer DB pipeline."""
from __future__ import annotations

import hashlib
import posixpath
import secrets
import threading
import time
from contextlib import asynccontextmanager
from datetime import date, datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import JSONResponse, Response

from . import dialer_db, report_service
from .config import ConfigError, get_settings
from .decrypt_service import (DecodingError, DecryptionError, GpgNotAvailableError,
                              InvalidEncryptedFileError, decrypt_data)
from .dialer_db import (DatabaseConnectionError, DatabaseInsertError,
                        DatabaseNotConfiguredError, DuplicateFileError)
from .logger import get_logger, setup_logging
from .processor import (InvalidCSVError, MissingColumnsError, NoValidRecordsError,
                        print_preview, process_csv)
from .sftp_service import (RemoteFileNotFoundError, RemoteFileReadError, SftpAuthError,
                           SftpConnectionError, read_remote_file)

log = get_logger("main")


class ProcessBusyError(Exception):
    """Another /process-file request is still running."""


# Exception -> HTTP status. Every message these exceptions carry is written by
# this project and is safe to return (no secrets, no customer data).
ERROR_STATUS: list[tuple[type[Exception], int]] = [
    (ProcessBusyError, status.HTTP_409_CONFLICT),
    (DuplicateFileError, status.HTTP_409_CONFLICT),
    (SftpAuthError, status.HTTP_502_BAD_GATEWAY),
    (SftpConnectionError, status.HTTP_502_BAD_GATEWAY),
    (RemoteFileNotFoundError, status.HTTP_404_NOT_FOUND),
    (RemoteFileReadError, status.HTTP_502_BAD_GATEWAY),
    (InvalidEncryptedFileError, 422),
    (DecryptionError, 422),
    (DecodingError, 422),
    (InvalidCSVError, 422),
    (MissingColumnsError, 422),
    (NoValidRecordsError, 422),
    (DatabaseConnectionError, status.HTTP_503_SERVICE_UNAVAILABLE),
    (DatabaseInsertError, status.HTTP_500_INTERNAL_SERVER_ERROR),
    (DatabaseNotConfiguredError, status.HTTP_500_INTERNAL_SERVER_ERROR),
    (GpgNotAvailableError, status.HTTP_500_INTERNAL_SERVER_ERROR),
    (ConfigError, status.HTTP_500_INTERNAL_SERVER_ERROR),
    (report_service.ReportNotFoundError, status.HTTP_404_NOT_FOUND),
]
KNOWN_ERRORS = tuple(exc for exc, _ in ERROR_STATUS)

# Failures after the file was read that should be written to history as FAILED
HISTORY_FAILURES = (InvalidEncryptedFileError, DecryptionError, DecodingError,
                    InvalidCSVError, MissingColumnsError, NoValidRecordsError,
                    DatabaseInsertError, DatabaseConnectionError, GpgNotAvailableError)

_process_lock = threading.Lock()
_last_run: dict[str, Any] | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()  # fails fast with a clear message if .env is incomplete
    setup_logging(settings.log_level, settings.log_file)
    log.info("Service started | mode=%s | remote file=%s (today: %s)",
             settings.process_mode, settings.sftp_remote_file, settings.remote_file_for())
    if not settings.is_save_mode:
        log.warning("PREVIEW mode: decrypted data is printed to console, nothing is saved to DB")
    yield
    log.info("Service stopped")


app = FastAPI(
    title="SFTP Encrypted File -> Dialer DB",
    description="Reads a GPG-encrypted CSV from SFTP in memory, decrypts it and saves it to the Dialer DB.",
    version="1.0.0",
    lifespan=lifespan,
)


# FastAPI evaluates endpoint/dependency annotations at runtime, so these use
# typing.Optional/Dict (Python 3.8 has no "X | None" or "dict[...]" at runtime).
def verify_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    """If API_KEY is set in .env, protected endpoints require header X-API-Key."""
    expected = get_settings().api_key
    if expected and not (x_api_key and secrets.compare_digest(x_api_key, expected)):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing API key")


def _error_response(exc: Exception, file_name: str | None) -> JSONResponse:
    code = next(c for e, c in ERROR_STATUS if isinstance(exc, e))
    body: dict[str, Any] = {"status": "error", "message": str(exc)}
    if file_name:
        body["file"] = file_name
    return JSONResponse(status_code=code, content=body)


def run_pipeline(remote_path: str) -> dict[str, Any]:
    settings = get_settings()
    file_name = posixpath.basename(remote_path)
    started = time.monotonic()

    # 1-3. Connect, authenticate, read encrypted bytes into memory
    encrypted_data = read_remote_file(remote_path)

    # 4. Identify the file by its content
    file_hash = hashlib.sha256(encrypted_data).hexdigest()
    log.info("File SHA-256: %s", file_hash)

    # 5. Duplicate check (save mode only; preview never touches the DB)
    if settings.is_save_mode and dialer_db.check_already_processed(file_hash):
        log.warning("Duplicate file, already processed successfully. Nothing inserted.")
        raise DuplicateFileError("File already processed (same SHA-256 found in history)")

    try:
        # 6. Decrypt in memory
        decrypted_data = decrypt_data(encrypted_data)
        del encrypted_data

        # 7-8. Read CSV from memory, validate, transform
        result = process_csv(decrypted_data)

        if not settings.is_save_mode:
            print_preview(decrypted_data, result, settings.preview_rows)
            del decrypted_data
            log.info("Processing completed (preview mode, nothing saved)")
            return {
                "status": "success",
                "mode": "preview",
                "file": file_name,
                "file_hash": file_hash,
                "columns": result.source_columns,
                "records_read": result.records_read,
                "records_valid": result.records_valid,
                "records_skipped": result.records_skipped,
                "records_inserted": 0,
                "message": "Decrypted data printed to the server console. Nothing saved to DB.",
                "seconds": round(time.monotonic() - started, 2),
            }
        del decrypted_data

        # 9-11. Insert into Dialer DB + history SUCCESS in one transaction
        inserted, leads = dialer_db.insert_records(result.records, file_name=file_name,
                                                   file_hash=file_hash)
    except HISTORY_FAILURES as exc:
        if settings.is_save_mode:
            dialer_db.mark_failed(file_name=file_name, file_hash=file_hash, error_message=str(exc))
        raise

    log.info("Processing completed: %s records inserted, %s VICIdial leads", inserted, leads)
    return {
        "status": "success",
        "mode": "save",
        "file": file_name,
        "file_hash": file_hash,
        "records_read": result.records_read,
        "records_valid": result.records_valid,
        "records_skipped": result.records_skipped,
        "records_inserted": inserted,
        "vicidial_leads_inserted": leads,
        "vicidial_list_id": settings.vicidial_list_id if settings.vicidial_enabled else None,
        "seconds": round(time.monotonic() - started, 2),
    }


@app.get("/health", tags=["monitoring"])
def health() -> Dict[str, str]:
    return {"status": "ok"}


# Sync (def) endpoints run in FastAPI's thread pool, so blocking SFTP / GPG / MySQL
# calls do not block the event loop.
@app.post("/process-file", tags=["processing"], dependencies=[Depends(verify_api_key)])
def process_file(file_date: Optional[date] = Query(
        None, description="Date for {date:...} in SFTP_REMOTE_FILE, e.g. 2026-10-03 (default: today)")):
    global _last_run
    remote_path = get_settings().remote_file_for(file_date)
    file_name = posixpath.basename(remote_path)

    if not _process_lock.acquire(blocking=False):
        return _error_response(ProcessBusyError("Processing is already running, try again later"),
                               file_name)
    finished_at = lambda: datetime.now(timezone.utc).isoformat()  # noqa: E731
    try:
        result = run_pipeline(remote_path)
        _last_run = {**result, "finished_at": finished_at()}
        return result
    except KNOWN_ERRORS as exc:
        log.error("Processing failed: %s: %s", type(exc).__name__, exc)
        _last_run = {"status": "error", "file": file_name, "message": str(exc),
                     "finished_at": finished_at()}
        return _error_response(exc, file_name)
    except Exception:
        # Full traceback goes to the log; the client gets a generic message.
        log.exception("Unexpected error during processing")
        _last_run = {"status": "error", "file": file_name, "message": "Internal server error",
                     "finished_at": finished_at()}
        return JSONResponse(status_code=500,
                            content={"status": "error", "message": "Internal server error"})
    finally:
        _process_lock.release()


@app.get("/status", tags=["monitoring"], dependencies=[Depends(verify_api_key)])
def last_status() -> Dict[str, Any]:
    """Result of the last /process-file call since the service started."""
    return {
        "mode": get_settings().process_mode,
        "running": _process_lock.locked(),
        "last_run": _last_run,
    }


@app.get("/report", tags=["reports"], dependencies=[Depends(verify_api_key)])
def report(
        file_date: Optional[date] = Query(
            None, description="Date of the SBI file ({date:...} in SFTP_REMOTE_FILE), default today"),
        list_id: Optional[int] = Query(
            None, description="VICIdial list to read calls from (default REPORT_LIST_ID), e.g. 1001")):
    """Disposition CSV: the SBI columns of that day's file + DIAL_CNT and the latest calls."""
    settings = get_settings()
    source_file = posixpath.basename(settings.remote_file_for(file_date))
    try:
        if not settings.vicidial_enabled:
            raise ConfigError("Report needs the VICIdial DB: set VICIDIAL_DB_HOST in .env")
        result = report_service.disposition_report(source_file, list_id or settings.report_list_id)
    except KNOWN_ERRORS as exc:
        log.error("Report failed: %s: %s", type(exc).__name__, exc)
        return _error_response(exc, source_file)
    name = source_file.replace(".csv.gpg", "").replace(".gpg", "") + "_disposition.csv"
    return Response(content=result["csv"], media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/history", tags=["monitoring"], dependencies=[Depends(verify_api_key)])
def history(limit: int = Query(20, ge=1, le=200)):
    """Rows from the sftp_file_history table (needs Dialer DB settings)."""
    try:
        return {"history": dialer_db.get_history(limit)}
    except KNOWN_ERRORS as exc:
        return _error_response(exc, None)
