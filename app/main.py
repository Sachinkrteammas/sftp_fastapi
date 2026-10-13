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
from .decrypt_service import (DecodingError, DecryptionError, EncryptionError,
                              GpgNotAvailableError, InvalidEncryptedFileError, decrypt_data,
                              encrypt_data)
from .dialer_db import (DatabaseConnectionError, DatabaseInsertError,
                        DatabaseNotConfiguredError, DuplicateFileError)
from .logger import get_logger, setup_logging
from .processor import (InvalidCSVError, MissingColumnsError, NoValidRecordsError,
                        print_preview, process_csv)
from .sftp_service import (RemoteFileExistsError, RemoteFileNotFoundError, RemoteFileReadError,
                           RemoteFileWriteError, SftpAuthError, SftpConnectionError,
                           read_remote_file, upload_file)

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
    (RemoteFileExistsError, status.HTTP_409_CONFLICT),
    (RemoteFileWriteError, status.HTTP_502_BAD_GATEWAY),
    (EncryptionError, status.HTTP_500_INTERNAL_SERVER_ERROR),
]
KNOWN_ERRORS = tuple(exc for exc, _ in ERROR_STATUS)

# Failures after the file was read that should be written to history as FAILED
HISTORY_FAILURES = (InvalidEncryptedFileError, DecryptionError, DecodingError,
                    InvalidCSVError, MissingColumnsError, NoValidRecordsError,
                    DatabaseInsertError, DatabaseConnectionError, GpgNotAvailableError)

_process_lock = threading.Lock()
_send_lock = threading.Lock()  # one report upload at a time
_last_run: dict[str, Any] | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()  # fails fast with a clear message if .env is incomplete
    setup_logging(settings.log_level, settings.log_file)
    log.info("Service started | mode=%s", settings.process_mode)
    for feed in settings.feeds:
        log.info("Feed %s | list %s | today: %s", feed.name, feed.list_id,
                 settings.feed_file_for(feed))
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


def run_pipeline(remote_path: str, list_id: int) -> dict[str, Any]:
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
                                                   file_hash=file_hash, list_id=list_id)
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
        "vicidial_list_id": list_id if settings.vicidial_enabled else None,
        "seconds": round(time.monotonic() - started, 2),
    }


@app.get("/health", tags=["monitoring"])
def health() -> Dict[str, str]:
    return {"status": "ok"}


# Sync (def) endpoints run in FastAPI's thread pool, so blocking SFTP / GPG / MySQL
# calls do not block the event loop.
def _run_feed(feed, file_date: Optional[date]) -> tuple:
    """Process one feed. Returns (result dict, error response or None)."""
    settings = get_settings()
    remote_path = settings.feed_file_for(feed, file_date)
    file_name = posixpath.basename(remote_path)
    try:
        return {"feed": feed.name, **run_pipeline(remote_path, feed.list_id)}, None
    except KNOWN_ERRORS as exc:
        log.error("Processing failed (feed %s): %s: %s", feed.name, type(exc).__name__, exc)
        response = _error_response(exc, file_name)
        return {"feed": feed.name, "status": "error", "file": file_name,
                "http_status": response.status_code, "message": str(exc)}, response
    except Exception:
        # Full traceback goes to the log; the client gets a generic message.
        log.exception("Unexpected error during processing (feed %s)", feed.name)
        response = JSONResponse(status_code=500,
                                content={"status": "error", "message": "Internal server error"})
        return {"feed": feed.name, "status": "error", "file": file_name, "http_status": 500,
                "message": "Internal server error"}, response


# Sync (def) endpoints run in FastAPI's thread pool, so blocking SFTP / GPG / MySQL
# calls do not block the event loop.
@app.post("/process-file", tags=["processing"], dependencies=[Depends(verify_api_key)])
def process_file(
        file_date: Optional[date] = Query(
            None, description="Date for {date:...} in the file name, e.g. 2026-10-03 (default: today)"),
        feed: Optional[str] = Query(
            None, description="Only this feed (e.g. NC). Default: every feed in FEEDS")):
    """Read, decrypt and save the SBI file of every feed (or one feed)."""
    global _last_run
    settings = get_settings()
    try:
        feeds = [settings.feed(feed)] if feed else list(settings.feeds)
    except ConfigError as exc:
        return _error_response(exc, None)
    if not _process_lock.acquire(blocking=False):
        return _error_response(ProcessBusyError("Processing is already running, try again later"),
                               None)
    finished_at = lambda: datetime.now(timezone.utc).isoformat()  # noqa: E731
    try:
        results = [_run_feed(f, file_date) for f in feeds]
    finally:
        _process_lock.release()

    if len(results) == 1:  # one feed: same response as before feeds existed
        result, error = results[0]
        _last_run = {**result, "finished_at": finished_at()}
        return error if error is not None else result

    ok = sum(1 for result, error in results if error is None)
    overall = "success" if ok == len(results) else ("error" if ok == 0 else "partial")
    body = {"status": overall, "feeds": {result["feed"]: result for result, _ in results}}
    _last_run = {**body, "finished_at": finished_at()}
    return body


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
            None, description="VICIdial list to read calls from (default REPORT_LIST_ID), e.g. 1001"),
        format: Optional[str] = Query(
            None, pattern="^(txt|csv)$", description="txt (pipe-separated) or csv, default REPORT_FORMAT"),
        feed: Optional[str] = Query(
            None, description="Only this feed (e.g. NC). Default: all feeds in one report")):
    """Download the disposition report (not encrypted) to check it before sending."""
    settings = get_settings()
    fmt = format or settings.report_format
    source_file = None
    try:
        if not settings.vicidial_enabled:
            raise ConfigError("Report needs the VICIdial DB: set VICIDIAL_DB_HOST in .env")
        feeds = [settings.feed(feed)] if feed else list(settings.feeds)
        result = report_service.combined_report(file_date, feeds, list_id)
    except KNOWN_ERRORS as exc:
        log.error("Report failed: %s: %s", type(exc).__name__, exc)
        return _error_response(exc, source_file)
    name = settings.report_file_for(file_date)
    name = name[:-4] if name.endswith(".gpg") else name
    if not name.endswith("." + fmt):
        name = name.rsplit(".", 1)[0] + "." + fmt
    return Response(content=report_service.render(result["rows"], fmt),
                    media_type="text/csv" if fmt == "csv" else "text/plain",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.post("/report/send", tags=["reports"], dependencies=[Depends(verify_api_key)])
def report_send(
        file_date: Optional[date] = Query(
            None, description="Date of the SBI file, default today"),
        list_id: Optional[int] = Query(
            None, description="VICIdial list to read calls from (default REPORT_LIST_ID), e.g. 1001"),
        overwrite: bool = Query(
            False, description="Replace the report if it was already uploaded")):
    """Build the report (REPORT_FORMAT), encrypt it with SBI's public key and upload it to SBI."""
    settings = get_settings()
    source_file = None
    remote_path = posixpath.join(settings.report_upload_dir, settings.report_file_for(file_date))
    if not _send_lock.acquire(blocking=False):
        return _error_response(ProcessBusyError("A report upload is already running, try again later"),
                               source_file)
    started = time.monotonic()
    try:
        if not settings.vicidial_enabled:
            raise ConfigError("Report needs the VICIdial DB: set VICIDIAL_DB_HOST in .env")
        result = report_service.combined_report(file_date, list(settings.feeds), list_id)
        text = report_service.render(result["rows"], settings.report_format)
        encrypted = encrypt_data(text.encode("utf-8"), settings.report_gpg_recipient)
        del text  # plain report data only lived in memory
        size = upload_file(remote_path, encrypted, overwrite=overwrite)
    except KNOWN_ERRORS as exc:
        log.error("Report send failed: %s: %s", type(exc).__name__, exc)
        return _error_response(exc, source_file)
    finally:
        _send_lock.release()
    log.info("Report sent: %s (%s accounts, %s called)", remote_path, result["accounts"], result["called"])
    return {
        "status": "success",
        "feeds": result["feeds"],
        "missing_feeds": result["missing"],
        "uploaded_to": remote_path,
        "format": settings.report_format,
        "bytes": size,
        "accounts": result["accounts"],
        "called": result["called"],
        "calls": result["calls"],
        "seconds": round(time.monotonic() - started, 2),
    }


@app.get("/history", tags=["monitoring"], dependencies=[Depends(verify_api_key)])
def history(limit: int = Query(20, ge=1, le=200)):
    """Rows from the sftp_file_history table (needs Dialer DB settings)."""
    try:
        return {"history": dialer_db.get_history(limit)}
    except KNOWN_ERRORS as exc:
        return _error_response(exc, None)
