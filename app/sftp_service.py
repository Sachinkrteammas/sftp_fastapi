"""SFTP access with paramiko.

The encrypted file is opened with sftp.open(path, "rb") and read straight
into memory. sftp.get() is never used, so no local copy is created.
"""
from __future__ import annotations

import os
import socket

import paramiko

from .config import get_settings
from .logger import get_logger

log = get_logger("sftp")


class SftpAuthError(Exception):
    """Username/password rejected by the SFTP server."""


class SftpConnectionError(Exception):
    """Network, timeout, SSH handshake or host-key problem."""


class RemoteFileNotFoundError(Exception):
    """The configured remote file does not exist."""


class RemoteFileReadError(Exception):
    """The remote file exists but could not be read completely."""


def _verify_host_key(transport: paramiko.Transport, host: str, port: int) -> None:
    """Compare the server's host key with ~/.ssh/known_hosts."""
    settings = get_settings()
    server_key = transport.get_remote_server_key()

    if not settings.sftp_strict_host_key_checking:
        log.warning("Host key checking is DISABLED (SFTP_STRICT_HOST_KEY_CHECKING=false). "
                    "Server key fingerprint: %s", server_key.fingerprint)
        return

    known_hosts_path = os.path.expanduser(settings.sftp_known_hosts)
    if not os.path.isfile(known_hosts_path):
        raise SftpConnectionError(
            "known_hosts file not found. Add the server key with ssh-keyscan (see README)")

    host_keys = paramiko.HostKeys(known_hosts_path)
    lookup_name = host if port == 22 else f"[{host}]:{port}"
    entries = host_keys.lookup(lookup_name)
    expected = entries.get(server_key.get_name()) if entries else None

    if expected is None:
        raise SftpConnectionError(
            "SFTP server host key is not trusted. Add it with ssh-keyscan (see README)")
    if expected.asbytes() != server_key.asbytes():
        raise SftpConnectionError(
            "SFTP server host key does NOT match known_hosts (possible man-in-the-middle)")


def connect_sftp() -> tuple[paramiko.Transport, paramiko.SFTPClient]:
    """Open an authenticated SFTP session. Caller must close sftp and transport."""
    settings = get_settings()
    host, port = settings.sftp_host, settings.sftp_port
    log.info("SFTP connection started: %s:%s as user '%s'", host, port, settings.sftp_username)

    sock: socket.socket | None = None
    transport: paramiko.Transport | None = None
    try:
        try:
            sock = socket.create_connection((host, port), timeout=settings.sftp_timeout_seconds)
        except socket.gaierror as exc:
            raise SftpConnectionError("SFTP host name could not be resolved") from exc
        except (TimeoutError, socket.timeout) as exc:
            raise SftpConnectionError("SFTP connection timed out") from exc
        except OSError as exc:
            raise SftpConnectionError("Could not connect to SFTP server") from exc

        transport = paramiko.Transport(sock)
        transport.banner_timeout = settings.sftp_timeout_seconds
        transport.auth_timeout = settings.sftp_timeout_seconds
        try:
            transport.start_client(timeout=settings.sftp_timeout_seconds)
        except (paramiko.SSHException, EOFError, OSError) as exc:
            raise SftpConnectionError("SSH handshake with SFTP server failed") from exc

        _verify_host_key(transport, host, port)

        try:
            # Returns the auth methods still required when the password was only a partial success
            remaining = transport.auth_password(settings.sftp_username, settings.sftp_password)
        except paramiko.BadAuthenticationType as exc:
            raise SftpAuthError("SFTP server does not allow password authentication") from exc
        except paramiko.AuthenticationException as exc:
            raise SftpAuthError("SFTP authentication failed (wrong username or password)") from exc
        except (paramiko.SSHException, EOFError, OSError) as exc:
            raise SftpConnectionError("SFTP connection lost during authentication") from exc

        if not transport.is_authenticated():
            if remaining:
                raise SftpAuthError(
                    "SFTP password accepted, but the server also requires: "
                    f"{', '.join(remaining)} (e.g. publickey = an SSH key registered with the server)")
            raise SftpAuthError("SFTP authentication failed")

        try:
            sftp = paramiko.SFTPClient.from_transport(transport)
        except (paramiko.SSHException, EOFError, OSError) as exc:
            raise SftpConnectionError("Could not open SFTP channel") from exc
        if sftp is None:
            raise SftpConnectionError("Could not open SFTP channel")

        log.info("SFTP connection successful")
        return transport, sftp
    except Exception:
        # Clean up anything half-open before re-raising
        if transport is not None:
            transport.close()
        elif sock is not None:
            sock.close()
        raise


def read_remote_file(remote_path: str | None = None) -> bytes:
    """Read the whole remote encrypted file into memory and return its bytes."""
    settings = get_settings()
    path = remote_path or settings.sftp_remote_file
    max_bytes = settings.sftp_max_file_mb * 1024 * 1024

    transport: paramiko.Transport | None = None
    sftp: paramiko.SFTPClient | None = None
    remote_file: paramiko.SFTPFile | None = None
    try:
        transport, sftp = connect_sftp()

        try:
            remote_file = sftp.open(path, "rb")  # NOT sftp.get() -> no local file
        except FileNotFoundError as exc:
            raise RemoteFileNotFoundError(f"Remote file not found: {path}") from exc
        except PermissionError as exc:
            raise RemoteFileReadError(f"Permission denied for remote file: {path}") from exc
        except (OSError, paramiko.SSHException) as exc:
            raise RemoteFileReadError(f"Could not open remote file: {path}") from exc
        log.info("Remote file opened: %s", path)

        try:
            size = remote_file.stat().st_size or 0
            log.info("Encrypted file size: %s bytes", size)
            if size > max_bytes:
                raise RemoteFileReadError(
                    f"Remote file is larger than SFTP_MAX_FILE_MB ({settings.sftp_max_file_mb} MB)")
            if size == 0:
                raise RemoteFileReadError("Remote file is empty")

            remote_file.prefetch(size)          # faster sequential read
            data = remote_file.read()           # bytes, kept only in memory
        except RemoteFileReadError:
            raise
        except (OSError, EOFError, paramiko.SSHException) as exc:
            raise RemoteFileReadError("Failed while reading remote file") from exc

        if len(data) != size:
            raise RemoteFileReadError(
                f"Incomplete read: expected {size} bytes, got {len(data)}")
        log.info("Encrypted bytes read into memory: %s bytes", len(data))
        return data
    finally:
        for name, resource in (("remote_file", remote_file), ("sftp", sftp), ("transport", transport)):
            if resource is not None:
                try:
                    resource.close()
                except Exception:  # cleanup must never hide the real error
                    log.debug("Error while closing %s", name)
        log.info("SFTP resources closed")
