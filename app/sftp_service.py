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


def _load_private_key(path: str, passphrase: str) -> paramiko.PKey:
    try:
        return paramiko.PKey.from_path(os.path.expanduser(path), passphrase=passphrase.encode() if passphrase else None)
    except paramiko.PasswordRequiredException as exc:
        raise SftpAuthError("SFTP_PRIVATE_KEY is encrypted: set SFTP_PRIVATE_KEY_PASSPHRASE") from exc
    except (paramiko.SSHException, ValueError, OSError) as exc:
        # Also raised for a wrong passphrase or a PuTTY .ppk file (convert it with puttygen)
        raise SftpAuthError("SFTP_PRIVATE_KEY could not be loaded "
                            "(wrong passphrase, or not an OpenSSH/PEM key file)") from exc


def _authenticate(transport: paramiko.Transport, settings) -> None:
    """Log in the same way WinSCP/PuTTY do: SSH key, then keyboard-interactive, then password.

    GoAnywhere (SBI) asks two passwords in a row: the first keyboard-interactive
    prompt takes SFTP_PASSWORD, the second one takes SFTP_INTERACTIVE_RESPONSE.
    """
    user = settings.sftp_username
    try:
        transport.auth_none(user)  # asks the server which methods it accepts
    except paramiko.BadAuthenticationType as exc:
        remaining = list(exc.allowed_types)
    else:
        remaining = []
    log.info("Server login methods: %s", ", ".join(remaining) or "none needed")

    # Answer for each keyboard-interactive round, in order
    ki_answers = [settings.sftp_password,
                  settings.sftp_interactive_response or settings.sftp_password]
    ki_round = 0
    tried = set()

    while not transport.is_authenticated() and remaining:
        if "publickey" in remaining and settings.sftp_private_key and "publickey" not in tried:
            tried.add("publickey")
            key = _load_private_key(settings.sftp_private_key, settings.sftp_private_key_passphrase)
            log.info("Sending SSH key (%s)", key.fingerprint)
            try:
                remaining = transport.auth_publickey(user, key)
            except paramiko.AuthenticationException:
                log.warning("SSH key not accepted, trying the next login method")

        elif "keyboard-interactive" in remaining and ki_round < len(ki_answers):
            response = ki_answers[ki_round]
            ki_round += 1

            def answer(_title, _instructions, prompts, _round=ki_round):
                # Prompt text is written by the server, not a secret: log it to help diagnose
                for text, _echo in prompts:
                    log.info("Server prompt %d: %r", _round, text)
                return [response for _ in prompts]

            try:
                remaining = transport.auth_interactive(user, answer)
            except paramiko.AuthenticationException as exc:
                which = "SFTP_PASSWORD" if ki_round == 1 else "SFTP_INTERACTIVE_RESPONSE"
                raise SftpAuthError(f"SFTP login rejected at password prompt {ki_round} "
                                    f"(check {which} in .env)") from exc
            if remaining:
                log.info("Prompt %d accepted, server asks for more: %s", ki_round, ", ".join(remaining))

        elif "password" in remaining and "password" not in tried:
            tried.add("password")
            try:
                remaining = transport.auth_password(user, settings.sftp_password)
            except paramiko.AuthenticationException as exc:
                raise SftpAuthError("SFTP authentication failed (wrong username or password)") from exc

        else:
            hint = (" Set SFTP_PRIVATE_KEY to the SSH key registered with the server."
                    if "publickey" in remaining and not settings.sftp_private_key else "")
            raise SftpAuthError("SFTP login incomplete, the server still requires: "
                                f"{', '.join(remaining)}.{hint}")

    if not transport.is_authenticated():
        raise SftpAuthError("SFTP authentication failed")
    log.info("SFTP authentication successful")


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
            _authenticate(transport, settings)
        except (paramiko.SSHException, EOFError, OSError) as exc:
            if isinstance(exc, paramiko.AuthenticationException):
                raise SftpAuthError(f"SFTP authentication failed: {exc}") from exc
            raise SftpConnectionError("SFTP connection lost during authentication") from exc

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
