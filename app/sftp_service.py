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
    path = os.path.expanduser(path)
    try:
        with open(path, "rb") as fh:
            header = fh.read(32)
    except OSError as exc:
        raise SftpAuthError("SFTP_PRIVATE_KEY file could not be read") from exc
    if header.startswith(b"PuTTY-User-Key-File"):
        # paramiko cannot read .ppk files; convert once with puttygen (see README)
        raise SftpAuthError("SFTP_PRIVATE_KEY is a PuTTY .ppk file. Convert it: "
                            "puttygen key.ppk -O private-openssh -o sbi_sftp_key")
    try:
        try:
            return paramiko.PKey.from_path(path, passphrase=passphrase.encode() if passphrase else None)
        except TypeError:
            # "Password was given but private key is not encrypted": passphrase not needed
            log.warning("SFTP_PRIVATE_KEY is not encrypted, ignoring SFTP_PRIVATE_KEY_PASSPHRASE")
            return paramiko.PKey.from_path(path)
    except paramiko.PasswordRequiredException as exc:
        raise SftpAuthError("SFTP_PRIVATE_KEY is encrypted: set SFTP_PRIVATE_KEY_PASSPHRASE") from exc
    except (paramiko.SSHException, ValueError, OSError) as exc:
        # Also raised for a wrong passphrase
        raise SftpAuthError("SFTP_PRIVATE_KEY could not be loaded "
                            "(wrong passphrase, or not an OpenSSH/PEM key file)") from exc


# Orders tried when the server wants several methods (key AND password).
# GoAnywhere (SBI) loops forever (key -> password -> key -> ...) with some orders,
# so each order runs on a fresh connection until one completes.
LOGIN_ORDERS = (
    ("publickey", "password"),
    ("password", "publickey"),
    ("keyboard-interactive", "publickey"),
    ("publickey", "keyboard-interactive"),
)


class _LoginLoop(SftpAuthError):
    """Server asked again for a method it already accepted: try another order."""


def _send_key(transport: paramiko.Transport, user: str, key: paramiko.PKey) -> list:
    """auth_publickey, falling back to the SHA-1 "ssh-rsa" signature for RSA keys."""
    try:
        return transport.auth_publickey(user, key)
    except paramiko.AuthenticationException:
        # paramiko >= 4 dropped ssh-rsa signing: nothing to retry there
        if key.get_name() != "ssh-rsa" or "ssh-rsa" not in transport._preferred_pubkeys:
            raise
    # Older servers (e.g. GoAnywhere) only verify SHA-1 "ssh-rsa" signatures;
    # PuTTY/WinSCP fall back to it the same way
    log.warning("SSH key not accepted with rsa-sha2, retrying with ssh-rsa")
    transport.disabled_algorithms = {**transport.disabled_algorithms,
                                     "pubkeys": ["rsa-sha2-512", "rsa-sha2-256"]}
    return transport.auth_publickey(user, key)


def _authenticate(transport: paramiko.Transport, settings, order: tuple) -> None:
    """Log in using the methods the server asks for, preferring them in `order`.

    Each method is used once; keyboard-interactive a second time only when
    SFTP_INTERACTIVE_RESPONSE is set (answer for a second password prompt).
    """
    user = settings.sftp_username
    try:
        transport.auth_none(user)  # asks the server which methods it accepts
    except paramiko.BadAuthenticationType as exc:
        remaining = list(exc.allowed_types)
    else:
        remaining = []
    log.info("Server login methods: %s (trying order: %s)",
             ", ".join(remaining) or "none needed", " -> ".join(order))

    ki_answers = [settings.sftp_password]
    if settings.sftp_interactive_response:
        ki_answers.append(settings.sftp_interactive_response)
    usable = {"publickey": bool(settings.sftp_private_key),
              "password": bool(settings.sftp_password),
              "keyboard-interactive": bool(settings.sftp_password)}
    limit = {"keyboard-interactive": len(ki_answers)}
    preference = list(order) + [m for m in ("publickey", "keyboard-interactive", "password")
                                if m not in order]
    used = {}

    while not transport.is_authenticated() and remaining:
        choices = [m for m in preference if m in remaining and usable.get(m)]
        method = next((m for m in choices if used.get(m, 0) < limit.get(m, 1)), None)
        if method is None:
            if choices:
                raise _LoginLoop("server asks again for: " + ", ".join(remaining))
            hint = (" Set SFTP_PRIVATE_KEY to the SSH key registered with the server."
                    if "publickey" in remaining and not settings.sftp_private_key else "")
            raise SftpAuthError("SFTP login incomplete, the server still requires: "
                                f"{', '.join(remaining)}.{hint}")
        used[method] = used.get(method, 0) + 1

        if method == "publickey":
            key = _load_private_key(settings.sftp_private_key, settings.sftp_private_key_passphrase)
            log.info("Sending SSH key (%s)", key.fingerprint)
            try:
                remaining = _send_key(transport, user, key)
            except paramiko.AuthenticationException as exc:
                raise SftpAuthError("SFTP server rejected the SSH key (SFTP_PRIVATE_KEY is not "
                                    "registered for this SFTP_USERNAME)") from exc

        elif method == "keyboard-interactive":
            ki_round = used[method]
            response = ki_answers[ki_round - 1]

            def answer(_title, _instructions, prompts, _round=ki_round):
                # Prompt text is written by the server, not a secret: log it to help diagnose
                for text, _echo in prompts:
                    log.info("Server prompt %d: %r", _round, text)
                return [response for _ in prompts]

            log.info("Sending password (keyboard-interactive)")
            try:
                remaining = transport.auth_interactive(user, answer)
            except paramiko.AuthenticationException as exc:
                which = "SFTP_PASSWORD" if ki_round == 1 else "SFTP_INTERACTIVE_RESPONSE"
                raise SftpAuthError(f"SFTP login rejected at password prompt {ki_round} "
                                    f"(check {which} in .env)") from exc

        else:
            log.info("Sending password (password method)")
            try:
                remaining = transport.auth_password(user, settings.sftp_password)
            except paramiko.AuthenticationException as exc:
                raise SftpAuthError("SFTP authentication failed (wrong username or password)") from exc

        if remaining and not transport.is_authenticated():
            log.info("%s accepted, server asks for more: %s", method, ", ".join(remaining))

    if not transport.is_authenticated():
        raise SftpAuthError("SFTP authentication failed")
    log.info("SFTP authentication successful (order: %s)", " -> ".join(order))


def _open_transport(settings) -> paramiko.Transport:
    """TCP connect + SSH handshake + host key check (not yet logged in)."""
    host, port = settings.sftp_host, settings.sftp_port
    try:
        sock = socket.create_connection((host, port), timeout=settings.sftp_timeout_seconds)
    except socket.gaierror as exc:
        raise SftpConnectionError("SFTP host name could not be resolved") from exc
    except (TimeoutError, socket.timeout) as exc:
        raise SftpConnectionError("SFTP connection timed out") from exc
    except OSError as exc:
        raise SftpConnectionError("Could not connect to SFTP server") from exc

    try:
        transport = paramiko.Transport(sock)
    except Exception:
        sock.close()
        raise
    try:
        transport.banner_timeout = settings.sftp_timeout_seconds
        transport.auth_timeout = settings.sftp_timeout_seconds
        try:
            transport.start_client(timeout=settings.sftp_timeout_seconds)
        except (paramiko.SSHException, EOFError, OSError) as exc:
            raise SftpConnectionError("SSH handshake with SFTP server failed") from exc
        _verify_host_key(transport, host, port)
        return transport
    except Exception:
        transport.close()
        raise


def connect_sftp() -> tuple[paramiko.Transport, paramiko.SFTPClient]:
    """Open an authenticated SFTP session. Caller must close sftp and transport."""
    settings = get_settings()
    log.info("SFTP connection started: %s:%s as user '%s'",
             settings.sftp_host, settings.sftp_port, settings.sftp_username)
    orders = [settings.sftp_login_order] if settings.sftp_login_order else list(LOGIN_ORDERS)

    for number, order in enumerate(orders, 1):
        transport = _open_transport(settings)
        try:
            try:
                _authenticate(transport, settings, order)
            except _LoginLoop as exc:
                if number == len(orders):
                    raise SftpAuthError("SFTP login never completes: the server keeps asking "
                                        f"for the same methods ({exc})") from exc
                log.warning("Login order %s does not complete (%s), reconnecting with the next order",
                            " -> ".join(order), exc)
                transport.close()
                continue
            except (paramiko.SSHException, EOFError, OSError) as exc:
                if isinstance(exc, paramiko.AuthenticationException):
                    raise SftpAuthError(f"SFTP authentication failed: {exc}") from exc
                raise SftpConnectionError("SFTP connection lost during authentication") from exc

            if not settings.sftp_login_order and number > 1:
                log.info("Tip: set SFTP_LOGIN_ORDER=%s in .env to log in with one connection",
                         ",".join(order))
            try:
                sftp = paramiko.SFTPClient.from_transport(transport)
            except (paramiko.SSHException, EOFError, OSError) as exc:
                raise SftpConnectionError("Could not open SFTP channel") from exc
            if sftp is None:
                raise SftpConnectionError("Could not open SFTP channel")

            log.info("SFTP connection successful")
            return transport, sftp
        except Exception:
            transport.close()
            raise
    raise SftpAuthError("SFTP authentication failed")  # not reached


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
