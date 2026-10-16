"""In-memory GPG/PGP decryption with python-gnupg.

python-gnupg starts the local `gpg` program and streams the encrypted bytes
to it through a pipe (stdin). The passphrase is also sent through a pipe,
not the command line. No temporary file is written.
"""
from __future__ import annotations

import re

import gnupg

from .config import get_settings
from .logger import get_logger

log = get_logger("decrypt")

_gpg: gnupg.GPG | None = None


class GpgNotAvailableError(Exception):
    """gpg executable is missing or the keyring folder is unusable."""


class DecryptionError(Exception):
    """Valid GPG data, but it could not be decrypted (key/passphrase problem)."""


class InvalidEncryptedFileError(Exception):
    """The bytes are not GPG/PGP encrypted data."""


class EncryptionError(Exception):
    """Could not encrypt for the recipient (public key missing, expired or not trusted)."""


class DecodingError(Exception):
    """Decrypted bytes are not valid text in FILE_ENCODING."""


def _get_gpg() -> gnupg.GPG:
    global _gpg
    if _gpg is None:
        settings = get_settings()
        kwargs = {"gnupghome": settings.gpg_home} if settings.gpg_home else {}
        try:
            _gpg = gnupg.GPG(**kwargs)
        except (OSError, ValueError, RuntimeError) as exc:
            raise GpgNotAvailableError(
                "GPG executable not found or GPG home is not usable. Install gnupg (see README)"
            ) from exc
    return _gpg


GPG_ERR_BAD_PASSPHRASE = 11


def _has_bad_passphrase_error(stderr: str) -> bool:
    """gpg reports a wrong private-key passphrase as 'ERROR pkdecrypt_failed <code>'."""
    for line in stderr.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1] == "error" and parts[2] == "pkdecrypt_failed":
            try:
                return int(parts[3]) & 0xFFFF == GPG_ERR_BAD_PASSPHRASE
            except ValueError:
                return False
    return False


def _classify_failure(result: gnupg.Crypt) -> Exception:
    status = (result.status or "").lower()
    stderr = (result.stderr or "").lower()

    if "no valid openpgp data" in stderr or status == "no data was provided":
        return InvalidEncryptedFileError("File is not valid GPG/PGP encrypted data")
    # Check passphrase problems BEFORE "no secret key": with a wrong passphrase
    # gpg also prints NO_SECKEY even though the key is in the keyring.
    if ("bad_passphrase" in stderr or "bad passphrase" in status
            or "bad session key" in stderr or _has_bad_passphrase_error(stderr)):
        return DecryptionError("Decryption failed: wrong GPG passphrase")
    if "no_seckey" in stderr or "no secret key" in status:
        if "key_considered" in stderr:  # key exists but could not be unlocked
            return DecryptionError("Decryption failed: private key found but could not be "
                                   "unlocked (check GPG_PASSPHRASE)")
        return DecryptionError(
            "Decryption failed: the private key for this file is not in the GPG keyring")
    if "missing_passphrase" in stderr or "need passphrase" in status:
        return DecryptionError("Decryption failed: GPG passphrase is required")
    return DecryptionError("Decryption failed")


_UTF8_BOM = b"\xef\xbb\xbf"
# Byte-order marks, longest first (UTF-32 LE starts with the UTF-16 LE mark)
_BOMS = ((b"\xff\xfe\x00\x00", "utf-32"), (b"\x00\x00\xfe\xff", "utf-32"),
         (_UTF8_BOM, "utf-8-sig"), (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16"))
# .xlsx (zip) and old .xls (OLE2) files are not text at all
_EXCEL_SIGNATURES = (b"PK\x03\x04", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
# A valid UTF-8 multi-byte character (e.g. é = C3 A9): sign the file is UTF-8 with a few bad bytes
_UTF8_MULTIBYTE = re.compile(rb"[\xc2-\xf4][\x80-\xbf]+")


def _utf16_without_bom(data: bytes) -> str | None:
    """UTF-16 saved without a mark: plain text then has a zero byte in every 2nd position."""
    sample = data[:4000]
    half = len(sample) // 2
    if half < 2:
        return None
    even_zeros, odd_zeros = sample[0::2].count(0), sample[1::2].count(0)
    if odd_zeros > 0.3 * half and even_zeros < 0.05 * half:
        return "utf-16-le"
    if even_zeros > 0.3 * half and odd_zeros < 0.05 * half:
        return "utf-16-be"
    return None


def decode_text(data: bytes, preferred: str) -> tuple[str, str]:
    """Turn decrypted bytes into text, whatever encoding the sender used.

    Order: Excel check -> byte-order mark -> UTF-16 without mark -> preferred
    (FILE_ENCODING) -> UTF-8 -> cp1252 (Windows/Excel "ANSI") -> UTF-8 with only the broken
    bytes replaced (if it contains real UTF-8 characters) -> latin-1 (never fails).
    Returns (text, encoding used). A leading UTF-8 mark is always removed, so the first
    column name (account_no) is found whichever encoding is used.
    """
    if data.startswith(_EXCEL_SIGNATURES):
        raise DecodingError("Decrypted file is an Excel file (.xlsx/.xls), not a CSV. "
                            "Ask the sender to save it as CSV")
    for bom, encoding in _BOMS:
        if data.startswith(bom):
            try:
                return data.decode(encoding).lstrip("﻿"), encoding
            except UnicodeDecodeError:
                break  # mark present but content does not match: try the others
    utf16 = _utf16_without_bom(data)
    if utf16:
        try:
            return data.decode(utf16).lstrip("﻿"), utf16
        except UnicodeDecodeError:
            pass

    body = data[len(_UTF8_BOM):] if data.startswith(_UTF8_BOM) else data
    for encoding in dict.fromkeys((preferred, "utf-8", "cp1252")):  # unique, in order
        try:
            source = data if encoding.lower().replace("_", "-") == "utf-8-sig" else body
            return source.decode(encoding).lstrip("﻿"), encoding
        except UnicodeDecodeError:
            continue
        except LookupError:
            log.warning("FILE_ENCODING %r is not a known encoding, skipped", encoding)
    if _UTF8_MULTIBYTE.search(body):
        text = body.decode("utf-8", errors="replace")
        log.warning("Decrypted file is UTF-8 with %s invalid byte(s), replaced with '\ufffd'",
                    text.count("\ufffd"))
        return text, "utf-8 (repaired)"
    return body.decode("latin-1"), "latin-1"


def decrypt_data(encrypted_data: bytes) -> tuple[str, str]:
    """Decrypt bytes in memory. Returns (decrypted text, encoding used to read it)."""
    if not encrypted_data:
        raise InvalidEncryptedFileError("Encrypted file is empty")

    settings = get_settings()
    gpg = _get_gpg()
    log.info("Decryption started (%s encrypted bytes)", len(encrypted_data))

    result = gpg.decrypt(encrypted_data, passphrase=settings.gpg_passphrase or None)

    if not result.ok:
        error = _classify_failure(result)
        # status is a short gpg keyword such as "decryption failed"; safe to log
        log.error("Decryption failed (gpg status: %s)", result.status)
        raise error

    text, encoding = decode_text(result.data, settings.file_encoding)
    if encoding != settings.file_encoding:
        log.warning("Decrypted file read as %s (not FILE_ENCODING %s)", encoding, settings.file_encoding)
    log.info("Decryption successful (%s decrypted bytes, encoding %s)", len(result.data), encoding)
    return text, encoding


def encrypt_data(data: bytes, recipient: str) -> bytes:
    """Encrypt bytes in memory for `recipient` (a public key in the keyring); binary .gpg output."""
    if not recipient:
        raise EncryptionError("REPORT_GPG_RECIPIENT is not set (SBI's public key ID or fingerprint)")
    gpg = _get_gpg()
    # always_trust: the key was imported on purpose by the admin; GPG would otherwise refuse
    # a key that has no trust signature
    result = gpg.encrypt(data, [recipient], always_trust=True, armor=False)
    if not result.ok:
        log.error("Encryption failed (gpg status: %s)", result.status)
        raise EncryptionError(f"Encryption failed for recipient {recipient!r} (gpg status: "
                              f"{result.status}). Import SBI's public key: gpg --import <file>")
    log.info("Encrypted %s bytes for %s -> %s bytes", len(data), recipient, len(result.data))
    return result.data
