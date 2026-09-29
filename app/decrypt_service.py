"""In-memory GPG/PGP decryption with python-gnupg.

python-gnupg starts the local `gpg` program and streams the encrypted bytes
to it through a pipe (stdin). The passphrase is also sent through a pipe,
not the command line. No temporary file is written.
"""
from __future__ import annotations

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


def decrypt_data(encrypted_data: bytes) -> str:
    """Decrypt bytes in memory and return the decrypted text."""
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

    try:
        text = result.data.decode(settings.file_encoding)
    except (UnicodeDecodeError, LookupError) as exc:
        raise DecodingError(
            f"Decrypted file is not valid text in encoding '{settings.file_encoding}'. "
            "Set FILE_ENCODING (e.g. latin-1)") from exc

    log.info("Decryption successful (%s decrypted bytes)", len(result.data))
    return text
