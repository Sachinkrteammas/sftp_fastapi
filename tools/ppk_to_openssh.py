"""Convert a PuTTY v3 RSA key (.ppk) to an OpenSSH private key file.

Needed because paramiko cannot read .ppk and older puttygen (< 0.75) cannot
read PPK v3. Also repairs a .ppk whose Public-Lines were damaged (e.g. a line
turned into "#NAME?" by Excel): the public key is rebuilt from the private
part and the result is checked against Private-MAC, so a wrong passphrase or
a damaged private part is always detected.

Usage (asks for the passphrase, prints nothing secret):
    pip install argon2-cffi
    python tools/ppk_to_openssh.py sbi_key.ppk keys/sbi_sftp_key
The output key has no passphrase: keep it chmod 600.
"""
from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import os
import struct
import sys
from typing import Dict, List, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _ssh_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _mpint(n: int) -> bytes:
    raw = n.to_bytes((n.bit_length() + 8) // 8, "big") if n else b""
    return _ssh_string(raw)


def _read_mpints(blob: bytes, count: int) -> List[int]:
    out, pos = [], 0
    for _ in range(count):
        (length,) = struct.unpack(">I", blob[pos:pos + 4])
        pos += 4
        out.append(int.from_bytes(blob[pos:pos + length], "big"))
        pos += length
    return out


def parse_ppk(text: str) -> Tuple[Dict[str, str], List[str], List[str]]:
    lines = [ln.strip() for ln in text.replace("\r", "").split("\n") if ln.strip()]
    fields: Dict[str, str] = {}
    public: List[str] = []
    private: List[str] = []
    i = 0
    while i < len(lines):
        key, _, value = lines[i].partition(": ")
        fields[key] = value
        i += 1
        if key in ("Public-Lines", "Private-Lines"):
            block = lines[i:i + int(value)]
            (public if key == "Public-Lines" else private).extend(block)
            i += int(value)
    return fields, public, private


def convert(text: str, passphrase: str) -> bytes:
    fields, public_lines, private_lines = parse_ppk(text)
    if fields.get("PuTTY-User-Key-File-3") != "ssh-rsa":
        sys.exit("Only 'PuTTY-User-Key-File-3: ssh-rsa' keys are supported")
    encryption = fields.get("Encryption", "none")

    private_enc = base64.b64decode("".join(private_lines))
    if encryption == "aes256-cbc":
        try:
            from argon2.low_level import Type, hash_secret_raw
        except ImportError:
            sys.exit("Missing package: run  pip install argon2-cffi")
        argon_type = {"Argon2id": Type.ID, "Argon2i": Type.I, "Argon2d": Type.D}[fields["Key-Derivation"]]
        material = hash_secret_raw(
            passphrase.encode(), bytes.fromhex(fields["Argon2-Salt"]),
            time_cost=int(fields["Argon2-Passes"]), memory_cost=int(fields["Argon2-Memory"]),
            parallelism=int(fields["Argon2-Parallelism"]), hash_len=80, type=argon_type, version=19)
        cipher_key, iv, mac_key = material[:32], material[32:48], material[48:]
        decryptor = Cipher(algorithms.AES(cipher_key), modes.CBC(iv)).decryptor()
        private_blob = decryptor.update(private_enc) + decryptor.finalize()
    elif encryption == "none":
        private_blob, mac_key = private_enc, b""
    else:
        sys.exit(f"Unsupported Encryption: {encryption}")

    # e comes from the start of the public blob (first line is intact)
    head = base64.b64decode(public_lines[0][:len(public_lines[0]) // 4 * 4])
    e = _read_mpints(head[4 + len(b"ssh-rsa"):], 1)[0]
    try:
        d, p, q, iqmp = _read_mpints(private_blob, 4)
    except struct.error:  # garbage after decrypting with a wrong passphrase
        sys.exit("Private-MAC check FAILED: wrong passphrase, or the private part is damaged")
    public_blob = _ssh_string(b"ssh-rsa") + _mpint(e) + _mpint(p * q)

    mac_data = b"".join(_ssh_string(x) for x in (
        b"ssh-rsa", encryption.encode(), fields.get("Comment", "").encode(),
        public_blob, private_blob))
    expected = hmac.new(mac_key, mac_data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, fields["Private-MAC"].lower()):
        sys.exit("Private-MAC check FAILED: wrong passphrase, or the private part is damaged")

    rebuilt = base64.b64encode(public_blob).decode()
    rebuilt_lines = [rebuilt[i:i + 64] for i in range(0, len(rebuilt), 64)]
    repaired = [n + 1 for n, (old, new) in enumerate(zip(public_lines, rebuilt_lines)) if old != new]
    if repaired:
        print(f"Repaired damaged public line(s): {repaired}")

    numbers = rsa.RSAPrivateNumbers(
        p=p, q=q, d=d, dmp1=d % (p - 1), dmq1=d % (q - 1), iqmp=iqmp,
        public_numbers=rsa.RSAPublicNumbers(e, p * q))
    key = numbers.private_key()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                             serialization.NoEncryption())


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    passphrase = ""
    if "Encryption: none" not in text:
        passphrase = getpass.getpass("Key passphrase: ")
    pem = convert(text, passphrase)
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    print(f"OK: MAC verified, OpenSSH key written to {dst} (no passphrase, keep chmod 600)")


if __name__ == "__main__":
    main()
