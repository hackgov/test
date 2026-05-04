"""
AES-256 file encryption/decryption using Fernet (symmetric, authenticated).
Key is derived from a user password via PBKDF2-HMAC-SHA256.
"""

import os
import base64
import struct
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Encrypted files get this extension appended
ENCRYPTED_EXT = ".enc"
# Prefix written at the start of every encrypted file: magic + version + salt
MAGIC = b"BACKUPENC"
VERSION = 1
SALT_SIZE = 16
KDF_ITERATIONS = 600_000


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte Fernet key from password + salt via PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    raw = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


def encrypt_file(src: Path, dst: Path, password: str) -> None:
    """
    Encrypt src -> dst.
    File layout: MAGIC (9) | VERSION (1) | SALT (16) | ciphertext
    """
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    f = Fernet(key)

    plaintext = src.read_bytes()
    ciphertext = f.encrypt(plaintext)

    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("wb") as out:
        out.write(MAGIC)
        out.write(struct.pack("B", VERSION))
        out.write(salt)
        out.write(ciphertext)


def decrypt_file(src: Path, dst: Path, password: str) -> None:
    """
    Decrypt src -> dst.
    Raises ValueError on wrong password or corrupted file.
    """
    data = src.read_bytes()

    magic_len = len(MAGIC)
    if not data.startswith(MAGIC):
        raise ValueError(f"{src}: not a recognised encrypted backup file")

    offset = magic_len
    version = struct.unpack("B", data[offset : offset + 1])[0]
    if version != VERSION:
        raise ValueError(f"{src}: unsupported version {version}")
    offset += 1

    salt = data[offset : offset + SALT_SIZE]
    offset += SALT_SIZE

    ciphertext = data[offset:]

    key = derive_key(password, salt)
    f = Fernet(key)
    try:
        plaintext = f.decrypt(ciphertext)
    except InvalidToken:
        raise ValueError(f"{src}: wrong password or file is corrupted")

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(plaintext)
