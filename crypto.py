"""
Cascade encryption: AES-256-GCM (inner) -> ChaCha20-Poly1305 (outer)
KDF: Argon2id  memory=256 MB, time=3, parallelism=4  -> 64-byte master key
Per-file keys: HKDF-SHA3-256 from master key + random file seed (32 B)

Breaking either cipher layer independently still doesn't reveal the plaintext.

File on disk (.vault):
  HEADER_NONCE  12 B   random
  HEADER_LEN     4 B   LE uint32
  HEADER_CT    variable   ChaCha20-Poly1305(header_key, HEADER_NONCE, header_plain)
  CHUNKS       remaining bytes

header_plain:
  INNER_MAGIC   8 B   fixed sentinel (verified after decryption)
  FILE_SEED    32 B   random; drives HKDF for per-file keys
  BASE_NONCE_A 12 B   base nonce for AES layer
  BASE_NONCE_C 12 B   base nonce for ChaCha layer
  CHUNK_COUNT   8 B   LE uint64
  NAME_LEN      2 B   LE uint16
  ORIG_NAME  NAME_LEN B   UTF-8 original filename
  ORIG_SIZE     8 B   LE uint64

Each chunk:
  CLEN  4 B  LE uint32
  CT    CLEN B   ChaCha20-Poly1305( ChaCha_key, nonce_c_i,
                   AES-256-GCM( AES_key, nonce_a_i, plaintext_chunk, aad_i ),
                 aad_i )
  nonce_X_i = BASE_NONCE_X XOR i.to_bytes(12,'big')
  aad_i     = i.to_bytes(8,'big')

.vault_session (destination root):
  ARGON2_SALT  32 B
  VFY_NONCE    12 B
  VFY_CT       24 B   ChaCha20-Poly1305(header_key, VFY_NONCE, INNER_MAGIC)
                       -> decryption success proves correct password
"""

import os
import struct
from pathlib import Path
from typing import NamedTuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from argon2.low_level import hash_secret_raw, Type as Argon2Type

# ─── constants ────────────────────────────────────────────────────────────────

INNER_MAGIC      = b"\xB4\xCF\x7A\x2E\x91\xD0\x55\x3F"
ENCRYPTED_EXT    = ".vault"
SESSION_FILENAME = ".vault_session"

_ARGON2_SALT_LEN = 32
_ARGON2_TIME     = 3
_ARGON2_MEM_KB   = 262144   # 256 MB
_ARGON2_PARALLEL = 4
_ARGON2_HASH_LEN = 64       # 32 B header_key || 32 B session_key

_FILE_SEED_LEN   = 32
_NONCE_LEN       = 12
_CHUNK_SIZE      = 131072   # 128 KB plaintext per chunk


# ─── key derivation ───────────────────────────────────────────────────────────

class MasterKey(NamedTuple):
    header_key:  bytes   # 32 B – encrypts per-file headers
    session_key: bytes   # 32 B – drives HKDF for per-file data keys


class FileKeys(NamedTuple):
    aes_key:    bytes   # 32 B
    chacha_key: bytes   # 32 B


def _argon2id(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=_ARGON2_TIME,
        memory_cost=_ARGON2_MEM_KB,
        parallelism=_ARGON2_PARALLEL,
        hash_len=_ARGON2_HASH_LEN,
        type=Argon2Type.ID,
    )


def _hkdf_sha3(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(ikm)


def derive_master(password: str, salt: bytes) -> MasterKey:
    raw = _argon2id(password, salt)
    return MasterKey(header_key=raw[:32], session_key=raw[32:])


def _derive_file_keys(master: MasterKey, file_seed: bytes) -> FileKeys:
    return FileKeys(
        aes_key=_hkdf_sha3(master.session_key, file_seed, b"aes-256-gcm-v1"),
        chacha_key=_hkdf_sha3(master.session_key, file_seed, b"chacha20-poly1305-v1"),
    )


# ─── nonce helpers ────────────────────────────────────────────────────────────

def _nonce(base: bytes, idx: int) -> bytes:
    return bytes(a ^ b for a, b in zip(base, idx.to_bytes(_NONCE_LEN, "big")))


def _aad(idx: int) -> bytes:
    return idx.to_bytes(8, "big")


# ─── chunk-level cascade ──────────────────────────────────────────────────────

def _enc_chunk(plain: bytes, keys: FileKeys,
               base_a: bytes, base_c: bytes, idx: int) -> bytes:
    aad = _aad(idx)
    mid = AESGCM(keys.aes_key).encrypt(_nonce(base_a, idx), plain, aad)
    return ChaCha20Poly1305(keys.chacha_key).encrypt(_nonce(base_c, idx), mid, aad)


def _dec_chunk(ct: bytes, keys: FileKeys,
               base_a: bytes, base_c: bytes, idx: int) -> bytes:
    aad = _aad(idx)
    mid = ChaCha20Poly1305(keys.chacha_key).decrypt(_nonce(base_c, idx), ct, aad)
    return AESGCM(keys.aes_key).decrypt(_nonce(base_a, idx), mid, aad)


# ─── session file ─────────────────────────────────────────────────────────────

def create_session(password: str, dest_dir: Path) -> MasterKey:
    """Derive master key, write .vault_session, return MasterKey."""
    salt   = os.urandom(_ARGON2_SALT_LEN)
    master = derive_master(password, salt)

    vfy_nonce = os.urandom(_NONCE_LEN)
    vfy_ct    = ChaCha20Poly1305(master.header_key).encrypt(vfy_nonce, INNER_MAGIC, None)

    dest_dir.mkdir(parents=True, exist_ok=True)
    with (dest_dir / SESSION_FILENAME).open("wb") as f:
        f.write(salt)       # 32
        f.write(vfy_nonce)  # 12
        f.write(vfy_ct)     # 8 + 16 = 24

    return master


def load_session(password: str, backup_dir: Path) -> MasterKey:
    """Read .vault_session, verify password, return MasterKey."""
    path = backup_dir / SESSION_FILENAME
    if not path.exists():
        raise FileNotFoundError(
            f"Session file not found: {path}\n"
            "Point to the backup destination directory."
        )

    data      = path.read_bytes()
    salt      = data[0:32]
    vfy_nonce = data[32:44]
    vfy_ct    = data[44:]

    master = derive_master(password, salt)
    try:
        ChaCha20Poly1305(master.header_key).decrypt(vfy_nonce, vfy_ct, None)
    except InvalidTag:
        raise ValueError("Wrong password.")

    return master


# ─── file encryption ──────────────────────────────────────────────────────────

def encrypt_file(src: Path, dst: Path, master: MasterKey) -> None:
    plain_data = src.read_bytes()
    orig_name  = src.name.encode("utf-8")

    file_seed = os.urandom(_FILE_SEED_LEN)
    base_a    = os.urandom(_NONCE_LEN)
    base_c    = os.urandom(_NONCE_LEN)
    keys      = _derive_file_keys(master, file_seed)

    chunks_plain = [
        plain_data[i: i + _CHUNK_SIZE]
        for i in range(0, max(len(plain_data), 1), _CHUNK_SIZE)
    ] or [b""]

    chunks_enc = [_enc_chunk(c, keys, base_a, base_c, i)
                  for i, c in enumerate(chunks_plain)]

    header_plain = (
        INNER_MAGIC
        + file_seed
        + base_a
        + base_c
        + struct.pack("<Q", len(chunks_enc))
        + struct.pack("<H", len(orig_name))
        + orig_name
        + struct.pack("<Q", len(plain_data))
    )

    h_nonce = os.urandom(_NONCE_LEN)
    h_ct    = ChaCha20Poly1305(master.header_key).encrypt(h_nonce, header_plain, None)

    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("wb") as f:
        f.write(h_nonce)
        f.write(struct.pack("<I", len(h_ct)))
        f.write(h_ct)
        for c in chunks_enc:
            f.write(struct.pack("<I", len(c)))
            f.write(c)


# ─── file decryption ──────────────────────────────────────────────────────────

def decrypt_file(src: Path, dst: Path, master: MasterKey) -> None:
    data   = src.read_bytes()
    offset = 0

    h_nonce = data[offset: offset + _NONCE_LEN]; offset += _NONCE_LEN
    h_len   = struct.unpack("<I", data[offset: offset + 4])[0]; offset += 4
    h_ct    = data[offset: offset + h_len]; offset += h_len

    try:
        hp = ChaCha20Poly1305(master.header_key).decrypt(h_nonce, h_ct, None)
    except InvalidTag:
        raise ValueError(f"{src.name}: header auth failed — wrong key or corrupted")

    hoff = 0
    if hp[hoff: hoff + 8] != INNER_MAGIC:
        raise ValueError(f"{src.name}: not a valid vault file")
    hoff += 8

    file_seed   = hp[hoff: hoff + _FILE_SEED_LEN]; hoff += _FILE_SEED_LEN
    base_a      = hp[hoff: hoff + _NONCE_LEN];     hoff += _NONCE_LEN
    base_c      = hp[hoff: hoff + _NONCE_LEN];     hoff += _NONCE_LEN
    chunk_count = struct.unpack("<Q", hp[hoff: hoff + 8])[0]; hoff += 8
    name_len    = struct.unpack("<H", hp[hoff: hoff + 2])[0]; hoff += 2
    hoff += name_len   # orig_name (preserved via dst path)

    keys  = _derive_file_keys(master, file_seed)
    parts = []

    for i in range(chunk_count):
        clen = struct.unpack("<I", data[offset: offset + 4])[0]; offset += 4
        ct   = data[offset: offset + clen]; offset += clen
        try:
            parts.append(_dec_chunk(ct, keys, base_a, base_c, i))
        except InvalidTag:
            raise ValueError(
                f"{src.name}: chunk {i} auth failed — file is corrupted or tampered"
            )

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(b"".join(parts))
