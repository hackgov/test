"""
Walks a source directory tree, encrypting or decrypting every file into a
mirror directory tree, preserving relative paths.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Generator

from tqdm import tqdm

from crypto import ENCRYPTED_EXT, encrypt_file, decrypt_file


def _all_files(root: Path) -> Generator[Path, None, None]:
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            yield Path(dirpath) / name


def _count_files(root: Path) -> int:
    return sum(1 for _ in _all_files(root))


def encrypt_directory(
    src_dir: Path,
    dst_dir: Path,
    password: str,
    on_error: Callable[[Path, Exception], None] | None = None,
) -> tuple[int, int]:
    """
    Encrypt every file under src_dir into dst_dir/<relative_path>.enc.
    Returns (success_count, error_count).
    """
    total = _count_files(src_dir)
    ok = err = 0

    with tqdm(total=total, unit="file", desc="Encrypting") as bar:
        for src in _all_files(src_dir):
            rel = src.relative_to(src_dir)
            dst = dst_dir / (str(rel) + ENCRYPTED_EXT)
            try:
                encrypt_file(src, dst, password)
                ok += 1
            except Exception as exc:
                err += 1
                if on_error:
                    on_error(src, exc)
            finally:
                bar.update(1)

    return ok, err


def decrypt_directory(
    src_dir: Path,
    dst_dir: Path,
    password: str,
    on_error: Callable[[Path, Exception], None] | None = None,
) -> tuple[int, int]:
    """
    Decrypt every *.enc file under src_dir into dst_dir, stripping the .enc
    suffix to restore original filenames.
    Returns (success_count, error_count).
    """
    enc_files = [p for p in _all_files(src_dir) if p.suffix == ENCRYPTED_EXT]
    ok = err = 0

    with tqdm(total=len(enc_files), unit="file", desc="Decrypting") as bar:
        for src in enc_files:
            rel = src.relative_to(src_dir)
            # Strip .enc to recover original name
            dst = dst_dir / Path(str(rel)[: -len(ENCRYPTED_EXT)])
            try:
                decrypt_file(src, dst, password)
                ok += 1
            except Exception as exc:
                err += 1
                if on_error:
                    on_error(src, exc)
            finally:
                bar.update(1)

    return ok, err
