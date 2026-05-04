"""
Directory-level encrypt / decrypt using a thread pool.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from tqdm import tqdm

from crypto import MasterKey, ENCRYPTED_EXT, encrypt_file, decrypt_file


def _iter_files(root: Path,
                skip: Callable[[Path], bool] | None = None):
    for dirpath, dirnames, names in os.walk(root, topdown=True):
        dp = Path(dirpath)
        if skip:
            # Prune subdirectories in-place so os.walk never descends into them
            dirnames[:] = [d for d in dirnames if not skip(dp / d)]
        for name in names:
            if name == ".vault_session":
                continue
            p = dp / name
            if not skip or not skip(p):
                yield p


def encrypt_directory(
    src_dir: Path,
    dst_dir: Path,
    master: MasterKey,
    workers: int = 4,
    on_error: Callable[[Path, Exception], None] | None = None,
    skip: Callable[[Path], bool] | None = None,
) -> tuple[int, int]:
    files = list(_iter_files(src_dir, skip))
    ok = err = 0

    with tqdm(total=len(files), unit="file", desc="Encrypting", dynamic_ncols=True) as bar:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {}
            for src in files:
                rel = src.relative_to(src_dir)
                dst = dst_dir / (str(rel) + ENCRYPTED_EXT)
                future_map[pool.submit(encrypt_file, src, dst, master)] = src

            for fut in as_completed(future_map):
                src = future_map[fut]
                try:
                    fut.result()
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
    master: MasterKey,
    workers: int = 4,
    on_error: Callable[[Path, Exception], None] | None = None,
) -> tuple[int, int]:
    files = [p for p in _iter_files(src_dir) if p.suffix == ENCRYPTED_EXT]
    ok = err = 0

    with tqdm(total=len(files), unit="file", desc="Decrypting", dynamic_ncols=True) as bar:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {}
            for src in files:
                rel = src.relative_to(src_dir)
                dst = dst_dir / Path(str(rel)[: -len(ENCRYPTED_EXT)])
                future_map[pool.submit(decrypt_file, src, dst, master)] = src

            for fut in as_completed(future_map):
                src = future_map[fut]
                try:
                    fut.result()
                    ok += 1
                except Exception as exc:
                    err += 1
                    if on_error:
                        on_error(src, exc)
                finally:
                    bar.update(1)

    return ok, err


def verify_directory(
    backup_dir: Path,
    master: MasterKey,
    workers: int = 4,
    on_error: Callable[[Path, Exception], None] | None = None,
) -> tuple[int, int]:
    """Decrypt each file into memory only — checks integrity without writing to disk."""
    from crypto import decrypt_file as _dec
    import tempfile, shutil

    files = [p for p in _iter_files(backup_dir) if p.suffix == ENCRYPTED_EXT]
    ok = err = 0
    tmp = Path(tempfile.mkdtemp())

    try:
        with tqdm(total=len(files), unit="file", desc="Verifying", dynamic_ncols=True) as bar:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                future_map = {}
                for src in files:
                    rel = src.relative_to(backup_dir)
                    dst = tmp / Path(str(rel)[: -len(ENCRYPTED_EXT)])
                    future_map[pool.submit(_dec, src, dst, master)] = src

                for fut in as_completed(future_map):
                    src = future_map[fut]
                    try:
                        fut.result()
                        ok += 1
                    except Exception as exc:
                        err += 1
                        if on_error:
                            on_error(src, exc)
                    finally:
                        bar.update(1)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    return ok, err
