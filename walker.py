"""
In-place directory encrypt / decrypt using a thread pool.

encrypt_inplace:  file.txt        -> file.txt.vault  (original deleted)
decrypt_inplace:  file.txt.vault  -> file.txt         (.vault deleted)
verify_inplace:   check every .vault without writing anything
"""

from __future__ import annotations

import os
import tempfile
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from tqdm import tqdm

from crypto import MasterKey, ENCRYPTED_EXT, encrypt_file, decrypt_file


def _iter_plain(root: Path, skip: Callable[[Path], bool] | None = None):
    """Yield every plain (non-.vault) file under root, honouring skip."""
    for dirpath, dirnames, names in os.walk(root, topdown=True):
        dp = Path(dirpath)
        if skip:
            dirnames[:] = [d for d in dirnames if not skip(dp / d)]
        for name in names:
            if name == ".vault_session":
                continue
            p = dp / name
            if p.suffix == ENCRYPTED_EXT:
                continue                          # already encrypted
            if not skip or not skip(p):
                yield p


def _iter_vault(root: Path):
    """Yield every .vault file under root."""
    for dirpath, _, names in os.walk(root):
        for name in names:
            if name.endswith(ENCRYPTED_EXT) and name != ".vault_session":
                yield Path(dirpath) / name


def _run(files, task, desc, on_error):
    ok = err = 0
    with tqdm(total=len(files), unit="file", desc=desc, dynamic_ncols=True) as bar:
        with ThreadPoolExecutor(max_workers=task["workers"]) as pool:
            future_map = {pool.submit(task["fn"], f): f for f in files}
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


# ─── public API ───────────────────────────────────────────────────────────────

def encrypt_inplace(
    root: Path,
    master: MasterKey,
    workers: int = 4,
    on_error: Callable[[Path, Exception], None] | None = None,
    skip: Callable[[Path], bool] | None = None,
) -> tuple[int, int]:
    """
    Encrypt every plain file under root in-place:
      original  ->  original.vault  (original is deleted on success)
    """
    files = list(_iter_plain(root, skip))

    def _enc(src: Path):
        dst = Path(str(src) + ENCRYPTED_EXT)
        encrypt_file(src, dst, master)
        src.unlink()          # remove original only after successful encryption

    return _run(files, {"fn": _enc, "workers": workers}, "加密中", on_error)


def decrypt_inplace(
    root: Path,
    master: MasterKey,
    workers: int = 4,
    on_error: Callable[[Path, Exception], None] | None = None,
) -> tuple[int, int]:
    """
    Decrypt every .vault file under root in-place:
      original.vault  ->  original  (.vault is deleted on success)
    """
    files = list(_iter_vault(root))

    def _dec(src: Path):
        dst = Path(str(src)[: -len(ENCRYPTED_EXT)])
        decrypt_file(src, dst, master)
        src.unlink()          # remove .vault only after successful decryption

    return _run(files, {"fn": _dec, "workers": workers}, "解密中", on_error)


def verify_inplace(
    root: Path,
    master: MasterKey,
    workers: int = 4,
    on_error: Callable[[Path, Exception], None] | None = None,
) -> tuple[int, int]:
    """Verify every .vault file without writing anything to disk."""
    files = list(_iter_vault(root))
    tmp   = Path(tempfile.mkdtemp())

    def _vfy(src: Path):
        dst = tmp / src.name
        decrypt_file(src, dst, master)

    try:
        return _run(files, {"fn": _vfy, "workers": workers}, "校验中", on_error)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
