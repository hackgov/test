#!/usr/bin/env python3
"""
vault-encrypt — 自动扫描整个磁盘（跳过系统目录），加密所有用户文件。
用法: python encrypt.py --dest <备份目录> [--drive C] [--workers 4]
"""

import sys
import getpass
import platform
from pathlib import Path

import click

from crypto import create_session
from walker import encrypt_directory

# ─── Windows 系统目录跳过名单（相对于盘符根目录，全部小写匹配）─────────────────

_WIN_SKIP_DIRS: set[str] = {
    "windows",
    "windows.old",
    "windows.~bt",        # 系统升级临时目录
    "windows.~ws",
    "$windows.~bt",
    "$windows.~ws",
    "$winreagent",
    "$recycle.bin",
    "system volume information",
    "recovery",
    "msocache",
    "perflogs",
    "boot",
}

# 根目录下的系统文件（不进行加密）
_WIN_SKIP_ROOT_FILES: set[str] = {
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
    "bootmgr",
    "bootmgr.efi",
    "bootnxt",
    "bootsect.bak",
    "boot.ini",
    "ntldr",
    "ntdetect.com",
    "io.sys",
    "msdos.sys",
}

# Linux / macOS 系统目录跳过名单（相对于 /，全部小写匹配）
_UNIX_SKIP_DIRS: set[str] = {
    "proc", "sys", "dev", "run", "tmp",
    "boot", "lost+found",
    "snap",                 # Ubuntu snap 挂载
}


# ─── 跳过判断逻辑 ──────────────────────────────────────────────────────────────

def _build_skip(root: Path) -> "Callable[[Path], bool]":
    """
    返回一个函数：对给定路径返回 True 表示应跳过（不加密）。
    跳过规则：
      - Windows：顶层目录名在 _WIN_SKIP_DIRS 中；或根目录下的系统文件名
      - Linux/macOS：顶层目录名在 _UNIX_SKIP_DIRS 中
    """
    is_win = platform.system() == "Windows"
    skip_dirs  = _WIN_SKIP_DIRS   if is_win else _UNIX_SKIP_DIRS
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

        # 跳过顶层系统目录（及其所有子路径）
        if top in skip_dirs:
            return True

        # 跳过根目录下的系统文件
        if len(parts) == 1 and not path.is_dir() and top in skip_files:
            return True

        return False

    return should_skip


# ─── 辅助 ──────────────────────────────────────────────────────────────────────

def _get_password() -> str:
    pwd = getpass.getpass("设置备份密码: ")
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
    """把盘符字母或路径解析为扫描根目录。"""
    if platform.system() == "Windows":
        letter = drive.rstrip(":\\/").upper()
        return Path(f"{letter}:\\")
    else:
        # Linux/macOS：drive 参数当作路径使用
        return Path(drive)


# ─── CLI ───────────────────────────────────────────────────────────────────────

@click.command()
@click.option("--dest", "-d", required=True, type=click.Path(path_type=Path),
              help="备份目标目录（加密文件写入此处）。")
@click.option("--drive", default="C",  show_default=True,
              help="Windows 盘符（如 C、D）；Linux/macOS 填挂载路径（如 /home）。")
@click.option("--workers", "-w", default=4, show_default=True,
              help="并行线程数，SSD 可调到 8。")
@click.option("--password", "-p", default=None,
              help="密码（建议省略此选项，改为交互式输入）。")
@click.option("--show-skipped", is_flag=True, default=False,
              help="打印被跳过的系统目录列表后退出，不执行加密。")
def main(dest: Path, drive: str, workers: int,
         password: str | None, show_skipped: bool) -> None:
    """
    自动扫描整个磁盘，跳过系统目录，加密所有用户文件到 DEST。

    \b
    跳过的 Windows 系统目录（顶层）：
      Windows, Windows.old, $Recycle.Bin, Recovery,
      System Volume Information, Boot, PerfLogs, MSOCache …

    \b
    示例
    ----
      python encrypt.py --dest E:\\Backup\\enc
      python encrypt.py --dest E:\\Backup\\enc --drive D
      python encrypt.py --dest E:\\Backup\\enc --workers 8
      python encrypt.py --dest E:\\Backup\\enc --show-skipped
    """
    root = _resolve_root(drive)

    if not root.exists():
        click.echo(f"错误：找不到磁盘根目录 {root}", err=True)
        sys.exit(1)

    skip = _build_skip(root)

    if show_skipped:
        click.echo(f"扫描根目录: {root}")
        click.echo("以下顶层目录将被跳过（系统目录）：")
        for d in sorted(root.iterdir()):
            if d.is_dir() and skip(d):
                click.echo(f"  [跳过] {d}")
        click.echo("\n以下顶层目录将被加密：")
        for d in sorted(root.iterdir()):
            if d.is_dir() and not skip(d):
                click.echo(f"  [加密] {d}")
        return

    if password is None:
        password = _get_password()

    click.echo("正在生成主密钥（Argon2id，约 1-2 秒）…")
    master = create_session(password, dest)

    click.echo(f"扫描根目录: {root}")
    click.echo(f"备份目标  : {dest}")
    click.echo(f"线程数    : {workers}")
    click.echo()

    ok, err = encrypt_directory(root, dest, master, workers, _error_cb, skip)

    click.echo()
    click.echo(f"全部完成。已加密: {ok}  错误: {err}")
    if err:
        sys.exit(2)


if __name__ == "__main__":
    main()
