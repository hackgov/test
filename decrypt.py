#!/usr/bin/env python3
"""
vault-decrypt — 原地解密 / 完整性校验。
将 .vault 文件解密还原为原始文件，.vault 文件随即删除。
.vault_session 从盘符根目录读取。

用法:
  python decrypt.py restore [--drive C]
  python decrypt.py verify  [--drive C]
"""

import sys
import getpass
from pathlib import Path

import click

from crypto import load_session
from walker import decrypt_inplace, verify_inplace
import platform


def _get_password() -> str:
    pwd = getpass.getpass("输入加密密码: ")
    if not pwd:
        click.echo("错误：密码不能为空。", err=True)
        sys.exit(1)
    return pwd


def _error_cb(path: Path, exc: Exception) -> None:
    click.echo(f"  [跳过] {path.name}: {exc}", err=True)


def _resolve_root(drive: str) -> Path:
    if platform.system() == "Windows":
        letter = drive.rstrip(":\\/").upper()
        return Path(letter + ":\\")
    return Path(drive)


def _load(password: str | None, root: Path):
    if password is None:
        password = _get_password()
    click.echo("正在验证密码…")
    try:
        return load_session(password, root)
    except (FileNotFoundError, ValueError) as exc:
        click.echo(f"错误：{exc}", err=True)
        sys.exit(1)


@click.group()
def cli() -> None:
    """Vault-Decrypt — 原地解密与完整性校验工具。"""


@cli.command()
@click.option("--drive", default="C", show_default=True,
              help="要解密的盘符（与加密时一致）。")
@click.option("--workers", "-w", default=4, show_default=True)
@click.option("--password", "-p", default=None)
def restore(drive: str, workers: int, password: str | None) -> None:
    """
    将磁盘上所有 .vault 文件原地解密还原。

    \b
    解密规则：
      文件.vault  →  文件（.vault 文件立即删除）
      .vault_session 从盘符根目录读取。

    \b
    示例
    ----
      python decrypt.py restore
      python decrypt.py restore --drive D
    """
    root   = _resolve_root(drive)
    master = _load(password, root)

    click.echo(f"目标磁盘: {root}")
    click.echo()

    ok, err = decrypt_inplace(root, master, workers, _error_cb)

    click.echo()
    click.echo(f"完成。已解密: {ok}  错误: {err}")
    if err:
        sys.exit(2)


@cli.command()
@click.option("--drive", default="C", show_default=True)
@click.option("--workers", "-w", default=4, show_default=True)
@click.option("--password", "-p", default=None)
def verify(drive: str, workers: int, password: str | None) -> None:
    """
    校验磁盘上所有 .vault 文件的完整性，不修改任何文件。

    \b
    示例
    ----
      python decrypt.py verify
      python decrypt.py verify --drive D
    """
    root   = _resolve_root(drive)
    master = _load(password, root)

    click.echo()
    ok, err = verify_inplace(root, master, workers, _error_cb)

    click.echo()
    if err:
        click.echo(f"完整性校验失败！正常: {ok}  损坏/篡改: {err}", err=True)
        sys.exit(2)
    else:
        click.echo(f"全部 {ok} 个文件校验通过。")


if __name__ == "__main__":
    cli()
