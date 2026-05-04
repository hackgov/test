#!/usr/bin/env python3
"""
vault-decrypt — 解密器 / 完整性校验器
用法:
  python decrypt.py restore <备份目录> <还原目标目录>
  python decrypt.py verify  <备份目录>
"""

import sys
import getpass
from pathlib import Path

import click

from crypto import load_session
from walker import decrypt_directory, verify_directory


def _get_password() -> str:
    pwd = getpass.getpass("输入备份密码: ")
    if not pwd:
        click.echo("错误：密码不能为空。", err=True)
        sys.exit(1)
    return pwd


def _error_cb(path: Path, exc: Exception) -> None:
    click.echo(f"  [跳过] {path.name}: {exc}", err=True)


def _load(password: str | None, backup_dir: Path):
    if password is None:
        password = _get_password()
    click.echo("正在验证密码…")
    try:
        return load_session(password, backup_dir)
    except (FileNotFoundError, ValueError) as exc:
        click.echo(f"错误：{exc}", err=True)
        sys.exit(1)


@click.group()
def cli() -> None:
    """Vault-Decrypt — 解密与完整性校验工具。"""


@cli.command()
@click.argument("backup_dir",  type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument("restore_dir", type=click.Path(path_type=Path))
@click.option("--workers", "-w", default=4, show_default=True, help="并行线程数。")
@click.option("--password", "-p", default=None, help="密码（建议省略，改为交互式输入）。")
def restore(backup_dir: Path, restore_dir: Path,
            workers: int, password: str | None) -> None:
    """
    将 BACKUP_DIR 中的所有 .vault 文件解密还原到 RESTORE_DIR。

    BACKUP_DIR 必须包含加密时生成的 .vault_session 文件。

    \b
    示例
    ----
      python decrypt.py restore  E:\\Backup\\enc  E:\\Restore
    """
    master = _load(password, backup_dir)

    click.echo(f"备份来源: {backup_dir}")
    click.echo(f"还原目标: {restore_dir}")
    click.echo()

    ok, err = decrypt_directory(backup_dir, restore_dir, master, workers, _error_cb)

    click.echo()
    click.echo(f"完成。已解密: {ok}  错误: {err}")
    if err:
        sys.exit(2)


@cli.command()
@click.argument("backup_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--workers", "-w", default=4, show_default=True)
@click.option("--password", "-p", default=None)
def verify(backup_dir: Path, workers: int, password: str | None) -> None:
    """
    校验 BACKUP_DIR 中每个 .vault 文件的完整性，不写入任何文件。

    可在还原前运行，确认备份未损坏或被篡改。

    \b
    示例
    ----
      python decrypt.py verify  E:\\Backup\\enc
    """
    master = _load(password, backup_dir)
    click.echo()

    ok, err = verify_directory(backup_dir, master, workers, _error_cb)

    click.echo()
    if err:
        click.echo(f"完整性校验失败！正常: {ok}  损坏/篡改: {err}", err=True)
        sys.exit(2)
    else:
        click.echo(f"全部 {ok} 个文件完整性校验通过。")


if __name__ == "__main__":
    cli()
