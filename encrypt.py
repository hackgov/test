#!/usr/bin/env python3
"""
vault-encrypt — 加密器
用法: python encrypt.py --dest <备份目录> <源目录1> [源目录2 ...]
"""

import sys
import getpass
from pathlib import Path

import click

from crypto import create_session
from walker import encrypt_directory


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


def _src_to_subdir(src: Path) -> Path:
    """C:\\Users\\Alice  ->  C/Users/Alice,   /home/user  ->  home/user"""
    parts = list(src.resolve().parts)
    if parts and len(parts[0]) == 3 and parts[0][1:] == ":\\":
        parts[0] = parts[0][0]
    elif parts and parts[0] == "/":
        parts = parts[1:]
    return Path(*parts) if parts else Path(src.name)


@click.command()
@click.argument("sources", nargs=-1, required=True,
                type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--dest", "-d", required=True, type=click.Path(path_type=Path),
              help="备份目标目录（加密文件写入此处）。")
@click.option("--workers", "-w", default=4, show_default=True,
              help="并行线程数，SSD 可调到 8。")
@click.option("--password", "-p", default=None,
              help="密码（建议省略此选项，改为交互式输入）。")
def main(sources: tuple[Path, ...], dest: Path,
         workers: int, password: str | None) -> None:
    """
    将一个或多个源目录加密备份到 DEST。

    \b
    示例
    ----
    单个目录：
      python encrypt.py --dest E:\\Backup\\enc  C:\\Users\\Alice

    多个目录（同一 C 盘不同位置）：
      python encrypt.py --dest E:\\Backup\\enc  C:\\Users\\Alice  C:\\Work  C:\\ProgramData\\App

    跨盘符：
      python encrypt.py --dest E:\\Backup\\enc  C:\\Users\\Alice  D:\\Projects
    """
    if password is None:
        password = _get_password()

    click.echo("正在生成主密钥（Argon2id，约 1-2 秒）…")
    master = create_session(password, dest)
    click.echo(f"备份目标: {dest}")
    click.echo(f"线程数  : {workers}")
    click.echo()

    total_ok = total_err = 0
    for i, src in enumerate(sources, 1):
        sub_dst = dest / _src_to_subdir(src)
        click.echo(f"[{i}/{len(sources)}] {src}")
        click.echo(f"      → {sub_dst}")
        ok, err = encrypt_directory(src, sub_dst, master, workers, _error_cb)
        click.echo(f"      已加密: {ok}  错误: {err}\n")
        total_ok  += ok
        total_err += err

    click.echo(f"全部完成。总计加密: {total_ok}  总计错误: {total_err}")
    if total_err:
        sys.exit(2)


if __name__ == "__main__":
    main()
