#!/usr/bin/env python3
"""
backup-encrypt — encrypt or decrypt a directory tree for secure backup.

Usage examples
--------------
Encrypt C:\\Users\\Alice into D:\\Backup\\encrypted:
    python main.py encrypt "C:\\Users\\Alice" "D:\\Backup\\encrypted"

Restore the encrypted backup to D:\\Backup\\restored:
    python main.py decrypt "D:\\Backup\\encrypted" "D:\\Backup\\restored"
"""

import sys
import getpass
from pathlib import Path

import click

from walker import encrypt_directory, decrypt_directory


def _prompt_password(confirm: bool) -> str:
    pwd = getpass.getpass("Enter backup password: ")
    if not pwd:
        click.echo("Password must not be empty.", err=True)
        sys.exit(1)
    if confirm:
        pwd2 = getpass.getpass("Confirm password: ")
        if pwd != pwd2:
            click.echo("Passwords do not match.", err=True)
            sys.exit(1)
    return pwd


def _error_handler(path: Path, exc: Exception) -> None:
    click.echo(f"  [SKIP] {path}: {exc}", err=True)


@click.group()
def cli() -> None:
    """Backup Encrypt — AES-256 file backup tool."""


@cli.command()
@click.argument("source", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument("destination", type=click.Path(path_type=Path))
@click.option("--password", "-p", default=None, help="Password (omit to be prompted)")
def encrypt(source: Path, destination: Path, password: str | None) -> None:
    """
    Encrypt every file in SOURCE and write to DESTINATION.

    Each output file is SOURCE_FILE.enc — the original files are NOT modified.
    """
    if password is None:
        password = _prompt_password(confirm=True)

    click.echo(f"Source      : {source}")
    click.echo(f"Destination : {destination}")
    click.echo()

    ok, err = encrypt_directory(source, destination, password, _error_handler)

    click.echo()
    click.echo(f"Done. Encrypted: {ok}  Errors: {err}")
    if err:
        click.echo("Files listed as [SKIP] were not encrypted.", err=True)
        sys.exit(2)


@cli.command()
@click.argument("source", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument("destination", type=click.Path(path_type=Path))
@click.option("--password", "-p", default=None, help="Password (omit to be prompted)")
def decrypt(source: Path, destination: Path, password: str | None) -> None:
    """
    Decrypt every .enc file in SOURCE and write restored files to DESTINATION.

    Use the same password that was used when encrypting.
    """
    if password is None:
        password = _prompt_password(confirm=False)

    click.echo(f"Source      : {source}")
    click.echo(f"Destination : {destination}")
    click.echo()

    ok, err = decrypt_directory(source, destination, password, _error_handler)

    click.echo()
    click.echo(f"Done. Decrypted: {ok}  Errors: {err}")
    if err:
        click.echo("Files listed as [SKIP] were not decrypted (wrong password or corrupted).", err=True)
        sys.exit(2)


if __name__ == "__main__":
    cli()
