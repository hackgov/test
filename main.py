#!/usr/bin/env python3
"""
vault-backup  —  cascade-encrypted directory backup
Commands:  encrypt | decrypt | verify
"""

import sys
import getpass
from pathlib import Path

import click

from crypto import create_session, load_session
from walker import encrypt_directory, decrypt_directory, verify_directory


# ─── helpers ──────────────────────────────────────────────────────────────────

def _get_password(confirm: bool) -> str:
    pwd = getpass.getpass("Password: ")
    if not pwd:
        click.echo("Error: password must not be empty.", err=True)
        sys.exit(1)
    if confirm:
        if getpass.getpass("Confirm password: ") != pwd:
            click.echo("Error: passwords do not match.", err=True)
            sys.exit(1)
    return pwd


def _error_cb(path: Path, exc: Exception) -> None:
    click.echo(f"  [SKIP] {path.name}: {exc}", err=True)


# ─── CLI ──────────────────────────────────────────────────────────────────────

@click.group()
def cli() -> None:
    """Vault-Backup — AES-256-GCM + ChaCha20-Poly1305 cascade backup tool."""


@cli.command()
@click.argument("source",      type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument("destination", type=click.Path(path_type=Path))
@click.option("--workers", "-w", default=4, show_default=True,
              help="Parallel worker threads.")
@click.option("--password", "-p", default=None,
              help="Password (omit to be prompted securely).")
def encrypt(source: Path, destination: Path, workers: int, password: str | None) -> None:
    """
    Encrypt every file under SOURCE into DESTINATION.

    A .vault_session file is created in DESTINATION — keep it together
    with the encrypted files; it is required for decryption.
    Original files are never modified.
    """
    if password is None:
        password = _get_password(confirm=True)

    click.echo("Deriving master key (Argon2id, ~1-2 s) …")
    master = create_session(password, destination)

    click.echo(f"Source      : {source}")
    click.echo(f"Destination : {destination}")
    click.echo(f"Workers     : {workers}")
    click.echo()

    ok, err = encrypt_directory(source, destination, master, workers, _error_cb)

    click.echo()
    click.echo(f"Done.  Encrypted: {ok}   Errors: {err}")
    if err:
        sys.exit(2)


@cli.command()
@click.argument("source",      type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument("destination", type=click.Path(path_type=Path))
@click.option("--workers", "-w", default=4, show_default=True)
@click.option("--password", "-p", default=None)
def decrypt(source: Path, destination: Path, workers: int, password: str | None) -> None:
    """
    Decrypt all .vault files in SOURCE into DESTINATION.

    SOURCE must contain the .vault_session file created during encryption.
    """
    if password is None:
        password = _get_password(confirm=False)

    click.echo("Verifying password …")
    try:
        master = load_session(password, source)
    except (FileNotFoundError, ValueError) as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Source      : {source}")
    click.echo(f"Destination : {destination}")
    click.echo()

    ok, err = decrypt_directory(source, destination, master, workers, _error_cb)

    click.echo()
    click.echo(f"Done.  Decrypted: {ok}   Errors: {err}")
    if err:
        sys.exit(2)


@cli.command()
@click.argument("backup_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--workers", "-w", default=4, show_default=True)
@click.option("--password", "-p", default=None)
def verify(backup_dir: Path, workers: int, password: str | None) -> None:
    """
    Verify the integrity of every .vault file in BACKUP_DIR without
    writing any output — useful to confirm backup is intact.
    """
    if password is None:
        password = _get_password(confirm=False)

    click.echo("Verifying password …")
    try:
        master = load_session(password, backup_dir)
    except (FileNotFoundError, ValueError) as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    click.echo()
    ok, err = verify_directory(backup_dir, master, workers, _error_cb)

    click.echo()
    if err:
        click.echo(f"INTEGRITY CHECK FAILED.  OK: {ok}   Corrupted/Tampered: {err}", err=True)
        sys.exit(2)
    else:
        click.echo(f"All {ok} file(s) passed integrity check.")


if __name__ == "__main__":
    cli()
