#!/usr/bin/env python3
"""
vault-backup  —  cascade-encrypted directory backup
Commands:  encrypt | decrypt | verify
"""

import sys
import getpass
from pathlib import Path, PurePosixPath, PureWindowsPath

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


def _src_to_subdir(src: Path) -> Path:
    """
    Map an absolute source path to a safe relative subdirectory name.

    Examples
    --------
    Windows  C:\\Users\\Alice    ->  C/Users/Alice
    Windows  C:\\Work\\Project   ->  C/Work/Project
    Linux    /home/user/docs    ->  home/user/docs
    """
    parts = list(src.resolve().parts)
    # Strip Windows drive root ("C:\\") -> keep only the letter
    if parts and len(parts[0]) == 3 and parts[0][1:] == ":\\":
        parts[0] = parts[0][0]          # "C:\\" -> "C"
    elif parts and parts[0] == "/":
        parts = parts[1:]               # strip leading "/"
    return Path(*parts) if parts else Path(src.name)


# ─── CLI ──────────────────────────────────────────────────────────────────────

@click.group()
def cli() -> None:
    """Vault-Backup — AES-256-GCM + ChaCha20-Poly1305 cascade backup tool."""


@cli.command()
@click.argument("sources", nargs=-1, required=True,
                type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--dest", "-d", required=True, type=click.Path(path_type=Path),
              help="Backup destination directory.")
@click.option("--workers", "-w", default=4, show_default=True,
              help="Parallel worker threads.")
@click.option("--password", "-p", default=None,
              help="Password (omit to be prompted securely).")
def encrypt(sources: tuple[Path, ...], dest: Path,
            workers: int, password: str | None) -> None:
    """
    Encrypt one or more SOURCE directories into DEST.

    Each source is mirrored as DEST/<drive>/<path>/ so multiple
    directories can coexist in the same backup without collision.
    A .vault_session file is written to DEST — keep it with the backup.
    Original files are never modified.

    \b
    Examples
    --------
    Single directory:
      python main.py encrypt --dest E:\\Backup\\enc  C:\\Users\\Alice

    Multiple directories in one pass:
      python main.py encrypt --dest E:\\Backup\\enc  C:\\Users\\Alice  C:\\Work  C:\\ProgramData\\App
    """
    if password is None:
        password = _get_password(confirm=True)

    click.echo("Deriving master key (Argon2id, ~1-2 s) …")
    master = create_session(password, dest)
    click.echo(f"Destination : {dest}")
    click.echo(f"Workers     : {workers}")
    click.echo()

    total_ok = total_err = 0
    for src in sources:
        sub_dst = dest / _src_to_subdir(src)
        click.echo(f"  [{sources.index(src)+1}/{len(sources)}] {src}  →  {sub_dst}")
        ok, err = encrypt_directory(src, sub_dst, master, workers, _error_cb)
        click.echo(f"        Encrypted: {ok}   Errors: {err}\n")
        total_ok  += ok
        total_err += err

    click.echo(f"All done.  Total encrypted: {total_ok}   Total errors: {total_err}")
    if total_err:
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
