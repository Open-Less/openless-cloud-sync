#!/usr/bin/env python3
"""SQLite online backup with a strict seven-day retention ceiling. No decryption."""
import argparse
import datetime
import os
from pathlib import Path
import sqlite3
import time

# Hourly purge leaves a one-hour margin below the advertised seven-day ceiling.
PURGE_AFTER_SECONDS = 7 * 86400 - 3600


def prune(directory: Path, now: float) -> int:
    removed = 0
    for path in directory.glob("sync-*.sqlite3"):
        if not path.is_symlink() and path.is_file() and path.stat().st_mtime <= now - PURGE_AFTER_SECONDS:
            path.unlink()
            removed += 1
    return removed


def backup(source: Path, directory: Path) -> Path:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    target = directory / f"sync-{stamp}.sqlite3"
    temporary = directory / f".sync-{stamp}.tmp"
    # SQLite's backup API takes a consistent image while writes continue.
    try:
        with sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True, timeout=60) as src:
            with sqlite3.connect(temporary, timeout=60) as dst:
                src.backup(dst)
                if dst.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                    raise RuntimeError("backup integrity check failed")
                dst.execute("PRAGMA secure_delete=ON")
                dst.execute("DELETE FROM sessions")
                dst.execute("DELETE FROM rate_events")
        os.chmod(temporary, 0o600)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        temporary.replace(target)
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return target
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=Path("/var/lib/openless-cloud-sync/sync.db"))
    parser.add_argument("--directory", type=Path, default=Path("/var/backups/openless-cloud-sync"))
    parser.add_argument("--prune-only", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    args.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    removed = prune(args.directory, time.time())
    if not args.prune_only:
        backup(args.database, args.directory)
    print(f"backup maintenance complete; expired files removed: {removed}")


if __name__ == "__main__":
    main()
