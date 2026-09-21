#!/usr/bin/python3
"""Consistent local backup of the database and every key needed to restore it."""

import os
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

os.umask(0o077)
root = Path("/var/backups/flagroom")
root.mkdir(mode=0o700, parents=True, exist_ok=True)
destination = root / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
destination.mkdir(mode=0o700)
with sqlite3.connect("file:/opt/flagroom/instance/board.db?mode=ro", uri=True) as source, sqlite3.connect(destination / "board.db") as target:
    source.backup(target)
    assert target.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
for name in ("secret", "source_credentials.key", "pending_source_credentials.enc"):
    path = Path("/opt/flagroom/instance") / name
    if path.exists():
        shutil.copy2(path, destination / name)
shutil.copy2("/opt/flagroom/.env", destination / ".env")
backups = sorted(path for path in root.iterdir() if path.is_dir() and len(path.name) == 16 and path.name.endswith("Z") and (path / "board.db").exists())
for old in backups[:-14]:
    shutil.rmtree(old)
print(f"Backup completed: {destination}")
