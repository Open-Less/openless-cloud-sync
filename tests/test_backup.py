import importlib.util
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location("backup", Path(__file__).resolve().parents[1] / "scripts/backup.py")
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


class BackupTests(unittest.TestCase):
    def test_consistent_backup_excludes_sessions_and_purges_expired_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.db"
            with sqlite3.connect(source) as db:
                db.executescript("CREATE TABLE sessions(token_hash TEXT); CREATE TABLE rate_events(ip TEXT); CREATE TABLE vaults(ciphertext BLOB);")
                db.execute("INSERT INTO sessions VALUES(?)", ("test-token-hash",))
                db.execute("INSERT INTO rate_events VALUES(?)", ("test-ip-hash",))
                db.execute("INSERT INTO vaults VALUES(?)", (b"ciphertext-only",))
            directory = root / "backups"
            target = backup.backup(source, directory)
            with sqlite3.connect(target) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM sessions").fetchone(), (0,))
                self.assertEqual(db.execute("SELECT count(*) FROM rate_events").fetchone(), (0,))
                self.assertEqual(db.execute("SELECT ciphertext FROM vaults").fetchone(), (b"ciphertext-only",))
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            expired = directory / "sync-expired.sqlite3"
            expired.write_bytes(b"expired-ciphertext")
            old = time.time() - 7 * 86400
            os.utime(expired, (old, old))
            unrelated = directory / "unrelated.txt"
            unrelated.write_text("keep")
            self.assertEqual(backup.prune(directory, time.time()), 1)
            self.assertFalse(expired.exists())
            self.assertTrue(target.exists())
            self.assertTrue(unrelated.exists())
            with sqlite3.connect(source) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM sessions").fetchone(), (1,))


if __name__ == "__main__":
    unittest.main()
