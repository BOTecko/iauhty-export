from __future__ import annotations

import datetime as dt
import hashlib
import os
import plistlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from synthetic import PASSWORD, BackupBuilder

from iauhty_export.backup import (
    EncryptedBackup,
    discover_backups,
    read_backup_info,
    require_usable,
    select_backup,
)
from iauhty_export.errors import (
    BackupIncompleteError,
    BackupNotEncryptedError,
    BackupNotFoundError,
    DecryptionError,
    IncompatibleFormatError,
    WrongPasswordError,
)


class BackupTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def build(self, **kwargs: object) -> BackupBuilder:
        builder = BackupBuilder(self.root, **kwargs)  # type: ignore[arg-type]
        builder.add_file("HomeDomain", "Library/Preferences/com.example.plist", b"hello world" * 10)
        builder.add_file("HomeDomain", "empty.txt", b"")
        builder.add_file("HomeDomain", "aligned.bin", bytes(32), protection_class=1)
        builder.build()
        return builder


class DiscoveryTests(BackupTestCase):
    def test_discovers_and_sorts_newest_first(self) -> None:
        self.build(identifier="old", date=dt.datetime(2025, 1, 1))
        self.build(identifier="new", date=dt.datetime(2026, 6, 1))
        (self.root / "not-a-backup").mkdir()
        backups = discover_backups(self.root)
        self.assertEqual([b.identifier for b in backups], ["new", "old"])
        self.assertTrue(all(b.is_usable for b in backups))

    def test_selects_most_recent_usable(self) -> None:
        self.build(identifier="usable", date=dt.datetime(2025, 1, 1))
        self.build(identifier="unfinished", date=dt.datetime(2026, 1, 1), snapshot_state="uploading")
        self.assertEqual(select_backup(None, self.root).identifier, "usable")

    def test_no_usable_backup(self) -> None:
        self.build(identifier="plain", encrypted=False)
        with self.assertRaises(BackupNotFoundError):
            select_backup(None, self.root)

    def test_missing_root(self) -> None:
        with self.assertRaises(BackupNotFoundError):
            discover_backups(self.root / "missing")

    def test_explicit_missing_directory(self) -> None:
        with self.assertRaises(BackupNotFoundError):
            select_backup(self.root / "nope", self.root)


class MetadataTests(BackupTestCase):
    def test_valid_encrypted_backup_metadata(self) -> None:
        info = read_backup_info(self.build().path)
        self.assertTrue(info.is_usable)
        self.assertEqual(info.device_name, "Synthetic iPhone")
        self.assertEqual(info.ios_version, "18.1")
        self.assertEqual(info.backup_date, dt.datetime(2026, 11, 1, 12, tzinfo=dt.timezone.utc))
        require_usable(info)

    def test_incomplete_backup(self) -> None:
        path = self.build().path
        (path / "Manifest.db").unlink()
        info = read_backup_info(path)
        self.assertFalse(info.is_usable)
        self.assertIn("Manifest.db is missing", info.problems)
        with self.assertRaises(BackupIncompleteError):
            require_usable(info)

    def test_unfinished_snapshot(self) -> None:
        info = read_backup_info(self.build(snapshot_state="uploading").path)
        self.assertTrue(any("did not finish" in p for p in info.problems))

    def test_missing_metadata_files(self) -> None:
        path = self.build().path
        (path / "Info.plist").unlink()
        (path / "Status.plist").write_bytes(b"garbage")
        info = read_backup_info(path)
        self.assertIn("Info.plist is missing", info.problems)
        self.assertTrue(any("Status.plist" in p for p in info.problems))

    def test_unencrypted_backup_is_rejected(self) -> None:
        info = read_backup_info(self.build(encrypted=False).path)
        self.assertIs(info.is_encrypted, False)
        with self.assertRaises(BackupNotEncryptedError):
            require_usable(info)

    def test_encrypted_without_keybag(self) -> None:
        path = self.build().path
        manifest = plistlib.loads((path / "Manifest.plist").read_bytes())
        del manifest["BackupKeyBag"]
        (path / "Manifest.plist").write_bytes(plistlib.dumps(manifest))
        self.assertIn("Manifest.plist has no BackupKeyBag", read_backup_info(path).problems)


class EncryptedAccessTests(BackupTestCase):
    def test_reads_and_decrypts_files(self) -> None:
        info = read_backup_info(self.build().path)
        with EncryptedBackup.open(info, PASSWORD) as backup:
            record = backup.find_file("HomeDomain", "Library/Preferences/com.example.plist")
            self.assertIsNotNone(record)
            assert record is not None
            self.assertEqual(record.file_id, hashlib.sha1(
                b"HomeDomain-Library/Preferences/com.example.plist").hexdigest())
            self.assertEqual(backup.read_file(record), b"hello world" * 10)
            empty = backup.find_file("HomeDomain", "empty.txt")
            aligned = backup.find_file("HomeDomain", "aligned.bin")
            assert empty is not None and aligned is not None
            self.assertEqual(backup.read_file(empty), b"")
            self.assertEqual(backup.read_file(aligned), bytes(32))
            self.assertIsNone(backup.find_file("HomeDomain", "does/not/exist"))
            self.assertEqual(backup.count_domain_files("HomeDomain"), 4)

    def test_wal_and_legacy_manifest_db(self) -> None:
        """Regression: real Manifest.db files are in WAL mode without -shm/-wal."""
        for wal in (True, False):
            with self.subTest(wal=wal):
                info = read_backup_info(self.build(identifier=f"wal-{wal}", wal_manifest=wal).path)
                with EncryptedBackup.open(info, PASSWORD) as backup:
                    self.assertEqual(backup.count_domain_files("HomeDomain"), 4)

    def test_wal_header_is_patched_only_on_private_copy(self) -> None:
        from iauhty_export.backup import _rollback_journal_mode
        image = b"SQLite format 3\x00" + b"\x10\x00\x02\x02" + bytes(80)
        patched = _rollback_journal_mode(image)
        self.assertEqual(patched[18:20], b"\x01\x01")
        self.assertEqual(patched[:18] + patched[20:], image[:18] + image[20:])
        legacy = image[:18] + b"\x01\x01" + image[20:]
        self.assertEqual(_rollback_journal_mode(legacy), legacy)

    def test_directory_record_is_not_readable(self) -> None:
        info = read_backup_info(self.build().path)
        with EncryptedBackup.open(info, PASSWORD) as backup:
            record = backup.find_file("HomeDomain", "Library")
            assert record is not None
            with self.assertRaises(IncompatibleFormatError):
                backup.read_file(record)

    def test_wrong_password(self) -> None:
        info = read_backup_info(self.build().path)
        with self.assertRaises(WrongPasswordError):
            EncryptedBackup.open(info, "nope")

    def test_corrupted_manifest_db(self) -> None:
        path = self.build().path
        data = bytearray((path / "Manifest.db").read_bytes())
        data[:16] = bytes(16)
        (path / "Manifest.db").write_bytes(bytes(data))
        with self.assertRaises(DecryptionError):
            EncryptedBackup.open(read_backup_info(path), PASSWORD)

    def test_manifest_db_with_wrong_schema(self) -> None:
        from iauhty_export.crypto import aes_cbc_encrypt, pkcs7_pad
        from synthetic import _deterministic_bytes
        path = self.build().path
        db_file = self.root / "other.db"
        connection = sqlite3.connect(db_file)
        connection.execute("CREATE TABLE Unrelated (x)")
        connection.commit()
        connection.close()
        key = _deterministic_bytes("manifest-db-key", 32)
        (path / "Manifest.db").write_bytes(aes_cbc_encrypt(key, pkcs7_pad(db_file.read_bytes())))
        with self.assertRaises(IncompatibleFormatError):
            EncryptedBackup.open(read_backup_info(path), PASSWORD)

    def test_missing_physical_file(self) -> None:
        builder = self.build()
        file_id = hashlib.sha1(b"HomeDomain-Library/Preferences/com.example.plist").hexdigest()
        (builder.path / file_id[:2] / file_id).unlink()
        with EncryptedBackup.open(read_backup_info(builder.path), PASSWORD) as backup:
            record = backup.find_file("HomeDomain", "Library/Preferences/com.example.plist")
            assert record is not None
            with self.assertRaises(BackupIncompleteError):
                backup.read_file(record)

    def test_rejects_malformed_file_id(self) -> None:
        import dataclasses
        with EncryptedBackup.open(read_backup_info(self.build().path), PASSWORD) as backup:
            record = backup.find_file("HomeDomain", "Library/Preferences/com.example.plist")
            assert record is not None
            for bad_id in ("../../etc/passwd", "ZZ" * 20, "ab"):
                with self.subTest(bad_id=bad_id), self.assertRaises(IncompatibleFormatError):
                    backup.read_file(dataclasses.replace(record, file_id=bad_id))

    def test_rejects_symlink_escape(self) -> None:
        builder = self.build()
        file_id = hashlib.sha1(b"HomeDomain-Library/Preferences/com.example.plist").hexdigest()
        target = builder.path / file_id[:2] / file_id
        outside = self.root / "outside.bin"
        outside.write_bytes(target.read_bytes())
        target.unlink()
        os.symlink(outside, target)
        with EncryptedBackup.open(read_backup_info(builder.path), PASSWORD) as backup:
            record = backup.find_file("HomeDomain", "Library/Preferences/com.example.plist")
            assert record is not None
            with self.assertRaises(IncompatibleFormatError):
                backup.read_file(record)

    def test_private_temp_file_fallback(self) -> None:
        """Exercise the pre-3.11 path (no Connection.deserialize) on any Python."""
        from unittest import mock

        from iauhty_export import backup as backup_module

        real_connect = sqlite3.connect

        class NoDeserialize:
            def __init__(self, connection: sqlite3.Connection) -> None:
                self._connection = connection

            def close(self) -> None:
                self._connection.close()

        def fake_connect(database: str, *args: object, **kwargs: object):
            connection = real_connect(database, *args, **kwargs)
            return NoDeserialize(connection) if database == ":memory:" else connection

        source = self.root / "src.db"
        connection = real_connect(source)
        connection.execute("CREATE TABLE t (x)")
        connection.commit()
        connection.close()
        with mock.patch.object(backup_module.sqlite3, "connect", side_effect=fake_connect):
            db, temp_dir = backup_module._open_sqlite(source.read_bytes())
        self.assertIsNotNone(temp_dir)
        assert temp_dir is not None
        self.assertEqual(os.stat(temp_dir).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(os.path.join(temp_dir, "Manifest.db")).st_mode & 0o777, 0o600)
        self.assertEqual(db.execute("SELECT name FROM sqlite_master").fetchone()[0], "t")
        with self.assertRaises(sqlite3.OperationalError):
            db.execute("INSERT INTO t VALUES (1)")  # opened read-only
        backup_module._close_sqlite(db, temp_dir)
        self.assertFalse(os.path.exists(temp_dir))

    def test_temporary_files_are_cleaned_up(self) -> None:
        info = read_backup_info(self.build().path)
        backup = EncryptedBackup.open(info, PASSWORD)
        temp_dir = backup._temp_dir
        backup.close()
        if temp_dir is not None:  # only used on Python < 3.11
            self.assertFalse(os.path.exists(temp_dir))


if __name__ == "__main__":
    unittest.main()
