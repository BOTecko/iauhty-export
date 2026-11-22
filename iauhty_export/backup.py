"""Discovery, validation and read-only access to encrypted iOS backups.

Backup layout (iOS 10+, as written by Finder/iTunes):

* ``Info.plist``     device metadata written by the host computer.
* ``Status.plist``   snapshot state; ``SnapshotState == "finished"`` when complete.
* ``Manifest.plist`` ``IsEncrypted``, ``BackupKeyBag`` and ``ManifestKey``
  (4-byte little-endian protection class + RFC 3394 wrapped AES-256 key).
* ``Manifest.db``    SQLite catalogue, AES-256-CBC encrypted (zero IV) with
  the ManifestKey when the backup is encrypted. Table ``Files`` maps
  ``fileID = SHA1(domain + "-" + relativePath)`` to an NSKeyedArchiver
  ``MBFile`` blob with ``ProtectionClass``, ``Size`` and ``EncryptionKey``
  (4-byte class + wrapped per-file key).
* ``<fileID[:2]>/<fileID>`` the file contents, AES-256-CBC (zero IV, PKCS#7).

Nothing in the backup directory is ever opened for writing.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import shutil
import sqlite3
import struct
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .crypto import AES_BLOCK_SIZE, aes_cbc_decrypt, pkcs7_unpad
from .errors import (
    BackupIncompleteError,
    BackupNotEncryptedError,
    BackupNotFoundError,
    CryptoError,
    DecryptionError,
    IncompatibleFormatError,
)
from .keybag import Keybag, UnlockedKeybag
from .models import BackupInfo
from .plistutil import is_keyed_archive, load_plist_dict, unarchive

DEFAULT_BACKUP_ROOT = Path.home() / "Library" / "Application Support" / "MobileSync" / "Backup"

REQUIRED_FILES = ("Manifest.plist", "Manifest.db", "Info.plist", "Status.plist")
FLAG_REGULAR_FILE = 1
SQLITE_MAGIC = b"SQLite format 3\x00"
SQLITE_MIN_PAGE = 512

_FILE_ID_RE = re.compile(r"^[0-9a-f]{40}$")
_MAX_PLIST_SIZE = 64 << 20
_MAX_MANIFEST_DB_SIZE = 4 << 30
_MAX_FILE_SIZE = 512 << 20

FULL_DISK_ACCESS_HINT = (
    "macOS restricts access to iOS backups. Grant Full Disk Access to your "
    "terminal app in System Settings > Privacy & Security > Full Disk Access, "
    "or pass --backup with a copy of the backup directory."
)


# --------------------------------------------------------------------------
# Low-level read-only file access
# --------------------------------------------------------------------------

def _read_limited(path: Path, limit: int) -> bytes:
    """Read a regular file in binary read-only mode with a size cap."""
    try:
        with open(path, "rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            if size > limit:
                raise IncompatibleFormatError(f"{path.name} is implausibly large ({size} bytes)")
            return handle.read(limit)
    except FileNotFoundError as exc:
        raise BackupIncompleteError(f"{path.name} is missing") from exc
    except PermissionError as exc:
        raise BackupNotFoundError(f"permission denied reading {path.name}. {FULL_DISK_ACCESS_HINT}") from exc
    except IsADirectoryError as exc:
        raise BackupIncompleteError(f"{path.name} is not a regular file") from exc


def _read_plist(backup_dir: Path, name: str) -> dict[str, Any]:
    return load_plist_dict(_read_limited(backup_dir / name, _MAX_PLIST_SIZE), name)


def _utc(value: Any) -> dt.datetime | None:
    if not isinstance(value, dt.datetime):
        return None
    # plistlib yields naive datetimes that are in UTC.
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


# --------------------------------------------------------------------------
# Discovery and metadata (no password required)
# --------------------------------------------------------------------------

def read_backup_info(path: Path) -> BackupInfo:
    """Collect metadata and completeness problems for one backup directory."""
    path = Path(path)
    if not path.is_dir():
        raise BackupNotFoundError(f"backup directory not found: {path}")
    problems: list[str] = []
    for name in REQUIRED_FILES:
        if not (path / name).is_file():
            problems.append(f"{name} is missing")

    manifest = _try_plist(path, "Manifest.plist", problems)
    info = _try_plist(path, "Info.plist", problems)
    status = _try_plist(path, "Status.plist", problems)

    lockdown = manifest.get("Lockdown") if isinstance(manifest.get("Lockdown"), dict) else {}
    is_encrypted = manifest.get("IsEncrypted") if isinstance(manifest.get("IsEncrypted"), bool) else None
    snapshot_state = _str_or_none(status.get("SnapshotState"))
    if status and snapshot_state != "finished":
        problems.append(f"backup did not finish (SnapshotState={snapshot_state!r})")
    if is_encrypted:
        if not isinstance(manifest.get("BackupKeyBag"), bytes):
            problems.append("Manifest.plist has no BackupKeyBag")
        if not isinstance(manifest.get("ManifestKey"), bytes):
            problems.append("Manifest.plist has no ManifestKey")
    if (path / "Manifest.mbdb").is_file() and not (path / "Manifest.db").is_file():
        problems.append("legacy pre-iOS 10 backup format (Manifest.mbdb) is not supported")

    return BackupInfo(
        path=path,
        identifier=path.name,
        device_name=_str_or_none(info.get("Device Name")) or _str_or_none(lockdown.get("DeviceName")),
        product_type=_str_or_none(info.get("Product Type")) or _str_or_none(lockdown.get("ProductType")),
        ios_version=_str_or_none(info.get("Product Version")) or _str_or_none(lockdown.get("ProductVersion")),
        backup_date=_utc(status.get("Date")) or _utc(manifest.get("Date")) or _utc(info.get("Last Backup Date")),
        is_encrypted=is_encrypted,
        snapshot_state=snapshot_state,
        problems=tuple(problems),
    )


def _try_plist(path: Path, name: str, problems: list[str]) -> dict[str, Any]:
    if not (path / name).is_file():
        return {}
    try:
        return _read_plist(path, name)
    except IncompatibleFormatError as exc:
        problems.append(str(exc))
    except BackupNotFoundError:
        raise
    except BackupIncompleteError as exc:
        problems.append(str(exc))
    return {}


def discover_backups(root: Path = DEFAULT_BACKUP_ROOT) -> list[BackupInfo]:
    """Return backups under ``root`` sorted newest first."""
    root = Path(root)
    if not root.exists():
        raise BackupNotFoundError(f"backup folder not found: {root}")
    try:
        children = sorted(p for p in root.iterdir() if p.is_dir())
    except PermissionError as exc:
        raise BackupNotFoundError(f"permission denied listing {root}. {FULL_DISK_ACCESS_HINT}") from exc
    backups = [read_backup_info(child) for child in children if (child / "Manifest.plist").exists()]
    epoch = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    return sorted(backups, key=lambda b: b.backup_date or epoch, reverse=True)


def select_backup(explicit: Path | None, root: Path = DEFAULT_BACKUP_ROOT) -> BackupInfo:
    """Pick the explicit backup, or the most recent usable one under ``root``."""
    if explicit is not None:
        return read_backup_info(Path(explicit).expanduser())
    backups = discover_backups(root)
    if not backups:
        raise BackupNotFoundError(f"no iOS backups found in {root}")
    for backup in backups:
        if backup.is_usable:
            return backup
    raise BackupNotFoundError(
        "no complete, encrypted backup found; run 'list' to see why each backup was rejected"
    )


def require_usable(info: BackupInfo) -> None:
    if info.problems:
        raise BackupIncompleteError("backup is incomplete: " + "; ".join(info.problems))
    if info.is_encrypted is not True:
        raise BackupNotEncryptedError(
            "backup is not encrypted; unencrypted backups do not include keychain "
            "secrets. Enable 'Encrypt local backup' in Finder and back up again."
        )


# --------------------------------------------------------------------------
# Encrypted backup access
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ManifestRecord:
    file_id: str
    domain: str
    relative_path: str
    flags: int
    protection_class: int | None
    wrapped_key: bytes | None = field(repr=False)
    size: int | None


class EncryptedBackup:
    """Read-only, decrypted view of an encrypted backup.

    Use as a context manager so the decrypted Manifest database (and any
    private temporary file needed on older Pythons) is always cleaned up.
    """

    def __init__(self, info: BackupInfo, keybag: UnlockedKeybag, connection: sqlite3.Connection,
                 temp_dir: str | None) -> None:
        self.info = info
        self._keybag = keybag
        self._db = connection
        self._temp_dir = temp_dir

    @classmethod
    def open(cls, info: BackupInfo, password: str) -> "EncryptedBackup":
        require_usable(info)
        manifest = _read_plist(info.path, "Manifest.plist")
        keybag = Keybag.parse(manifest["BackupKeyBag"]).unlock(password)
        manifest_db = _decrypt_manifest_db(info.path, manifest["ManifestKey"], keybag)
        connection, temp_dir = _open_sqlite(manifest_db)
        try:
            _validate_manifest_schema(connection)
        except IncompatibleFormatError:
            _close_sqlite(connection, temp_dir)
            raise
        return cls(info, keybag, connection, temp_dir)

    @property
    def keybag(self) -> UnlockedKeybag:
        return self._keybag

    def close(self) -> None:
        _close_sqlite(self._db, self._temp_dir)
        self._temp_dir = None

    def __enter__(self) -> "EncryptedBackup":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def count_domain_files(self, domain: str) -> int:
        row = self._db.execute("SELECT COUNT(*) FROM Files WHERE domain = ?", (domain,)).fetchone()
        return int(row[0])

    def find_file(self, domain: str, relative_path: str) -> ManifestRecord | None:
        row = self._db.execute(
            "SELECT fileID, domain, relativePath, flags, file FROM Files "
            "WHERE domain = ? AND relativePath = ?",
            (domain, relative_path),
        ).fetchone()
        return None if row is None else _parse_manifest_row(row)

    def read_file(self, record: ManifestRecord) -> bytes:
        """Return the decrypted contents of a regular file in the backup."""
        if record.flags != FLAG_REGULAR_FILE:
            raise IncompatibleFormatError(f"{record.domain}/{record.relative_path} is not a regular file")
        if record.protection_class is None or not record.wrapped_key:
            raise IncompatibleFormatError(f"{record.relative_path} has no encryption key in Manifest.db")
        ciphertext = _read_limited(self._object_path(record.file_id), _MAX_FILE_SIZE)
        if record.size == 0 and not ciphertext:
            return b""
        try:
            file_key = self._keybag.unwrap_key(record.protection_class, record.wrapped_key)
        except CryptoError as exc:
            raise DecryptionError(f"cannot unwrap the key for {record.relative_path}: {exc}") from exc
        plaintext = aes_cbc_decrypt(file_key, ciphertext)
        # Size from MBFile is authoritative; PKCS#7 is the fallback when absent.
        if record.size is not None and 0 <= len(plaintext) - record.size <= AES_BLOCK_SIZE:
            return plaintext[:record.size]
        return pkcs7_unpad(plaintext)

    def _object_path(self, file_id: str) -> Path:
        if not _FILE_ID_RE.match(file_id):
            raise IncompatibleFormatError("Manifest.db contains a malformed fileID")
        base = Path(os.path.realpath(self.info.path))
        for candidate in (base / file_id[:2] / file_id, base / file_id):
            real = Path(os.path.realpath(candidate))
            if os.path.commonpath([str(base), str(real)]) != str(base):
                raise IncompatibleFormatError("backup file path escapes the backup directory")
            if real.is_file():
                return real
        raise BackupIncompleteError(f"backup file {file_id} is missing from the backup directory")


def _decrypt_manifest_db(backup_dir: Path, manifest_key: bytes, keybag: UnlockedKeybag) -> bytes:
    if len(manifest_key) < 4 + 24:
        raise IncompatibleFormatError("ManifestKey is truncated")
    protection_class = struct.unpack("<I", manifest_key[:4])[0]
    try:
        key = keybag.unwrap_key(protection_class, manifest_key[4:])
    except CryptoError as exc:
        raise DecryptionError(f"cannot unwrap the Manifest.db key: {exc}") from exc
    ciphertext = _read_limited(backup_dir / "Manifest.db", _MAX_MANIFEST_DB_SIZE)
    plaintext = aes_cbc_decrypt(key, ciphertext)
    if not plaintext.startswith(SQLITE_MAGIC):
        raise DecryptionError("decrypted Manifest.db is not an SQLite database")
    # SQLite files are a whole number of pages (>= 512 bytes). A remainder
    # therefore means PKCS#7 padding was appended by the encryption layer.
    if len(plaintext) % SQLITE_MIN_PAGE:
        plaintext = pkcs7_unpad(plaintext)
    return plaintext


def _rollback_journal_mode(data: bytes) -> bytes:
    """Return a copy of an SQLite image switched from WAL to rollback-journal mode.

    Real backups store Manifest.db in WAL mode (header bytes 18/19 = 2) but
    ship it without its -wal/-shm side files, i.e. fully checkpointed. SQLite
    cannot open such an image read-only or via ``deserialize`` because it
    wants to create the shared-memory index, failing with "unable to open
    database file". Setting both version bytes to 1 (legacy journal) on our
    private decrypted copy is lossless here and lets it open normally. The
    backup itself is never modified.
    """
    if len(data) > 19 and data[18] == 2 and data[19] == 2:
        return data[:18] + b"\x01\x01" + data[20:]
    return data


def _open_sqlite(data: bytes) -> tuple[sqlite3.Connection, str | None]:
    """Open decrypted SQLite bytes in memory, or in a private temp file as a fallback."""
    data = _rollback_journal_mode(data)
    connection = sqlite3.connect(":memory:")
    if hasattr(connection, "deserialize"):  # Python 3.11+
        try:
            connection.deserialize(data)
            return connection, None
        except sqlite3.DatabaseError as exc:
            connection.close()
            raise IncompatibleFormatError(f"decrypted Manifest.db could not be loaded (SQLite: {exc})") from exc
    connection.close()
    temp_dir = tempfile.mkdtemp(prefix="iauhty-export-")  # created with mode 0700
    try:
        db_path = os.path.join(temp_dir, "Manifest.db")
        fd = os.open(db_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        return sqlite3.connect(Path(db_path).as_uri() + "?mode=ro", uri=True), temp_dir
    except BaseException:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def _close_sqlite(connection: sqlite3.Connection, temp_dir: str | None) -> None:
    connection.close()
    if temp_dir:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _validate_manifest_schema(connection: sqlite3.Connection) -> None:
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(Files)")}
    except sqlite3.DatabaseError as exc:
        raise IncompatibleFormatError(f"Manifest.db is not a readable SQLite database (SQLite: {exc})") from exc
    missing = {"fileID", "domain", "relativePath", "flags", "file"} - columns
    if missing:
        raise IncompatibleFormatError(f"Manifest.db Files table lacks columns: {sorted(missing)}")


def _parse_manifest_row(row: tuple[Any, ...]) -> ManifestRecord:
    file_id, domain, relative_path, flags, blob = row
    if not isinstance(file_id, str) or not isinstance(flags, int):
        raise IncompatibleFormatError("Manifest.db row has unexpected column types")
    protection_class = size = None
    wrapped_key = None
    if isinstance(blob, bytes) and blob:
        archive = load_plist_dict(blob, f"metadata of {relative_path}")
        mbfile = unarchive(archive) if is_keyed_archive(archive) else archive
        if not isinstance(mbfile, dict):
            raise IncompatibleFormatError(f"metadata of {relative_path} is not an MBFile object")
        protection_class = _int_or_none(mbfile.get("ProtectionClass"))
        size = _int_or_none(mbfile.get("Size"))
        encryption_key = mbfile.get("EncryptionKey")
        if isinstance(encryption_key, bytes):
            if len(encryption_key) < 4 + 24:
                raise IncompatibleFormatError(f"EncryptionKey of {relative_path} is truncated")
            # The first 4 bytes repeat the protection class (little-endian).
            wrapped_key = encryption_key[4:]
    return ManifestRecord(file_id, str(domain), str(relative_path), flags, protection_class, wrapped_key, size)


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None
