"""Builder for synthetic, fully encrypted iOS backups used by the tests.

The generated backups follow the real on-disk layout (keybag TLV, wrapped
ManifestKey, encrypted Manifest.db, NSKeyedArchiver MBFile blobs, encrypted
files, keychain-backup.plist with version-3 GCM items) so the production
parsing and decryption code is exercised end to end, not mocked.

All data is fictitious. The ciphers used here are validated independently
against NIST/RFC vectors in test_crypto.py.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import plistlib
import sqlite3
import struct
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from iauhty_export.authy import AUTHY_DOMAIN, AUTHY_PREFERENCES
from iauhty_export.crypto import aes_cbc_encrypt, aes_gcm_encrypt, aes_key_wrap, pbkdf2, pkcs7_pad
from iauhty_export.keychain import KEYCHAIN_DOMAIN, KEYCHAIN_FILE

PASSWORD = "correct horse battery staple"
DEVICE_BOUND_CLASSES = (5, 9, 10, 11, 19)  # as observed on iOS 27
SALT = bytes(range(20))
DP_SALT = bytes(range(20, 40))
ITERATIONS = 10
DP_ITERATIONS = 100

# Deterministic fictitious secrets (RFC 4648 base32).
SECRET_A = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
SECRET_B = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
SECRET_C = "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U"


def _deterministic_bytes(label: str, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(f"{label}:{counter}".encode()).digest()
        counter += 1
    return out[:length]


# --------------------------------------------------------------------------
# Encoders
# --------------------------------------------------------------------------

def tlv(tag: str, value: bytes) -> bytes:
    return tag.encode("ascii") + struct.pack(">I", len(value)) + value


def u32(value: int) -> bytes:
    return struct.pack(">I", value)


def der(tag: int, value: bytes) -> bytes:
    length = len(value)
    if length < 0x80:
        header = bytes([length])
    else:
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        header = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + header + value


def der_value(value: object) -> bytes:
    if isinstance(value, bool):
        return der(0x01, b"\xff" if value else b"\x00")
    if isinstance(value, int):
        return der(0x02, value.to_bytes((value.bit_length() + 8) // 8 or 1, "big", signed=True))
    if isinstance(value, str):
        return der(0x0C, value.encode("utf-8"))
    if isinstance(value, bytes):
        return der(0x04, value)
    raise TypeError(type(value))


def der_attributes(attributes: dict[str, object]) -> bytes:
    body = b"".join(der(0x30, der_value(k) + der_value(v)) for k, v in attributes.items())
    return der(0x31, body)


# --------------------------------------------------------------------------
# Keybag
# --------------------------------------------------------------------------

@dataclass
class SyntheticKeybag:
    password: str = PASSWORD
    class_keys: dict[int, bytes] = field(default_factory=dict)
    use_dp_round: bool = True

    def __post_init__(self) -> None:
        for class_id in (*range(1, 12), 17, 18, 19):
            self.class_keys[class_id] = _deterministic_bytes(f"class-{class_id}", 32)

    def passcode_key(self) -> bytes:
        secret = self.password.encode("utf-8")
        if self.use_dp_round:
            secret = pbkdf2("sha256", secret, DP_SALT, DP_ITERATIONS, 32)
        return pbkdf2("sha1", secret, SALT, ITERATIONS, 32)

    def encode(self) -> bytes:
        passcode_key = self.passcode_key()
        out = tlv("VERS", u32(4)) + tlv("TYPE", u32(1)) + tlv("UUID", bytes(16))
        out += tlv("HMCK", bytes(40)) + tlv("WRAP", u32(0))
        out += tlv("SALT", SALT) + tlv("ITER", u32(ITERATIONS))
        if self.use_dp_round:
            out += tlv("DPWT", u32(1)) + tlv("DPIC", u32(DP_ITERATIONS)) + tlv("DPSL", DP_SALT)
        for class_id, key in self.class_keys.items():
            if class_id in DEVICE_BOUND_CLASSES:
                wrap, wrapped = 3, _deterministic_bytes(f"devicebound-{class_id}", 40)
            else:
                wrap, wrapped = 2, aes_key_wrap(passcode_key, key)
            out += tlv("UUID", _deterministic_bytes(f"uuid-{class_id}", 16))
            out += tlv("CLAS", u32(class_id)) + tlv("WRAP", u32(wrap))
            out += tlv("KTYP", u32(0)) + tlv("WPKY", wrapped)
        return out

    def wrap_for_class(self, class_id: int, key: bytes) -> bytes:
        return aes_key_wrap(self.class_keys[class_id], key)


# --------------------------------------------------------------------------
# Keychain
# --------------------------------------------------------------------------

def keychain_item(keybag: SyntheticKeybag, attributes: dict[str, object], protection_class: int = 7,
                  version: int = 3, iv: bytes = b"", label: str = "item") -> bytes:
    item_key = _deterministic_bytes(f"itemkey-{label}", 32)
    if protection_class in DEVICE_BOUND_CLASSES:
        wrapped = _deterministic_bytes(f"wrapped-{label}", 40)
    else:
        wrapped = keybag.wrap_for_class(protection_class, item_key)
    if version == 3:
        payload = der_attributes(attributes)
    else:
        payload = plistlib.dumps(attributes, fmt=plistlib.FMT_BINARY)
    ciphertext, tag = aes_gcm_encrypt(item_key, iv, payload)
    return struct.pack("<III", version, protection_class, len(wrapped)) + wrapped + ciphertext + tag


def keychain_plist(blobs: list[bytes]) -> bytes:
    genp = [{"v_Data": blob, "v_PersistentRef": _deterministic_bytes(f"ref-{i}", 12)} for i, blob in enumerate(blobs)]
    return plistlib.dumps({"genp": genp, "inet": [], "cert": [], "keys": []}, fmt=plistlib.FMT_BINARY)


def authy_item(keybag: SyntheticKeybag, account_id: str, secret: str, protection_class: int = 7) -> bytes:
    return keychain_item(keybag, {
        "svce": f"Google{account_id}App",
        "acct": f"account-{account_id}",
        "agrp": "9XYZ.com.authy",
        "pdmn": "ck",
        "v_Data": secret.encode("utf-8"),
    }, protection_class=protection_class, label=f"authy-{account_id}-{protection_class}")


def unrelated_item(keybag: SyntheticKeybag, label: str) -> bytes:
    return keychain_item(keybag, {
        "svce": f"com.example.{label}", "acct": "user", "agrp": "9XYZ.com.example",
        "v_Data": b"not an authy secret",
    }, label=label)


# --------------------------------------------------------------------------
# Backup
# --------------------------------------------------------------------------

def mbfile_archive(protection_class: int, size: int, encryption_key: bytes, relative_path: str) -> bytes:
    uid = plistlib.UID
    archive = {
        "$version": 100000,
        "$archiver": "NSKeyedArchiver",
        "$top": {"root": uid(1)},
        "$objects": [
            "$null",
            {"$class": uid(5), "ProtectionClass": protection_class, "Size": size,
             "EncryptionKey": uid(2), "RelativePath": uid(3), "Flags": 0},
            {"$class": uid(4), "NS.data": encryption_key},
            relative_path,
            {"$classname": "NSMutableData", "$classes": ["NSMutableData", "NSData", "NSObject"]},
            {"$classname": "MBFile", "$classes": ["MBFile", "NSObject"]},
        ],
    }
    return plistlib.dumps(archive, fmt=plistlib.FMT_BINARY)


@dataclass
class BackupBuilder:
    root: Path
    identifier: str = "00008110-000A1B2C3D4E5F60"
    keybag: SyntheticKeybag = field(default_factory=SyntheticKeybag)
    encrypted: bool = True
    snapshot_state: str = "finished"
    date: dt.datetime = dt.datetime(2026, 11, 1, 12, 0, 0)
    files: list[tuple[str, str, bytes, int]] = field(default_factory=list)
    # Real backups store Manifest.db in WAL mode, checkpointed, without -wal/-shm.
    wal_manifest: bool = True

    @property
    def path(self) -> Path:
        return self.root / self.identifier

    def add_file(self, domain: str, relative_path: str, content: bytes, protection_class: int = 3) -> None:
        self.files.append((domain, relative_path, content, protection_class))

    def add_authy(self, preferences: dict[str, object], keychain_blobs: list[bytes]) -> None:
        self.add_file(AUTHY_DOMAIN, AUTHY_PREFERENCES, plistlib.dumps(preferences, fmt=plistlib.FMT_BINARY))
        self.add_file(KEYCHAIN_DOMAIN, KEYCHAIN_FILE, keychain_plist(keychain_blobs), protection_class=4)

    def build(self) -> Path:
        self.path.mkdir(parents=True, exist_ok=True)
        manifest_db_key = _deterministic_bytes("manifest-db-key", 32)
        db_bytes = self._manifest_db()
        if self.encrypted:
            db_bytes = aes_cbc_encrypt(manifest_db_key, pkcs7_pad(db_bytes))
        (self.path / "Manifest.db").write_bytes(db_bytes)

        manifest: dict[str, object] = {
            "IsEncrypted": self.encrypted,
            "Version": "10.0",
            "Date": self.date,
            "Lockdown": {"DeviceName": "Synthetic iPhone", "ProductVersion": "18.1",
                         "ProductType": "iPhone15,2", "UniqueDeviceID": self.identifier},
        }
        if self.encrypted:
            manifest["BackupKeyBag"] = self.keybag.encode()
            manifest["ManifestKey"] = struct.pack("<I", 4) + self.keybag.wrap_for_class(4, manifest_db_key)
        self._write_plist("Manifest.plist", manifest)
        self._write_plist("Info.plist", {"Device Name": "Synthetic iPhone", "Product Type": "iPhone15,2",
                                         "Product Version": "18.1", "Last Backup Date": self.date})
        self._write_plist("Status.plist", {"SnapshotState": self.snapshot_state, "Date": self.date,
                                           "IsFullBackup": False, "Version": "3.3", "BackupState": "new"})
        return self.path

    def _write_plist(self, name: str, value: dict[str, object]) -> None:
        (self.path / name).write_bytes(plistlib.dumps(value, fmt=plistlib.FMT_BINARY))

    def _manifest_db(self) -> bytes:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "Manifest.db")
            connection = sqlite3.connect(db_path)
            if self.wal_manifest:
                connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, "
                               "relativePath TEXT, flags INTEGER, file BLOB)")
            connection.execute("CREATE TABLE Properties (key TEXT PRIMARY KEY, value BLOB)")
            connection.execute("INSERT INTO Files VALUES (?, ?, ?, ?, ?)",
                               (hashlib.sha1(b"HomeDomain-Library").hexdigest(), "HomeDomain", "Library", 2, None))
            for domain, relative_path, content, protection_class in self.files:
                file_id = hashlib.sha1(f"{domain}-{relative_path}".encode()).hexdigest()
                connection.execute("INSERT INTO Files VALUES (?, ?, ?, ?, ?)",
                                   (file_id, domain, relative_path, 1,
                                    self._store_file(file_id, relative_path, content, protection_class)))
            connection.commit()
            if self.wal_manifest:
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            connection.close()
            data = Path(db_path).read_bytes()
            assert (data[18], data[19]) == ((2, 2) if self.wal_manifest else (1, 1))
            return data

    def _store_file(self, file_id: str, relative_path: str, content: bytes, protection_class: int) -> bytes:
        file_key = _deterministic_bytes(f"filekey-{file_id}", 32)
        target = self.path / file_id[:2] / file_id
        target.parent.mkdir(parents=True, exist_ok=True)
        if self.encrypted:
            target.write_bytes(aes_cbc_encrypt(file_key, pkcs7_pad(content)))
            wrapped = struct.pack("<I", protection_class) + self.keybag.wrap_for_class(protection_class, file_key)
        else:
            target.write_bytes(content)
            wrapped = b""
        return mbfile_archive(protection_class, len(content), wrapped, relative_path)


def standard_authy_backup(root: Path, **kwargs: object) -> BackupBuilder:
    """A backup with three recoverable accounts plus several failure cases.

    Accounts:
      1001  recovered (SHA1/6/30 assumed defaults except digits)
      1002  recovered, 8 digits, no issuer
      1003  duplicate of 1001's secret
      1004  secret missing from the keychain
      1005  invalid (non-base32) secret
      1006  hex seed -> incompatible (Authy-native style)
      1007  secret stored in a device-bound keychain class (-> not found)
      1008  recovered, explicit SHA256 / 60 s
    Plus an unrelated keychain item, an orphan Authy secret (9999) and a
    non-numeric preference key.
    """
    builder = BackupBuilder(root, **kwargs)  # type: ignore[arg-type]
    kb = builder.keybag
    preferences = {
        "1001": {"name": "alice@example.com", "original_issuer": "Example", "digits": 6},
        "1002": {"name": "bob", "digits": 8},
        "1003": {"name": "alice copy", "original_issuer": "Example", "digits": 6},
        "1004": {"name": "missing", "original_issuer": "Nowhere", "digits": 6},
        "1005": {"name": "broken", "original_issuer": "Broken", "digits": 6},
        "1006": {"name": "native", "original_issuer": "AuthyNative", "digits": 7},
        "1007": {"name": "devicebound", "original_issuer": "Locked", "digits": 6},
        "1008": {"name": "carol", "original_issuer": "Strong", "digits": 6,
                 "algorithm": "SHA256", "period": 60},
        "AuthyLastSync": "2026-10-31",
    }
    blobs = [
        authy_item(kb, "1001", SECRET_A),
        authy_item(kb, "1002", SECRET_B.lower()),
        authy_item(kb, "1003", SECRET_A),
        authy_item(kb, "1005", "this is not base32!"),
        authy_item(kb, "1006", "0123456789abcdef0123456789abcdef"),
        authy_item(kb, "1007", SECRET_C, protection_class=10),
        authy_item(kb, "1008", SECRET_C),
        authy_item(kb, "9999", SECRET_B),
        unrelated_item(kb, "mail"),
    ]
    builder.add_authy(preferences, blobs)
    return builder
