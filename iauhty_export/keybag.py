"""Backup keybag parsing and unlocking.

The keybag (``BackupKeyBag`` in Manifest.plist) is a flat TLV list:
4-byte ASCII tag, 4-byte big-endian length, value. Header tags come first;
each subsequent ``UUID`` tag starts a class-key record (CLAS, WRAP, KTYP,
WPKY, ...). Layout per Apple Platform Security ("Keybags for Data
Protection") and the public iphone-dataprotection research.

Key derivation (iOS 10.2+): PBKDF2-HMAC-SHA256(password, DPSL, DPIC) and
then PBKDF2-HMAC-SHA1(that, SALT, ITER), both 32 bytes. Backups without
DPIC/DPSL use only the SHA1 round. Class keys whose WRAP flag is exactly 2
are AES-key-wrapped with that passcode key; WRAP flag 1 means the device UID
key is involved and the class key cannot be recovered off-device.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from .crypto import aes_key_unwrap, pbkdf2
from .errors import (
    CryptoError,
    DecryptionError,
    DeviceBoundKeyError,
    IncompatibleFormatError,
    WrongPasswordError,
)

WRAP_DEVICE = 1
WRAP_PASSCODE = 2
KEY_TYPE_AES = 0

_MAX_KEYBAG_SIZE = 1 << 20
_TLV_HEADER = struct.Struct(">4sI")


@dataclass(frozen=True)
class ClassKey:
    class_id: int
    wrap: int
    key_type: int
    wrapped_key: bytes = field(repr=False)

    @property
    def is_device_bound(self) -> bool:
        return bool(self.wrap & WRAP_DEVICE)


@dataclass(frozen=True)
class Keybag:
    keybag_type: int | None
    salt: bytes = field(repr=False)
    iterations: int
    dp_salt: bytes | None = field(repr=False)
    dp_iterations: int | None
    class_keys: tuple[ClassKey, ...]

    @classmethod
    def parse(cls, data: bytes) -> "Keybag":
        """Parse a keybag blob, rejecting truncated or inconsistent data."""
        header: dict[str, bytes] = {}
        records: list[dict[str, bytes]] = []
        seen_keybag_uuid = False
        for tag, value in iter_tlv(data):
            if tag == "UUID":
                if not seen_keybag_uuid:
                    seen_keybag_uuid = True
                    continue
                records.append({})
                continue
            target = records[-1] if records else header
            target.setdefault(tag, value)

        salt = header.get("SALT")
        iterations = _optional_uint(header, "ITER")
        if not salt or not iterations:
            raise IncompatibleFormatError("keybag lacks SALT/ITER key-derivation parameters")
        dp_iterations = _optional_uint(header, "DPIC")
        dp_salt = header.get("DPSL")
        if (dp_iterations is None) != (dp_salt is None):
            raise IncompatibleFormatError("keybag has incomplete DPIC/DPSL parameters")

        class_keys = []
        for record in records:
            class_id = _optional_uint(record, "CLAS")
            wrap = _optional_uint(record, "WRAP")
            wrapped = record.get("WPKY")
            if class_id is None or wrap is None or wrapped is None:
                continue  # incomplete record: nothing usable, ignore
            key_type = _optional_uint(record, "KTYP") or KEY_TYPE_AES
            class_keys.append(ClassKey(class_id, wrap, key_type, wrapped))
        if not class_keys:
            raise IncompatibleFormatError("keybag contains no class keys")

        return cls(
            keybag_type=_optional_uint(header, "TYPE"),
            salt=salt,
            iterations=iterations,
            dp_salt=dp_salt,
            dp_iterations=dp_iterations,
            class_keys=tuple(class_keys),
        )

    def derive_passcode_key(self, password: str) -> bytes:
        secret = password.encode("utf-8")
        if self.dp_iterations and self.dp_salt:
            secret = pbkdf2("sha256", secret, self.dp_salt, self.dp_iterations, 32)
        return pbkdf2("sha1", secret, self.salt, self.iterations, 32)

    def unlock(self, password: str) -> "UnlockedKeybag":
        """Derive the passcode key and unwrap every passcode-only class key.

        Raises :class:`WrongPasswordError` when an unwrap integrity check fails.
        """
        passcode_key = self.derive_passcode_key(password)
        return self.unlock_with_key(passcode_key)

    def unlock_with_key(self, passcode_key: bytes) -> "UnlockedKeybag":
        keys: dict[int, bytes] = {}
        device_bound: set[int] = set()
        for class_key in self.class_keys:
            if class_key.class_id in keys or class_key.class_id in device_bound:
                continue  # first record for a class wins
            if class_key.is_device_bound:
                device_bound.add(class_key.class_id)
                continue
            if class_key.wrap != WRAP_PASSCODE:
                continue
            try:
                keys[class_key.class_id] = aes_key_unwrap(passcode_key, class_key.wrapped_key)
            except DecryptionError as exc:
                raise WrongPasswordError("incorrect backup password") from exc
            except CryptoError as exc:
                raise IncompatibleFormatError("malformed wrapped class key in keybag") from exc
        if not keys:
            raise IncompatibleFormatError("keybag has no passcode-wrapped class keys")
        key_types = {k.class_id: k.key_type for k in self.class_keys}
        return UnlockedKeybag(
            MappingProxyType(keys), frozenset(device_bound), MappingProxyType(key_types)
        )


@dataclass(frozen=True)
class UnlockedKeybag:
    class_keys: Mapping[int, bytes] = field(repr=False)
    device_bound_classes: frozenset[int]
    key_types: Mapping[int, int]

    def has_class(self, class_id: int) -> bool:
        """True if the keybag defines ``class_id`` (usable or device-bound)."""
        return class_id in self.class_keys or class_id in self.device_bound_classes

    def unwrap_key(self, class_id: int, wrapped_key: bytes) -> bytes:
        """Unwrap a per-file / per-item key protected by ``class_id``."""
        if class_id in self.device_bound_classes:
            raise DeviceBoundKeyError(f"protection class {class_id} is bound to the original device")
        class_key = self.class_keys.get(class_id)
        if class_key is None:
            raise DecryptionError(f"protection class {class_id} is not available in the keybag")
        if self.key_types.get(class_id, KEY_TYPE_AES) != KEY_TYPE_AES:
            raise IncompatibleFormatError(
                f"protection class {class_id} uses an asymmetric key type (not supported)"
            )
        return aes_key_unwrap(class_key, wrapped_key)


def iter_tlv(data: bytes):
    """Yield ``(tag, value)`` pairs from a keybag TLV blob with bounds checks."""
    if len(data) > _MAX_KEYBAG_SIZE:
        raise IncompatibleFormatError("keybag is implausibly large")
    offset = 0
    while offset < len(data):
        if offset + _TLV_HEADER.size > len(data):
            raise IncompatibleFormatError("keybag TLV header is truncated")
        raw_tag, length = _TLV_HEADER.unpack_from(data, offset)
        offset += _TLV_HEADER.size
        if length > len(data) - offset:
            raise IncompatibleFormatError("keybag TLV value is truncated")
        try:
            tag = raw_tag.decode("ascii")
        except UnicodeDecodeError as exc:
            raise IncompatibleFormatError("keybag contains a non-ASCII tag") from exc
        yield tag, data[offset:offset + length]
        offset += length


def _optional_uint(record: Mapping[str, bytes], tag: str) -> int | None:
    value = record.get(tag)
    if value is None:
        return None
    if len(value) != 4:
        raise IncompatibleFormatError(f"keybag field {tag} has unexpected size {len(value)}")
    return struct.unpack(">I", value)[0]
