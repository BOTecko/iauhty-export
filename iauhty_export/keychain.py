"""Selective decryption of the keychain stored in an encrypted backup.

``KeychainDomain/keychain-backup.plist`` is a dictionary with the item
classes ``genp`` (generic passwords), ``inet``, ``cert`` and ``keys``. Each
item is a dict whose ``v_Data`` holds an encrypted blob (little-endian):

    [0:4]   version (2 = binary plist payload, 3 = DER payload)
    [4:8]   protection class (low 4 bits; keychain classes 6..12)
    [8:12]  length L of the wrapped item key
    [12:12+L]   item key, RFC 3394-wrapped with the class key
    [12+L:-16]  AES-256-GCM ciphertext
    [-16:]      GCM tag

The GCM nonce is zero-length (iOS backups pass a NULL IV; J0 = 0^128). A
12-byte zero IV is tried as a fallback because some iOS builds use a fixed
default IV; the GCM tag makes the choice unambiguous.

In format 3 *every* attribute, including the service name (``svce``), is
inside the encrypted payload. Items therefore have to be decrypted in memory
before they can be filtered; non-matching items are discarded immediately.
Only items accepted by the caller's predicate are returned.
"""

from __future__ import annotations

import struct
from typing import Any, Callable

from .crypto import aes_gcm_decrypt
from .errors import (
    CryptoError,
    DecryptionError,
    DeviceBoundKeyError,
    IncompatibleFormatError,
    KeychainUnavailableError,
)
from .keybag import UnlockedKeybag
from .models import KeychainItem, KeychainStats
from .plistutil import load_plist, load_plist_dict

KEYCHAIN_DOMAIN = "KeychainDomain"
KEYCHAIN_FILE = "keychain-backup.plist"

_GCM_TAG = 16
_GCM_IVS = (b"", bytes(12))
_SUPPORTED_VERSIONS = (2, 3)
_MAX_DER_DEPTH = 8


# --------------------------------------------------------------------------
# Minimal DER decoder (only the shapes used by keychain item payloads)
# --------------------------------------------------------------------------

_TAG_BOOLEAN = 0x01
_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_NULL = 0x05
_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31
_STRING_TAGS = {0x0C, 0x13, 0x14, 0x16}  # UTF8, Printable, T61, IA5
_TIME_TAGS = {0x17, 0x18}  # UTCTime, GeneralizedTime


def _der_read(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one DER TLV at ``offset``; return ``(tag, value, next_offset)``."""
    if offset + 2 > len(data):
        raise IncompatibleFormatError("DER element is truncated")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise IncompatibleFormatError("DER high-tag-number form is not supported")
    first = data[offset + 1]
    offset += 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4:
            raise IncompatibleFormatError("unsupported DER length encoding")
        if offset + count > len(data):
            raise IncompatibleFormatError("DER length is truncated")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    if length > len(data) - offset:
        raise IncompatibleFormatError("DER value is truncated")
    return tag, data[offset:offset + length], offset + length


def _der_children(data: bytes) -> list[tuple[int, bytes]]:
    children = []
    offset = 0
    while offset < len(data):
        tag, value, offset = _der_read(data, offset)
        children.append((tag, value))
    return children


def _der_value(tag: int, value: bytes) -> Any:
    # Values are decoded leniently: an odd encoding of an attribute we never
    # use must not make the whole item unreadable, so it stays raw bytes.
    if tag == _TAG_BOOLEAN and len(value) == 1:
        return value != b"\x00"
    if tag == _TAG_INTEGER and 1 <= len(value) <= 16:
        return int.from_bytes(value, "big", signed=True)
    if tag == _TAG_NULL:
        return None
    if tag in _STRING_TAGS or tag in _TIME_TAGS:
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value
    return value  # OCTET STRING and anything unrecognised stay as raw bytes


def decode_der_attributes(data: bytes) -> dict[str, Any]:
    """Decode ``SET OF SEQUENCE { key STRING, value ANY }`` into a dict."""
    tag, body, end = _der_read(data, 0)
    if tag not in (_TAG_SET, _TAG_SEQUENCE) or end != len(data):
        raise IncompatibleFormatError("keychain payload is not a DER attribute set")
    attributes: dict[str, Any] = {}
    for child_tag, child in _der_children(body):
        if child_tag != _TAG_SEQUENCE:
            raise IncompatibleFormatError("keychain attribute is not a DER SEQUENCE")
        parts = _der_children(child)
        if len(parts) != 2 or parts[0][0] not in _STRING_TAGS:
            raise IncompatibleFormatError("keychain attribute has an unexpected shape")
        key = _der_value(*parts[0])
        if not isinstance(key, str):
            raise IncompatibleFormatError("keychain attribute name is not valid text")
        attributes.setdefault(key, _der_value(*parts[1]))
    return attributes


# --------------------------------------------------------------------------
# Item decryption
# --------------------------------------------------------------------------

def decrypt_item(blob: bytes, keybag: UnlockedKeybag) -> dict[str, Any]:
    """Decrypt one ``v_Data`` blob into its attribute dictionary.

    Raises :class:`DeviceBoundKeyError` for ThisDeviceOnly classes,
    :class:`IncompatibleFormatError` for unknown layouts and
    :class:`DecryptionError` for corrupted data.
    """
    if len(blob) < 12:
        raise IncompatibleFormatError("keychain item blob is truncated")
    version, raw_class, wrapped_len = struct.unpack_from("<III", blob, 0)
    if version not in _SUPPORTED_VERSIONS:
        raise IncompatibleFormatError(f"unsupported keychain item version {version}")
    # Modern keybags define classes above 15 (e.g. 17-19), so the full value
    # is used when the keybag knows it. Otherwise fall back to the low nibble,
    # the convention of the iphone-dataprotection tools for flag bits.
    protection_class = raw_class if keybag.has_class(raw_class) else raw_class & 0xF
    if not 24 <= wrapped_len <= 512 or 12 + wrapped_len + _GCM_TAG > len(blob):
        raise IncompatibleFormatError("keychain item has an invalid wrapped-key length")
    wrapped_key = blob[12:12 + wrapped_len]
    ciphertext = blob[12 + wrapped_len:-_GCM_TAG]
    tag = blob[-_GCM_TAG:]

    item_key = keybag.unwrap_key(protection_class, wrapped_key)
    payload = None
    for iv in _GCM_IVS:
        try:
            payload = aes_gcm_decrypt(item_key, iv, ciphertext, tag)
            break
        except DecryptionError:
            continue
    if payload is None:
        raise DecryptionError("keychain item failed GCM authentication")

    if version == 3:
        return decode_der_attributes(payload)
    value = load_plist(payload, "keychain item payload")
    if not isinstance(value, dict):
        raise IncompatibleFormatError("keychain item payload is not a dictionary")
    return value


def _text(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return None
    return None


def extract_generic_passwords(
    keychain_plist: bytes,
    keybag: UnlockedKeybag,
    service_filter: Callable[[str], bool],
) -> tuple[list[KeychainItem], KeychainStats]:
    """Decrypt generic-password items and keep only those whose service matches.

    Per-item failures are counted, never fatal; only an unreadable keychain
    file as a whole raises :class:`KeychainUnavailableError`.
    """
    try:
        keychain = load_plist_dict(keychain_plist, KEYCHAIN_FILE)
    except IncompatibleFormatError as exc:
        raise KeychainUnavailableError(str(exc)) from exc
    entries = keychain.get("genp", [])
    if not isinstance(entries, list):
        raise KeychainUnavailableError("keychain backup has a malformed 'genp' section")

    matches: list[KeychainItem] = []
    decrypted = device_bound = unsupported = corrupted = 0
    for entry in entries:
        blob = entry.get("v_Data") if isinstance(entry, dict) else None
        if not isinstance(blob, bytes):
            corrupted += 1
            continue
        try:
            attributes = decrypt_item(blob, keybag)
        except DeviceBoundKeyError:
            device_bound += 1
            continue
        except IncompatibleFormatError:
            unsupported += 1
            continue
        except CryptoError:
            corrupted += 1
            continue
        decrypted += 1
        service = _text(attributes.get("svce"))
        if service is None or not service_filter(service):
            continue  # unrelated item: drop it without keeping any data
        data = attributes.get("v_Data")
        if isinstance(data, str):
            data = data.encode("utf-8")
        matches.append(KeychainItem(
            service=service,
            account=_text(attributes.get("acct")),
            access_group=_text(attributes.get("agrp")),
            data=data if isinstance(data, bytes) else b"",
        ))
    stats = KeychainStats(
        total=len(entries),
        decrypted=decrypted,
        matched=len(matches),
        device_bound=device_bound,
        unsupported=unsupported,
        corrupted=corrupted,
    )
    return matches, stats
