"""Defensive property-list helpers (plain plists and NSKeyedArchiver blobs)."""

from __future__ import annotations

import plistlib
import struct
from typing import Any
from xml.parsers.expat import ExpatError

from .errors import IncompatibleFormatError

# Exceptions plistlib can raise on malformed input. Listed explicitly rather
# than catching ``Exception`` so genuine programming errors still surface.
_PLIST_DECODE_ERRORS = (
    plistlib.InvalidFileException,
    ValueError,
    TypeError,
    KeyError,
    IndexError,
    OverflowError,
    RecursionError,
    struct.error,
    ExpatError,
)

_MAX_ARCHIVE_DEPTH = 32


def load_plist(data: bytes, what: str) -> Any:
    """Parse an XML or binary plist; raise :class:`IncompatibleFormatError` if invalid."""
    try:
        return plistlib.loads(data)
    except _PLIST_DECODE_ERRORS as exc:
        raise IncompatibleFormatError(f"{what} is not a valid property list") from exc


def load_plist_dict(data: bytes, what: str) -> dict[str, Any]:
    value = load_plist(data, what)
    if not isinstance(value, dict):
        raise IncompatibleFormatError(f"{what} does not contain a dictionary")
    return value


def is_keyed_archive(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("$archiver") == "NSKeyedArchiver"
        and isinstance(value.get("$objects"), list)
        and isinstance(value.get("$top"), dict)
    )


def unarchive(archive: dict[str, Any], root_key: str = "root") -> Any:
    """Resolve an NSKeyedArchiver archive into plain Python values.

    Only the Foundation shapes needed here are understood: NSDictionary /
    NSMutableDictionary (``NS.keys``/``NS.objects``), NSArray (``NS.objects``),
    NSData (``NS.data``), NSString (``NS.string``) and plain archived objects
    (returned as dicts of their resolved fields). ``$null`` becomes ``None``.
    """
    if not is_keyed_archive(archive):
        raise IncompatibleFormatError("data is not an NSKeyedArchiver archive")
    objects = archive["$objects"]
    root = archive["$top"].get(root_key)
    if not isinstance(root, plistlib.UID):
        raise IncompatibleFormatError("keyed archive has no root object")
    return _resolve(objects, root, 0)


def _resolve(objects: list[Any], value: Any, depth: int) -> Any:
    if depth > _MAX_ARCHIVE_DEPTH:
        raise IncompatibleFormatError("keyed archive nesting is too deep")
    if isinstance(value, plistlib.UID):
        if not 0 <= value.data < len(objects):
            raise IncompatibleFormatError("keyed archive reference out of range")
        value = objects[value.data]
        if value == "$null":
            return None
    if isinstance(value, list):
        return [_resolve(objects, item, depth + 1) for item in value]
    if not isinstance(value, dict):
        return value
    if "NS.keys" in value and "NS.objects" in value:
        keys = [_resolve(objects, k, depth + 1) for k in value["NS.keys"]]
        vals = [_resolve(objects, v, depth + 1) for v in value["NS.objects"]]
        if len(keys) != len(vals) or not all(isinstance(k, (str, int)) for k in keys):
            raise IncompatibleFormatError("keyed archive dictionary is inconsistent")
        return dict(zip(keys, vals))
    if "NS.objects" in value:
        return [_resolve(objects, v, depth + 1) for v in value["NS.objects"]]
    if "NS.data" in value:
        return _resolve(objects, value["NS.data"], depth + 1)
    if "NS.string" in value:
        return _resolve(objects, value["NS.string"], depth + 1)
    return {
        key: _resolve(objects, item, depth + 1)
        for key, item in value.items()
        if key != "$class"
    }
