"""Minimal ctypes binding to Apple's CommonCrypto.

This is the only module that touches ``ctypes``. It exposes thin wrappers
with explicit argument/return types, checks every status code and wipes the
native output buffers after copying their contents out. Input validation
(key sizes, block alignment) is done in :mod:`iauhty_export.crypto`.
"""

from __future__ import annotations

import ctypes
import sys
from functools import lru_cache

from .errors import CryptoError

# CommonCryptor.h / CommonKeyDerivation.h / CommonSymmetricKeywrap.h constants.
K_CC_ENCRYPT = 0
K_CC_DECRYPT = 1
K_CC_ALGORITHM_AES = 0
K_CC_OPTION_NONE = 0
K_CC_WRAP_AES = 1
RFC3394_IV = b"\xa6" * 8

_STATUS_NAMES = {
    0: "kCCSuccess",
    -4300: "kCCParamError",
    -4301: "kCCBufferTooSmall",
    -4302: "kCCMemoryFailure",
    -4303: "kCCAlignmentError",
    -4304: "kCCDecodeError",
    -4305: "kCCUnimplemented",
    -4306: "kCCOverflow",
    -4307: "kCCRNGFailure",
    -4308: "kCCUnspecifiedError",
    -4309: "kCCCallSequenceError",
    -4310: "kCCKeySizeError",
    -4311: "kCCInvalidKey",
}

_LIBRARY_CANDIDATES = (
    "/usr/lib/system/libcommonCrypto.dylib",
    "/usr/lib/libSystem.B.dylib",
)

_c_size_p = ctypes.POINTER(ctypes.c_size_t)


@lru_cache(maxsize=1)
def _library() -> ctypes.CDLL:
    if sys.platform != "darwin":
        raise CryptoError("CommonCrypto is only available on macOS")
    for candidate in _LIBRARY_CANDIDATES:
        try:
            lib = ctypes.CDLL(candidate)
        except OSError:
            continue
        if hasattr(lib, "CCCrypt"):
            _declare(lib)
            return lib
    raise CryptoError("unable to load CommonCrypto from the system libraries")


def _declare(lib: ctypes.CDLL) -> None:
    lib.CCCrypt.restype = ctypes.c_int32
    lib.CCCrypt.argtypes = [
        ctypes.c_uint32,  # CCOperation
        ctypes.c_uint32,  # CCAlgorithm
        ctypes.c_uint32,  # CCOptions
        ctypes.c_void_p, ctypes.c_size_t,  # key, keyLength
        ctypes.c_void_p,  # iv
        ctypes.c_void_p, ctypes.c_size_t,  # dataIn, dataInLength
        ctypes.c_void_p, ctypes.c_size_t,  # dataOut, dataOutAvailable
        _c_size_p,  # dataOutMoved
    ]
    lib.CCSymmetricKeyWrap.restype = ctypes.c_int
    lib.CCSymmetricKeyWrap.argtypes = [
        ctypes.c_uint32,  # CCWrappingAlgorithm
        ctypes.c_void_p, ctypes.c_size_t,  # iv, ivLen
        ctypes.c_void_p, ctypes.c_size_t,  # kek, kekLen
        ctypes.c_void_p, ctypes.c_size_t,  # rawKey, rawKeyLen
        ctypes.c_void_p, _c_size_p,  # wrappedKey, wrappedKeyLen
    ]
    lib.CCSymmetricKeyUnwrap.restype = ctypes.c_int
    lib.CCSymmetricKeyUnwrap.argtypes = [
        ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_void_p, ctypes.c_size_t,  # wrappedKey, wrappedKeyLen
        ctypes.c_void_p, _c_size_p,  # rawKey, rawKeyLen
    ]
    # CCCryptorGCM is the legacy one-shot GCM API. It is used instead of
    # CCCryptorGCMOneshotDecrypt because only the legacy API accepts the
    # zero-length IV that iOS uses for keychain backup items (the oneshot API
    # returns kCCParamError for it). In decrypt mode it *outputs* the computed
    # tag; the caller must compare it in constant time.
    lib.CCCryptorGCM.restype = ctypes.c_int32
    lib.CCCryptorGCM.argtypes = [
        ctypes.c_uint32,  # CCOperation
        ctypes.c_uint32,  # CCAlgorithm
        ctypes.c_void_p, ctypes.c_size_t,  # key, keyLength
        ctypes.c_void_p, ctypes.c_size_t,  # iv, ivLen
        ctypes.c_void_p, ctypes.c_size_t,  # aData, aDataLen
        ctypes.c_void_p, ctypes.c_size_t,  # dataIn, dataInLength
        ctypes.c_void_p,  # dataOut
        ctypes.c_void_p, _c_size_p,  # tagOut, tagLength
    ]


def _check(status: int, operation: str) -> None:
    if status != 0:
        name = _STATUS_NAMES.get(status, "unknown status")
        raise CryptoError(f"CommonCrypto {operation} failed: {name} ({status})")


def _take(buffer: ctypes.Array, length: int) -> bytes:
    """Copy ``length`` bytes out of a native buffer, then zero the buffer."""
    data = buffer.raw[:length]
    ctypes.memset(buffer, 0, len(buffer))
    return data


def _buffer(length: int) -> ctypes.Array:
    # A zero-length buffer would be a NULL-ish pointer; always allocate >= 1.
    return ctypes.create_string_buffer(max(length, 1))


def cc_crypt(operation: int, key: bytes, iv: bytes | None, data: bytes) -> bytes:
    """Run AES-CBC without padding (caller guarantees block alignment)."""
    lib = _library()
    out = _buffer(len(data) + 16)
    moved = ctypes.c_size_t(0)
    status = lib.CCCrypt(
        operation, K_CC_ALGORITHM_AES, K_CC_OPTION_NONE,
        key, len(key), iv, data, len(data), out, len(out), ctypes.byref(moved),
    )
    if status != 0:
        ctypes.memset(out, 0, len(out))
    _check(status, "CCCrypt")
    if moved.value != len(data):
        _take(out, 0)
        raise CryptoError("CCCrypt produced an unexpected output length")
    return _take(out, moved.value)


def cc_key_wrap(kek: bytes, raw_key: bytes) -> bytes:
    lib = _library()
    out_len = ctypes.c_size_t(len(raw_key) + 8)
    out = _buffer(out_len.value)
    status = lib.CCSymmetricKeyWrap(
        K_CC_WRAP_AES, RFC3394_IV, len(RFC3394_IV), kek, len(kek),
        raw_key, len(raw_key), out, ctypes.byref(out_len),
    )
    _check(status, "CCSymmetricKeyWrap")
    return _take(out, out_len.value)


def cc_key_unwrap(kek: bytes, wrapped_key: bytes) -> bytes | None:
    """Return the unwrapped key, or ``None`` if the integrity check fails."""
    lib = _library()
    out_len = ctypes.c_size_t(len(wrapped_key) - 8)
    out = _buffer(out_len.value)
    status = lib.CCSymmetricKeyUnwrap(
        K_CC_WRAP_AES, RFC3394_IV, len(RFC3394_IV), kek, len(kek),
        wrapped_key, len(wrapped_key), out, ctypes.byref(out_len),
    )
    if status != 0:
        # CommonCrypto reports an RFC 3394 integrity (IV) mismatch as a
        # non-zero status; that is the expected signal for a wrong key.
        ctypes.memset(out, 0, len(out))
        return None
    return _take(out, out_len.value)


def cc_gcm(
    operation: int, key: bytes, iv: bytes, data: bytes, tag_length: int = 16
) -> tuple[bytes, bytes]:
    """Run one-shot AES-GCM without AAD. Returns ``(output, computed_tag)``."""
    lib = _library()
    out = _buffer(len(data))
    tag = _buffer(tag_length)
    tag_len = ctypes.c_size_t(tag_length)
    status = lib.CCCryptorGCM(
        operation, K_CC_ALGORITHM_AES, key, len(key),
        iv if iv else None, len(iv), None, 0,
        data, len(data), out, tag, ctypes.byref(tag_len),
    )
    if status != 0:
        ctypes.memset(out, 0, len(out))
    _check(status, "CCCryptorGCM")
    if tag_len.value != tag_length:
        raise CryptoError("CCCryptorGCM returned an unexpected tag length")
    return _take(out, len(data)), _take(tag, tag_length)
