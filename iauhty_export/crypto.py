"""Cryptographic primitives used by iOS encrypted backups.

AES itself is never implemented here: all block-cipher work is delegated to
CommonCrypto via :mod:`iauhty_export._commoncrypto`. This module validates
inputs, applies padding rules and performs integrity checks (key-wrap IV,
GCM tag) so that callers never receive unauthenticated garbage silently.
"""

from __future__ import annotations

import hashlib
import hmac

from . import _commoncrypto as cc
from .errors import CryptoError, DecryptionError

AES_BLOCK_SIZE = 16
AES_KEY_SIZES = (16, 24, 32)
GCM_TAG_SIZE = 16
ZERO_IV = bytes(AES_BLOCK_SIZE)

# iOS backups use PBKDF2 with up to ~10 million iterations. Anything far
# beyond that is treated as corrupted/hostile input to avoid an
# effectively unbounded CPU burn.
MAX_PBKDF2_ITERATIONS = 100_000_000


def _require_aes_key(key: bytes) -> None:
    if len(key) not in AES_KEY_SIZES:
        raise CryptoError(f"invalid AES key length: {len(key)} bytes")


def pbkdf2(hash_name: str, password: bytes, salt: bytes, iterations: int, length: int) -> bytes:
    """PBKDF2-HMAC (RFC 8018) with bounds checks on the iteration count."""
    if hash_name not in ("sha1", "sha256"):
        raise CryptoError(f"unsupported PBKDF2 hash: {hash_name}")
    if not 1 <= iterations <= MAX_PBKDF2_ITERATIONS:
        raise CryptoError(f"PBKDF2 iteration count out of range: {iterations}")
    if not salt:
        raise CryptoError("PBKDF2 salt is empty")
    return hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, length)


MAX_SCRYPT_MEMORY = 256 << 20


def scrypt_available() -> bool:
    """True when ``hashlib.scrypt`` exists (Python built against OpenSSL >= 1.1).

    The Python bundled with macOS links LibreSSL and lacks it; CommonCrypto
    has no public scrypt either.
    """
    return hasattr(hashlib, "scrypt")


def scrypt(password: bytes, salt: bytes, n: int, r: int, p: int, length: int = 32) -> bytes:
    """scrypt (RFC 7914) via OpenSSL, with bounds checks on the cost parameters."""
    if not scrypt_available():
        raise CryptoError("scrypt is unavailable: Python must be built with OpenSSL (use Python 3.12+)")
    if n < 2 or n & (n - 1):
        raise CryptoError(f"scrypt N must be a power of two greater than 1, got {n}")
    if not 1 <= r <= 32 or not 1 <= p <= 16 or not salt:
        raise CryptoError("scrypt parameters out of range")
    # OpenSSL needs 128*r*(N+2) bytes for V plus 128*r*p for B.
    needed = 128 * r * (n + 2) + 128 * r * p
    if needed > MAX_SCRYPT_MEMORY:
        raise CryptoError("scrypt parameters require too much memory")
    try:
        return hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, maxmem=needed + (1 << 20), dklen=length)
    except ValueError as exc:
        raise CryptoError(f"scrypt failed: {exc}") from exc


def pkcs7_pad(data: bytes) -> bytes:
    pad = AES_BLOCK_SIZE - len(data) % AES_BLOCK_SIZE
    return data + bytes([pad]) * pad


def pkcs7_unpad(data: bytes) -> bytes:
    """Strictly remove PKCS#7 padding; raise :class:`DecryptionError` if invalid."""
    if not data or len(data) % AES_BLOCK_SIZE:
        raise DecryptionError("padded data is not a whole number of AES blocks")
    pad = data[-1]
    if not 1 <= pad <= AES_BLOCK_SIZE or data[-pad:] != bytes([pad]) * pad:
        raise DecryptionError("invalid PKCS#7 padding")
    return data[:-pad]


def aes_cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes = ZERO_IV) -> bytes:
    """AES-CBC encryption of block-aligned data (no implicit padding)."""
    _validate_cbc(key, plaintext, iv)
    return cc.cc_crypt(cc.K_CC_ENCRYPT, key, iv, plaintext)


def aes_cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes = ZERO_IV) -> bytes:
    """AES-CBC decryption of block-aligned data (padding is left in place)."""
    _validate_cbc(key, ciphertext, iv)
    return cc.cc_crypt(cc.K_CC_DECRYPT, key, iv, ciphertext)


def _validate_cbc(key: bytes, data: bytes, iv: bytes) -> None:
    _require_aes_key(key)
    if len(iv) != AES_BLOCK_SIZE:
        raise CryptoError(f"invalid AES-CBC IV length: {len(iv)} bytes")
    if len(data) % AES_BLOCK_SIZE:
        raise DecryptionError("AES-CBC data length is not a multiple of 16 bytes")


def aes_key_wrap(kek: bytes, key: bytes) -> bytes:
    """RFC 3394 AES Key Wrap."""
    _require_aes_key(kek)
    if len(key) < 16 or len(key) % 8:
        raise CryptoError("key to wrap must be at least 16 bytes and a multiple of 8")
    return cc.cc_key_wrap(kek, key)


def aes_key_unwrap(kek: bytes, wrapped: bytes) -> bytes:
    """RFC 3394 AES Key Unwrap.

    Raises :class:`DecryptionError` when the 64-bit integrity check fails,
    which is how a wrong password or wrong class key manifests.
    """
    _require_aes_key(kek)
    if len(wrapped) < 24 or len(wrapped) % 8:
        raise DecryptionError(f"invalid wrapped key length: {len(wrapped)} bytes")
    key = cc.cc_key_unwrap(kek, wrapped)
    if key is None or len(key) != len(wrapped) - 8:
        raise DecryptionError("AES key unwrap integrity check failed")
    return key


def aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """AES-GCM encryption without AAD. Returns ``(ciphertext, tag)``.

    ``iv`` may be empty: iOS keychain backups use a zero-length IV, for which
    the GCM pre-counter block J0 = GHASH_H(0^128) = 0^128.
    """
    _require_aes_key(key)
    return cc.cc_gcm(cc.K_CC_ENCRYPT, key, iv, plaintext, GCM_TAG_SIZE)


def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Authenticated AES-GCM decryption; raises on tag mismatch."""
    _require_aes_key(key)
    if len(tag) != GCM_TAG_SIZE:
        raise DecryptionError(f"invalid GCM tag length: {len(tag)} bytes")
    plaintext, computed_tag = cc.cc_gcm(cc.K_CC_DECRYPT, key, iv, ciphertext, GCM_TAG_SIZE)
    if not hmac.compare_digest(computed_tag, tag):
        raise DecryptionError("AES-GCM authentication tag mismatch")
    return plaintext
