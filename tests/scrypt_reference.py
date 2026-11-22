"""Pure-Python scrypt (RFC 7914), for tests only.

The product uses OpenSSL's ``hashlib.scrypt``. This slow reference lets the
encrypted-export code run on Pythons without it (e.g. macOS' bundled 3.9),
and is itself checked against the RFC 7914 test vectors and, where
available, against ``hashlib.scrypt``.
"""

from __future__ import annotations

import hashlib
import struct

_MASK = 0xFFFFFFFF


def _rotl(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (32 - shift))) & _MASK


def salsa20_8(block: bytes) -> bytes:
    """Salsa20/8 core (RFC 7914 §3) over a 64-byte block."""
    x = list(struct.unpack("<16I", block))
    original = x[:]
    for _ in range(4):
        for a, b, c, d in ((0, 4, 8, 12), (5, 9, 13, 1), (10, 14, 2, 6), (15, 3, 7, 11)):
            x[b] ^= _rotl((x[a] + x[d]) & _MASK, 7)
            x[c] ^= _rotl((x[b] + x[a]) & _MASK, 9)
            x[d] ^= _rotl((x[c] + x[b]) & _MASK, 13)
            x[a] ^= _rotl((x[d] + x[c]) & _MASK, 18)
        for a, b, c, d in ((0, 1, 2, 3), (5, 6, 7, 4), (10, 11, 8, 9), (15, 12, 13, 14)):
            x[b] ^= _rotl((x[a] + x[d]) & _MASK, 7)
            x[c] ^= _rotl((x[b] + x[a]) & _MASK, 9)
            x[d] ^= _rotl((x[c] + x[b]) & _MASK, 13)
            x[a] ^= _rotl((x[d] + x[c]) & _MASK, 18)
    return struct.pack("<16I", *((x[i] + original[i]) & _MASK for i in range(16)))


def _xor(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "little") ^ int.from_bytes(b, "little")).to_bytes(len(a), "little")


def _block_mix(block: bytes, r: int) -> bytes:
    x = block[(2 * r - 1) * 64:]
    even, odd = [], []
    for i in range(2 * r):
        x = salsa20_8(_xor(x, block[i * 64:(i + 1) * 64]))
        (even if i % 2 == 0 else odd).append(x)
    return b"".join(even + odd)


def _ro_mix(block: bytes, n: int, r: int) -> bytes:
    x = block
    v = []
    for _ in range(n):
        v.append(x)
        x = _block_mix(x, r)
    for _ in range(n):
        j = int.from_bytes(x[(2 * r - 1) * 64:(2 * r - 1) * 64 + 8], "little") % n
        x = _block_mix(_xor(x, v[j]), r)
    return x


def scrypt(password: bytes, salt: bytes, n: int, r: int, p: int, length: int = 32) -> bytes:
    blocks = hashlib.pbkdf2_hmac("sha256", password, salt, 1, p * 128 * r)
    mixed = b"".join(_ro_mix(blocks[i * 128 * r:(i + 1) * 128 * r], n, r) for i in range(p))
    return hashlib.pbkdf2_hmac("sha256", password, mixed, 1, length)
