"""RFC 4226 / RFC 6238 one-time password generation and secret validation.

Used only to validate recovered secrets locally. Generated codes must never
be printed or logged.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import struct

from .errors import InvalidSecretError
from .models import Algorithm, TotpParameters

# Proton's Aegis importer accepts 1..9 digits; RFC 4226 requires >= 6.
MIN_DIGITS = 6
MAX_DIGITS = 9
MIN_PERIOD = 1
MAX_PERIOD = 3600
# RFC 4226 §4 requires >= 128 bits and recommends 160; many real services
# still issue 80-bit secrets, so 80 bits is the hard floor here.
MIN_SECRET_BYTES = 10

_BASE32_RE = re.compile(r"^[A-Z2-7]+$")
_SEPARATORS_RE = re.compile(r"[\s\-_]")
# Base32 lengths (mod 8) that cannot occur for whole bytes.
_INVALID_BASE32_REMAINDERS = {1, 3, 6}


def normalize_base32(text: str) -> str:
    """Upper-case, drop separators and trailing padding (RFC 4648 §6)."""
    return _SEPARATORS_RE.sub("", text).upper().rstrip("=")


def decode_base32(text: str) -> bytes:
    """Decode a (possibly unpadded) base32 secret; raise on any invalid input."""
    normalized = normalize_base32(text)
    if not normalized or not _BASE32_RE.match(normalized):
        raise InvalidSecretError("secret is not valid base32")
    if len(normalized) % 8 in _INVALID_BASE32_REMAINDERS:
        raise InvalidSecretError("secret has an impossible base32 length")
    padded = normalized + "=" * (-len(normalized) % 8)
    try:
        return base64.b32decode(padded)
    except binascii.Error as exc:
        raise InvalidSecretError("secret is not valid base32") from exc


def validate_parameters(parameters: TotpParameters) -> None:
    if not isinstance(parameters.algorithm, Algorithm):
        raise InvalidSecretError("unsupported TOTP algorithm")
    if not MIN_DIGITS <= parameters.digits <= MAX_DIGITS:
        raise InvalidSecretError(f"unsupported number of digits: {parameters.digits}")
    if not MIN_PERIOD <= parameters.period <= MAX_PERIOD:
        raise InvalidSecretError(f"unsupported TOTP period: {parameters.period}")


def hotp(key: bytes, counter: int, digits: int, algorithm: Algorithm) -> str:
    """RFC 4226 HOTP with dynamic truncation."""
    if counter < 0:
        raise ValueError("HOTP counter must be non-negative")
    digest = hmac.new(key, struct.pack(">Q", counter), getattr(hashlib, algorithm.hashlib_name)).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % 10 ** digits).zfill(digits)


def totp(key: bytes, timestamp: int, parameters: TotpParameters) -> str:
    """RFC 6238 TOTP for a Unix ``timestamp`` (T0 = 0)."""
    return hotp(key, timestamp // parameters.period, parameters.digits, parameters.algorithm)


def self_check(secret: str, parameters: TotpParameters, timestamps: tuple[int, ...] = (0, 59, 1_111_111_109)) -> None:
    """Validate a secret end to end: decode, parameter ranges and code generation.

    This proves the secret is mathematically usable. It does *not* prove the
    issuing service will accept the codes.
    """
    key = decode_base32(secret)
    if len(key) < MIN_SECRET_BYTES:
        raise InvalidSecretError(f"secret is too short ({len(key) * 8} bits)")
    validate_parameters(parameters)
    for timestamp in timestamps:
        code = totp(key, timestamp, parameters)
        if len(code) != parameters.digits or not code.isdigit():
            raise InvalidSecretError("TOTP generation produced a malformed code")
