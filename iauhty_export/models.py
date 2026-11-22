"""Typed, immutable data models shared between layers.

Parsing layers produce these models; the exporter and CLI consume them.
None of them depend on the iOS backup layout or the Aegis output format.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


@dataclass(frozen=True)
class BackupInfo:
    """Metadata of one iOS backup directory, gathered without a password."""

    path: Path
    identifier: str
    device_name: str | None
    product_type: str | None
    ios_version: str | None
    backup_date: dt.datetime | None
    is_encrypted: bool | None
    snapshot_state: str | None
    problems: tuple[str, ...] = ()

    @property
    def is_usable(self) -> bool:
        """True when the backup looks complete and encrypted."""
        return not self.problems and self.is_encrypted is True


class Algorithm(Enum):
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA512 = "SHA512"

    @property
    def hashlib_name(self) -> str:
        return self.value.lower()


@dataclass(frozen=True)
class TotpParameters:
    algorithm: Algorithm
    digits: int
    period: int
    # Names of parameters that were not stored in the source data and were
    # filled with documented defaults (see authy.py). Reported, never hidden.
    assumed: tuple[str, ...] = ()


@dataclass(frozen=True)
class TotpToken:
    """A validated TOTP credential ready for export."""

    name: str
    issuer: str
    secret: str  # normalised, unpadded, upper-case RFC 4648 base32
    parameters: TotpParameters
    source_id: str

    def __repr__(self) -> str:  # never leak the secret through repr/logging
        return (
            f"TotpToken(name={self.name!r}, issuer={self.issuer!r}, "
            f"secret=<redacted>, parameters={self.parameters!r}, source_id={self.source_id!r})"
        )


@dataclass(frozen=True)
class AuthyAccount:
    """An Authy account record as found in the app preferences."""

    account_id: str
    name: str | None
    issuer: str | None
    digits: int | None
    period: int | None
    algorithm: str | None


@dataclass(frozen=True)
class KeychainItem:
    """A decrypted generic-password keychain item that passed the caller's filter."""

    service: str
    account: str | None
    access_group: str | None
    data: bytes

    def __repr__(self) -> str:
        return (
            f"KeychainItem(service={self.service!r}, account={self.account!r}, "
            f"access_group={self.access_group!r}, data=<redacted>)"
        )


@dataclass(frozen=True)
class KeychainStats:
    """Outcome counts for all generic-password items in the keychain backup."""

    total: int = 0
    decrypted: int = 0
    matched: int = 0
    device_bound: int = 0
    unsupported: int = 0
    corrupted: int = 0

    @property
    def undecryptable(self) -> int:
        return self.device_bound + self.unsupported + self.corrupted


class AccountStatus(Enum):
    RECOVERED = "recovered"
    DUPLICATE = "duplicate"
    SECRET_NOT_FOUND = "secret_not_found"
    AMBIGUOUS_SECRET = "ambiguous_secret"
    INVALID_SECRET = "invalid_secret"
    INCOMPATIBLE = "incompatible"


@dataclass(frozen=True)
class AccountResult:
    account: AuthyAccount
    status: AccountStatus
    detail: str = ""
    token: TotpToken | None = None
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class RecoveryReport:
    results: tuple[AccountResult, ...]
    keychain: KeychainStats
    orphan_secrets: int = 0  # Authy-pattern keychain items with no account record

    @property
    def tokens(self) -> tuple[TotpToken, ...]:
        return tuple(r.token for r in self.results if r.status is AccountStatus.RECOVERED and r.token)

    def count(self, status: AccountStatus) -> int:
        return sum(1 for r in self.results if r.status is status)


@dataclass(frozen=True)
class ExportSummary:
    path: Path
    entries: int
    validation_issues: tuple[str, ...] = field(default_factory=tuple)
