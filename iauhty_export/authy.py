"""Identification of Authy accounts and association with keychain secrets.

Reverse-engineered mapping (not documented by Twilio; based on the public
authy-extractor research by dnicolson, 2025, and re-checked here):

* Authy's app-group preferences ``Library/Preferences/group.authy.128FD4.plist``
  in domain ``AppDomainGroup-group.authy.128FD4`` hold one entry per
  third-party ("authenticator") account, keyed by a numeric account ID. Each
  value is a dictionary with ``name``, ``original_issuer`` and ``digits``.
* The secret for account ``<id>`` lives in a generic-password keychain item
  whose service (``svce``) is ``Google<id>App``; its data is the base32
  secret as UTF-8 text.

Neither shape is guaranteed for every Authy/iOS version, so anything that
does not match is reported per account instead of being guessed.

Parameter defaults: Authy stores only ``digits`` for authenticator tokens and
generates codes with HMAC-SHA1 and a 30-second step (the Google Authenticator
conventions it imports from ``otpauth://`` URIs without other parameters).
SHA1/30 s are therefore applied when the record has no explicit value, and
every applied default is recorded in :attr:`TotpParameters.assumed`.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from .errors import IncompatibleFormatError, InvalidSecretError
from .models import (
    AccountResult,
    AccountStatus,
    Algorithm,
    AuthyAccount,
    KeychainItem,
    KeychainStats,
    RecoveryReport,
    TotpParameters,
    TotpToken,
)
from .plistutil import is_keyed_archive, load_plist, unarchive
from .totp import decode_base32, normalize_base32, self_check, validate_parameters

AUTHY_DOMAIN = "AppDomainGroup-group.authy.128FD4"
AUTHY_PREFERENCES = "Library/Preferences/group.authy.128FD4.plist"

DEFAULT_ALGORITHM = Algorithm.SHA1
DEFAULT_PERIOD = 30
DEFAULT_DIGITS = 6

_ACCOUNT_ID_RE = re.compile(r"^[0-9]{1,20}$")
_SERVICE_RE = re.compile(r"^Google([0-9]{1,20})App$")
_HEX_SEED_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")


def is_authy_service(service: str) -> bool:
    return _SERVICE_RE.match(service) is not None


def _service_account_id(service: str) -> str | None:
    match = _SERVICE_RE.match(service)
    return match.group(1) if match else None


def _first_text(record: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _first_int(record: Mapping[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
    return None


def _record_dict(value: Any) -> dict[str, Any] | None:
    """Return the account dictionary, decoding an NSKeyedArchiver blob if needed."""
    if isinstance(value, dict):
        return unarchive(value) if is_keyed_archive(value) else value
    if isinstance(value, bytes):
        decoded = load_plist(value, "Authy account record")
        if is_keyed_archive(decoded):
            decoded = unarchive(decoded)
        return decoded if isinstance(decoded, dict) else None
    return None


def parse_accounts(preferences: Mapping[str, Any]) -> list[tuple[AuthyAccount, str | None]]:
    """Extract account records from the Authy preferences.

    Returns ``(account, problem)`` pairs; ``problem`` is set when the record
    exists but cannot be interpreted.
    """
    parsed: list[tuple[AuthyAccount, str | None]] = []
    ids = sorted((k for k in preferences if isinstance(k, str) and _ACCOUNT_ID_RE.match(k)), key=int)
    for account_id in ids:
        try:
            record = _record_dict(preferences[account_id])
        except IncompatibleFormatError:
            record = None
        if record is None:
            parsed.append((AuthyAccount(account_id, None, None, None, None, None),
                           "account record has an unrecognised structure"))
            continue
        parsed.append((AuthyAccount(
            account_id=account_id,
            name=_first_text(record, "name", "original_name"),
            issuer=_first_text(record, "original_issuer", "issuer"),
            digits=_first_int(record, "digits"),
            period=_first_int(record, "period"),
            algorithm=_first_text(record, "algorithm", "algo"),
        ), None))
    return parsed


def _parameters(account: AuthyAccount) -> TotpParameters:
    assumed = []
    if account.algorithm is None:
        algorithm = DEFAULT_ALGORITHM
        assumed.append("algorithm")
    else:
        try:
            algorithm = Algorithm(account.algorithm.upper().replace("-", ""))
        except ValueError as exc:
            raise IncompatibleFormatError(f"unsupported algorithm {account.algorithm!r}") from exc
    digits = account.digits
    if digits is None:
        digits = DEFAULT_DIGITS
        assumed.append("digits")
    period = account.period
    if period is None:
        period = DEFAULT_PERIOD
        assumed.append("period")
    return TotpParameters(algorithm, digits, period, tuple(assumed))


def _not_found_detail(stats: KeychainStats) -> str:
    detail = "no keychain item with service 'Google<id>App' was found"
    if stats.undecryptable:
        detail += (
            f"; {stats.undecryptable} keychain item(s) could not be decrypted "
            f"({stats.device_bound} device-bound, {stats.unsupported} unsupported, "
            f"{stats.corrupted} corrupted) and might contain it"
        )
    return detail


def _secret_text(items: list[KeychainItem]) -> str:
    distinct = {item.data for item in items}
    if len(distinct) > 1:
        raise LookupError("several keychain items with different data match this account")
    raw = next(iter(distinct))
    try:
        return raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise InvalidSecretError("keychain data is not UTF-8 text") from exc


def _display_name(account: AuthyAccount) -> tuple[str, tuple[str, ...]]:
    if account.name:
        return account.name, ()
    if account.issuer:
        return account.issuer, ("account has no name; the issuer is used as name",)
    return f"Authy account {account.account_id}", ("account has no name or issuer; a placeholder name is used",)


def _recover_one(account: AuthyAccount, items: list[KeychainItem], stats: KeychainStats) -> AccountResult:
    if not items:
        return AccountResult(account, AccountStatus.SECRET_NOT_FOUND, _not_found_detail(stats))
    try:
        secret_text = _secret_text(items)
    except LookupError as exc:
        return AccountResult(account, AccountStatus.AMBIGUOUS_SECRET, str(exc))
    except InvalidSecretError as exc:
        return AccountResult(account, AccountStatus.INVALID_SECRET, str(exc))

    try:
        decode_base32(secret_text)
    except InvalidSecretError as exc:
        if _HEX_SEED_RE.match(secret_text):
            return AccountResult(account, AccountStatus.INCOMPATIBLE,
                                 "secret is hex-encoded, typical of proprietary Authy-native tokens")
        return AccountResult(account, AccountStatus.INVALID_SECRET, str(exc))

    try:
        parameters = _parameters(account)
        validate_parameters(parameters)
    except (IncompatibleFormatError, InvalidSecretError) as exc:
        return AccountResult(account, AccountStatus.INCOMPATIBLE, str(exc))

    secret = normalize_base32(secret_text)
    try:
        self_check(secret, parameters)
    except InvalidSecretError as exc:
        return AccountResult(account, AccountStatus.INVALID_SECRET, str(exc))

    name, warnings = _display_name(account)
    if parameters.assumed:
        warnings += (f"assumed default {', '.join(parameters.assumed)} (not stored by Authy)",)
    token = TotpToken(name=name, issuer=account.issuer or "", secret=secret,
                      parameters=parameters, source_id=account.account_id)
    return AccountResult(account, AccountStatus.RECOVERED, token=token, warnings=warnings)


def recover_accounts(
    preferences: Mapping[str, Any],
    items: Iterable[KeychainItem],
    stats: KeychainStats,
) -> RecoveryReport:
    """Match account records to keychain secrets; one result per account."""
    by_id: dict[str, list[KeychainItem]] = {}
    for item in items:
        account_id = _service_account_id(item.service)
        if account_id is not None:
            by_id.setdefault(account_id, []).append(item)

    results: list[AccountResult] = []
    seen: dict[tuple[str, Algorithm, int, int], str] = {}
    account_ids = set()
    for account, problem in parse_accounts(preferences):
        account_ids.add(account.account_id)
        if problem:
            results.append(AccountResult(account, AccountStatus.INCOMPATIBLE, problem))
            continue
        result = _recover_one(account, by_id.get(account.account_id, []), stats)
        if result.token is not None:
            p = result.token.parameters
            key = (result.token.secret, p.algorithm, p.digits, p.period)
            if key in seen:
                result = AccountResult(account, AccountStatus.DUPLICATE,
                                       f"same secret and parameters as account {seen[key]}")
            else:
                seen[key] = account.account_id
        results.append(result)

    orphans = sum(1 for account_id in by_id if account_id not in account_ids)
    return RecoveryReport(results=tuple(results), keychain=stats, orphan_secrets=orphans)
