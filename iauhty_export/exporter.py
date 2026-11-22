"""Encrypted Aegis vault export (Aegis ``docs/vault.md`` format).

The output is a current-format Aegis vault protected by a password slot,
importable by Aegis and other authenticators that read Aegis vaults (Proton
Authenticator is the one this project has tested). Field requirements were
cross-checked against Aegis' own writer (``Vault``/``VaultEntry``/
``PasswordSlot``/``CryptoUtils``) and Proton's importer
(``proton-pass-common``, ``proton-authenticator/src/parser/aegis``).

Encryption, as Aegis does it:

* a random 32-byte master key encrypts the UTF-8 JSON of the ``db`` object
  with AES-256-GCM (12-byte nonce, 16-byte tag, no AAD); ``db`` holds the
  base64 ciphertext and ``header.params`` the hex nonce/tag;
* one password slot (``type`` 1) stores the master key encrypted with
  AES-256-GCM under scrypt(password UTF-8, 32-byte salt, N=2^15, r=8, p=1);
  ``key``, ``salt`` and ``key_params`` are hex. Importers such as Proton use
  ``slots[0]``, so exactly one slot is written.

Structural validation proves the file matches that format. It does not
prove that a particular app version will import it.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from . import crypto
from .errors import CryptoError, DecryptionError, ExportError, InvalidSecretError, WrongPasswordError
from .models import Algorithm, ExportSummary, TotpParameters, TotpToken
from .totp import self_check

DEFAULT_OUTPUT_DIR = Path.home() / "IauhtyExport"
DEFAULT_OUTPUT_NAME = "iauhty-export.json"

VAULT_VERSION = 1
DB_VERSION = 3
_MAX_EXPORT_SIZE = 16 << 20

# Locations commonly synchronised to cloud services on macOS.
_SYNCED_DIRS = (
    Path.home() / "Desktop",
    Path.home() / "Documents",
    Path.home() / "Library" / "Mobile Documents",
    Path.home() / "Library" / "CloudStorage",
    Path.home() / "Dropbox",
    Path.home() / "Google Drive",
    Path.home() / "OneDrive",
)


# --------------------------------------------------------------------------
# Building and validating the document
# --------------------------------------------------------------------------

def build_vault(tokens: Iterable[TotpToken], uuid_factory: Callable[[], uuid.UUID] = uuid.uuid4) -> dict[str, Any]:
    entries = []
    for token in tokens:
        entries.append({
            "type": "totp",
            "uuid": str(uuid_factory()),
            "name": token.name,
            "issuer": token.issuer,
            "note": "",
            "favorite": False,
            "icon": None,
            "info": {
                "secret": token.secret,
                "algo": token.parameters.algorithm.value,
                "digits": token.parameters.digits,
                "period": token.parameters.period,
            },
            "groups": [],
        })
    return {
        "version": VAULT_VERSION,
        "header": {"slots": None, "params": None},
        "db": {"version": DB_VERSION, "entries": entries, "groups": [], "icons_optimized": True},
    }


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate_vault(document: Any) -> list[str]:
    """Return a list of problems (empty when the document is valid).

    Messages identify entries by index only and never include secrets.
    """
    if not isinstance(document, dict):
        return ["top level is not a JSON object"]
    issues: list[str] = []
    if document.get("version") != VAULT_VERSION:
        issues.append(f"unsupported vault version {document.get('version')!r}")
    header = document.get("header")
    if not isinstance(header, dict) or header.get("slots") is not None or header.get("params") is not None:
        issues.append("header must have null 'slots' and 'params' (unencrypted vault)")
    db = document.get("db")
    if not isinstance(db, dict):
        return issues + ["'db' is not a JSON object (encrypted or malformed vault)"]
    if not _is_int(db.get("version")) or not 1 <= db["version"] <= DB_VERSION:
        issues.append(f"unsupported db version {db.get('version')!r}")
    if not isinstance(db.get("groups", []), list):
        issues.append("'db.groups' is not a list")
    entries = db.get("entries")
    if not isinstance(entries, list):
        return issues + ["'db.entries' is not a list"]

    uuids: set[str] = set()
    tokens: set[tuple[Any, ...]] = set()
    for index, entry in enumerate(entries):
        issues.extend(f"entry {index}: {problem}" for problem in _validate_entry(entry, uuids, tokens))
    return issues


def _validate_entry(entry: Any, uuids: set[str], tokens: set[tuple[Any, ...]]) -> list[str]:
    if not isinstance(entry, dict):
        return ["not a JSON object"]
    problems = []
    if entry.get("type") != "totp":
        problems.append(f"unsupported type {entry.get('type')!r}")
    try:
        parsed = uuid.UUID(str(entry.get("uuid")))
        if str(parsed) != entry.get("uuid") or parsed.version != 4:
            problems.append("uuid is not a canonical UUID v4")
        elif entry["uuid"] in uuids:
            problems.append("duplicate uuid")
        uuids.add(str(entry.get("uuid")))
    except ValueError:
        problems.append("uuid is not a valid UUID")
    for key in ("name", "issuer", "note"):
        if not isinstance(entry.get(key), str):
            problems.append(f"'{key}' must be a string")
    if not entry.get("name"):
        problems.append("'name' is empty")
    if not isinstance(entry.get("favorite"), bool):
        problems.append("'favorite' must be a boolean")
    if entry.get("icon") is not None and not isinstance(entry.get("icon"), str):
        problems.append("'icon' must be a string or null")
    if not isinstance(entry.get("groups"), list):
        problems.append("'groups' must be a list")

    info = entry.get("info")
    if not isinstance(info, dict):
        return problems + ["'info' is not a JSON object"]
    secret, algo, digits, period = (info.get(k) for k in ("secret", "algo", "digits", "period"))
    if not isinstance(secret, str) or not isinstance(algo, str) or not _is_int(digits) or not _is_int(period):
        return problems + ["'info' must contain secret/algo (strings) and digits/period (integers)"]
    try:
        parameters = TotpParameters(Algorithm(algo), digits, period)
        self_check(secret, parameters)
    except ValueError:
        problems.append(f"unsupported algorithm {algo!r}")
    except InvalidSecretError as exc:
        problems.append(str(exc))
    key = (secret, algo, digits, period)
    if key in tokens:
        problems.append("duplicate token (same secret and parameters as an earlier entry)")
    tokens.add(key)
    return problems


def entries_match_tokens(document: dict[str, Any], tokens: Iterable[TotpToken]) -> bool:
    """Check the exported entries carry exactly the given tokens."""
    expected = sorted(
        (t.name, t.issuer, t.secret, t.parameters.algorithm.value, t.parameters.digits, t.parameters.period)
        for t in tokens
    )
    actual = sorted(
        (e["name"], e["issuer"], e["info"]["secret"], e["info"]["algo"], e["info"]["digits"], e["info"]["period"])
        for e in document["db"]["entries"]
    )
    return expected == actual


# --------------------------------------------------------------------------
# Password-protected vault
# --------------------------------------------------------------------------

Kdf = Callable[[bytes, bytes, int, int, int, int], bytes]

SLOT_TYPE_PASSWORD = 1
MIN_PASSWORD_LENGTH = 8
_KEY_SIZE = 32
_NONCE_SIZE = 12
_TAG_SIZE = 16
_SALT_SIZE = 32
_HEX_RE = re.compile(r"^[0-9a-fA-F]*$")


@dataclass(frozen=True)
class ScryptParams:
    """Aegis' scrypt cost parameters (CryptoUtils: N=2^15, r=8, p=1)."""

    n: int = 1 << 15
    r: int = 8
    p: int = 1


DEFAULT_SCRYPT = ScryptParams()


def _scrypt(kdf: Kdf | None) -> Kdf:
    # Resolved at call time so the KDF can be substituted in tests on
    # Pythons without OpenSSL scrypt (by a reference validated on RFC 7914).
    return kdf or crypto.scrypt


def _check_scrypt_params(n: Any, r: Any, p: Any) -> None:
    # Importers such as Proton derive log2(N) by counting trailing zeros, so
    # N must be a power of two; r/p bounds keep memory and CPU reasonable.
    if not all(_is_int(v) for v in (n, r, p)) or n < 2 or n & (n - 1) or not 1 <= r <= 32 or not 1 <= p <= 16:
        raise ExportError("invalid scrypt parameters (N must be a power of two; r 1-32; p 1-16)")


def is_encrypted(document: Any) -> bool:
    header = document.get("header") if isinstance(document, dict) else None
    return isinstance(header, dict) and (header.get("slots") is not None or header.get("params") is not None)


def encrypt_vault(
    document: dict[str, Any],
    password: str,
    *,
    params: ScryptParams | None = None,
    kdf: Kdf | None = None,
    random_bytes: Callable[[int], bytes] = os.urandom,
) -> dict[str, Any]:
    """Return a password-protected copy of a plain vault produced by :func:`build_vault`."""
    if not password:
        raise ExportError("an export password is required")
    params = params or DEFAULT_SCRYPT
    _check_scrypt_params(params.n, params.r, params.p)
    master_key = random_bytes(_KEY_SIZE)
    salt = random_bytes(_SALT_SIZE)
    slot_nonce = random_bytes(_NONCE_SIZE)
    db_nonce = random_bytes(_NONCE_SIZE)
    try:
        derived = _scrypt(kdf)(password.encode("utf-8"), salt, params.n, params.r, params.p, _KEY_SIZE)
    except CryptoError as exc:
        raise ExportError(f"cannot derive the export key: {exc}") from exc
    encrypted_key, key_tag = crypto.aes_gcm_encrypt(derived, slot_nonce, master_key)
    plaintext = json.dumps(document["db"], indent=4, ensure_ascii=False).encode("utf-8")
    ciphertext, db_tag = crypto.aes_gcm_encrypt(master_key, db_nonce, plaintext)
    slot = {
        "type": SLOT_TYPE_PASSWORD,
        "uuid": str(uuid.uuid4()),
        "key": encrypted_key.hex(),
        "key_params": {"nonce": slot_nonce.hex(), "tag": key_tag.hex()},
        "n": params.n,
        "r": params.r,
        "p": params.p,
        "salt": salt.hex(),
        "repaired": True,  # password bytes are exact UTF-8 (Aegis issue #95 fix)
        "is_backup": False,
    }
    return {
        "version": VAULT_VERSION,
        "header": {"slots": [slot], "params": {"nonce": db_nonce.hex(), "tag": db_tag.hex()}},
        "db": base64.b64encode(ciphertext).decode("ascii"),
    }


def _hex_field(container: Any, key: str, size: int | None, what: str) -> bytes:
    value = container.get(key) if isinstance(container, dict) else None
    if not isinstance(value, str) or not _HEX_RE.match(value) or len(value) % 2:
        raise ExportError(f"{what} '{key}' is not valid hex")
    data = bytes.fromhex(value)
    if size is not None and len(data) != size:
        raise ExportError(f"{what} '{key}' has length {len(data)}, expected {size}")
    return data


def decrypt_vault(document: Any, password: str, *, kdf: Kdf | None = None) -> dict[str, Any]:
    """Decrypt a password-protected vault into the equivalent plain vault.

    Uses ``slots[0]`` like Proton's importer, and requires it to be a
    password slot. Raises :class:`WrongPasswordError` when the slot key does
    not authenticate and :class:`ExportError` for structural problems.
    """
    if not is_encrypted(document):
        raise ExportError("the vault is not encrypted")
    header = document["header"]
    slots = header.get("slots")
    if not isinstance(slots, list) or not slots or not isinstance(slots[0], dict):
        raise ExportError("encrypted vault has no key slot")
    slot = slots[0]
    if slot.get("type") != SLOT_TYPE_PASSWORD:
        raise ExportError("the first key slot is not a password slot")
    n, r, p = slot.get("n"), slot.get("r"), slot.get("p")
    _check_scrypt_params(n, r, p)
    encrypted_key = _hex_field(slot, "key", _KEY_SIZE, "slot")
    salt = _hex_field(slot, "salt", None, "slot")
    slot_nonce = _hex_field(slot.get("key_params"), "nonce", _NONCE_SIZE, "slot key_params")
    slot_tag = _hex_field(slot.get("key_params"), "tag", _TAG_SIZE, "slot key_params")
    db_nonce = _hex_field(header.get("params"), "nonce", _NONCE_SIZE, "header params")
    db_tag = _hex_field(header.get("params"), "tag", _TAG_SIZE, "header params")
    db = document.get("db")
    if not isinstance(db, str):
        raise ExportError("encrypted vault 'db' is not a base64 string")
    try:
        ciphertext = base64.b64decode(db, validate=True)
    except binascii.Error as exc:
        raise ExportError("encrypted vault 'db' is not valid base64") from exc

    try:
        derived = _scrypt(kdf)(password.encode("utf-8"), salt, n, r, p, _KEY_SIZE)
    except CryptoError as exc:
        raise ExportError(f"cannot derive the vault key: {exc}") from exc
    try:
        master_key = crypto.aes_gcm_decrypt(derived, slot_nonce, encrypted_key, slot_tag)
    except DecryptionError as exc:
        raise WrongPasswordError("incorrect export password") from exc
    try:
        plaintext = crypto.aes_gcm_decrypt(master_key, db_nonce, ciphertext, db_tag)
    except DecryptionError as exc:
        raise ExportError("encrypted vault content failed authentication (file is corrupted)") from exc
    try:
        inner = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExportError("decrypted vault content is not valid UTF-8 JSON") from exc
    return {"version": document.get("version"), "header": {"slots": None, "params": None}, "db": inner}


# --------------------------------------------------------------------------
# File I/O
# --------------------------------------------------------------------------

def synced_location_warning(path: Path) -> str | None:
    resolved = Path(os.path.realpath(Path(path).expanduser()))
    for synced in _SYNCED_DIRS:
        real = Path(os.path.realpath(synced))
        if resolved == real or real in resolved.parents:
            return f"{path} is inside {synced}, which may be synchronised to a cloud service"
    return None


def write_private_file(path: Path, data: bytes, overwrite: bool = False) -> Path:
    """Atomically write ``data`` to ``path`` with mode 0600.

    The content is written to a private temporary file in the same directory,
    fsynced, then moved into place: with ``os.replace`` when overwriting is
    allowed, otherwise with ``os.link`` which fails if the target exists, so
    an existing file is never clobbered by a race.
    """
    path = Path(path).expanduser().absolute()
    if path.is_dir():
        raise ExportError(f"{path} is a directory")
    if not overwrite and (path.exists() or path.is_symlink()):
        raise ExportError(f"{path} already exists; use --force to overwrite it")
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    except OSError as exc:
        raise ExportError(f"cannot create {path.parent}: {exc.strerror}") from exc
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if overwrite:
            os.replace(temp_name, path)
        else:
            try:
                os.link(temp_name, path)
            except FileExistsError as exc:
                raise ExportError(f"{path} already exists; use --force to overwrite it") from exc
        _fsync_directory(path.parent)
    except OSError as exc:
        raise ExportError(f"cannot write {path}: {exc.strerror}") from exc
    finally:
        if os.path.lexists(temp_name):
            os.unlink(temp_name)
    return path


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_vault(path: Path) -> Any:
    path = Path(path).expanduser()
    try:
        with open(path, "rb") as handle:
            if os.fstat(handle.fileno()).st_size > _MAX_EXPORT_SIZE:
                raise ExportError(f"{path} is implausibly large for an export")
            raw = handle.read()
    except FileNotFoundError as exc:
        raise ExportError(f"{path} does not exist") from exc
    except OSError as exc:
        raise ExportError(f"cannot read {path}: {exc.strerror}") from exc
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExportError(f"{path} is not valid UTF-8 JSON") from exc


def export_tokens(
    tokens: tuple[TotpToken, ...],
    path: Path,
    password: str,
    overwrite: bool = False,
    *,
    kdf: Kdf | None = None,
    params: ScryptParams | None = None,
) -> ExportSummary:
    """Build, validate, encrypt, write, re-read, decrypt and re-validate the export."""
    if not tokens:
        raise ExportError("no recovered tokens to export")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ExportError(f"the export password must have at least {MIN_PASSWORD_LENGTH} characters")
    document = build_vault(tokens)
    issues = validate_vault(document)
    if issues:
        raise ExportError("refusing to write an invalid export: " + "; ".join(issues))
    encrypted = encrypt_vault(document, password, params=params, kdf=kdf)
    data = (json.dumps(encrypted, indent=4) + "\n").encode("utf-8")
    written = write_private_file(path, data, overwrite)

    issues = []
    entries = 0
    try:
        reread = decrypt_vault(read_vault(written), password, kdf=kdf)
    except (ExportError, WrongPasswordError) as exc:
        issues = [f"re-read failed: {exc}"]
    else:
        issues = validate_vault(reread)
        if not issues:
            entries = len(reread["db"]["entries"])
            if not entries_match_tokens(reread, tokens):
                issues = ["re-read entries do not match the recovered tokens"]
    if (os.stat(written).st_mode & 0o777) != 0o600:
        issues.append("export file permissions are not 0600")
    return ExportSummary(path=written, entries=entries, validation_issues=tuple(issues))
