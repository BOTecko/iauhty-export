"""End-to-end orchestration: backup -> Authy records + keychain -> report.

Kept separate from the CLI so the full pipeline can be exercised by tests
without a terminal, and separate from the parsers so they stay free of I/O.
"""

from __future__ import annotations

from dataclasses import dataclass

from .authy import AUTHY_DOMAIN, AUTHY_PREFERENCES, is_authy_service, recover_accounts
from .backup import EncryptedBackup
from .errors import AuthyDataNotFoundError, KeychainUnavailableError
from .keychain import KEYCHAIN_DOMAIN, KEYCHAIN_FILE, extract_generic_passwords
from .models import BackupInfo, RecoveryReport
from .plistutil import load_plist_dict


@dataclass(frozen=True)
class ComponentReport:
    """Availability of the components needed for extraction (no secrets)."""

    available_classes: tuple[int, ...]
    device_bound_classes: tuple[int, ...]
    authy_domain_files: int
    authy_preferences_present: bool
    keychain_present: bool


def inspect_components(info: BackupInfo, password: str) -> ComponentReport:
    with EncryptedBackup.open(info, password) as backup:
        return ComponentReport(
            available_classes=tuple(sorted(backup.keybag.class_keys)),
            device_bound_classes=tuple(sorted(backup.keybag.device_bound_classes)),
            authy_domain_files=backup.count_domain_files(AUTHY_DOMAIN),
            authy_preferences_present=backup.find_file(AUTHY_DOMAIN, AUTHY_PREFERENCES) is not None,
            keychain_present=backup.find_file(KEYCHAIN_DOMAIN, KEYCHAIN_FILE) is not None,
        )


def recover(info: BackupInfo, password: str) -> RecoveryReport:
    """Decrypt only what is needed and return per-account recovery results."""
    with EncryptedBackup.open(info, password) as backup:
        preferences_record = backup.find_file(AUTHY_DOMAIN, AUTHY_PREFERENCES)
        if preferences_record is None:
            raise AuthyDataNotFoundError(
                f"Authy preferences ({AUTHY_DOMAIN}/{AUTHY_PREFERENCES}) are not in this "
                "backup; Authy may not be installed or its data was not backed up"
            )
        preferences = load_plist_dict(backup.read_file(preferences_record), "Authy preferences")

        keychain_record = backup.find_file(KEYCHAIN_DOMAIN, KEYCHAIN_FILE)
        if keychain_record is None:
            raise KeychainUnavailableError("the backup does not contain keychain-backup.plist")
        keychain_data = backup.read_file(keychain_record)
        items, stats = extract_generic_passwords(keychain_data, backup.keybag, is_authy_service)
        del keychain_data

    report = recover_accounts(preferences, items, stats)
    if not report.results:
        raise AuthyDataNotFoundError("Authy preferences contain no account records")
    return report
