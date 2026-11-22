"""Exception hierarchy and process exit codes.

Every exception carries an ``exit_code`` so the CLI can map failures to
stable, documented process exit statuses. Messages must never contain
passwords, keys, secrets or OTP codes.
"""

from __future__ import annotations

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
EXIT_BACKUP_INVALID = 3
EXIT_WRONG_PASSWORD = 4
EXIT_INCOMPATIBLE = 5
EXIT_EXTRACTION_FAILED = 6
EXIT_EXPORT_FAILED = 7
EXIT_PARTIAL = 8


class IauhtyExportError(Exception):
    """Base class for all expected, user-reportable failures."""

    exit_code: int = EXIT_FAILURE


class InputError(IauhtyExportError):
    """Invalid command-line input or environment (e.g. no TTY for password)."""

    exit_code = EXIT_USAGE


class BackupNotFoundError(IauhtyExportError):
    """No backup exists at the requested location."""

    exit_code = EXIT_BACKUP_INVALID


class BackupIncompleteError(IauhtyExportError):
    """The backup directory lacks required components or did not finish."""

    exit_code = EXIT_BACKUP_INVALID


class BackupNotEncryptedError(IauhtyExportError):
    """Unencrypted backups do not contain the keychain, so Authy secrets are absent."""

    exit_code = EXIT_BACKUP_INVALID


class WrongPasswordError(IauhtyExportError):
    """The backup password failed the AES key-wrap integrity check."""

    exit_code = EXIT_WRONG_PASSWORD


class CryptoError(IauhtyExportError):
    """A native cryptographic primitive failed or rejected its input."""

    exit_code = EXIT_EXTRACTION_FAILED


class DecryptionError(CryptoError):
    """Ciphertext could not be decrypted or failed an integrity check."""


class DeviceBoundKeyError(DecryptionError):
    """The data is protected by a class key that also requires the device UID.

    Such keys (keybag WRAP flag 1, e.g. keychain "ThisDeviceOnly" classes)
    are entangled with a hardware key that never leaves the Secure Enclave,
    so they are not recoverable from a backup on another machine.
    """


class IncompatibleFormatError(IauhtyExportError):
    """A data structure does not match any format this tool understands."""

    exit_code = EXIT_INCOMPATIBLE


class KeychainUnavailableError(IauhtyExportError):
    """The keychain backup is missing or cannot be decrypted as a whole."""

    exit_code = EXIT_EXTRACTION_FAILED


class AuthyDataNotFoundError(IauhtyExportError):
    """The backup decrypted correctly but contains no Authy data."""

    exit_code = EXIT_EXTRACTION_FAILED


class InvalidSecretError(IauhtyExportError):
    """A TOTP secret or parameter set failed validation."""

    exit_code = EXIT_INCOMPATIBLE


class ExportError(IauhtyExportError):
    """The export file could not be written or failed validation."""

    exit_code = EXIT_EXPORT_FAILED
