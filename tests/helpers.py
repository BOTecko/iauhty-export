"""Shared test helpers for the password-protected export."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Callable, Iterator
from unittest import mock

import scrypt_reference
from synthetic import PASSWORD

from iauhty_export import cli, crypto, exporter

EXPORT_PASSWORD = "export-pass-1234"
# Cheap but valid scrypt cost (N must stay a power of two) for fast tests.
FAST_SCRYPT = exporter.ScryptParams(n=16, r=1, p=1)


@contextmanager
def fast_encryption() -> Iterator[None]:
    """Run export encryption with the RFC 7914 reference scrypt at low cost.

    This lets the full encrypt/decrypt path run on Pythons without OpenSSL
    scrypt. Real ``hashlib.scrypt`` with Aegis' default cost is exercised
    separately where available (see test_exporter / test_integration).
    """
    with mock.patch.object(crypto, "scrypt", scrypt_reference.scrypt), \
            mock.patch.object(exporter, "DEFAULT_SCRYPT", FAST_SCRYPT), \
            mock.patch.object(cli, "encryption_supported", lambda: True):
        yield


def prompts(backup: str = PASSWORD, export: str = EXPORT_PASSWORD,
            repeat: str | None = None) -> Callable[[str], str]:
    """Answer each password prompt by its label, like a user at a terminal."""
    answers = {
        cli.BACKUP_PASSWORD_PROMPT: backup,
        cli.NEW_EXPORT_PASSWORD_PROMPT: export,
        cli.REPEAT_EXPORT_PASSWORD_PROMPT: export if repeat is None else repeat,
        cli.EXPORT_PASSWORD_PROMPT: export,
    }
    return lambda label: answers[label]
