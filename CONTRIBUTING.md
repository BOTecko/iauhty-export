# Contributing

Thanks for helping! This project is deliberately small: Python standard library
only, macOS CommonCrypto for AES, and `unittest` for tests.

## Set up

```bash
git clone <your fork URL>
cd iauhty-export
python3 --version   # 3.12 or newer (python.org build, with OpenSSL scrypt)
```

There is nothing to install. No virtual environment or `pip install` is needed.

## Run the tests

```bash
python3 -m unittest discover -s tests -v
```

The tests build synthetic, fully encrypted iOS backups at runtime
(`tests/synthetic.py`) and exercise the real parsing and decryption code.
Encrypted-export tests use `tests/helpers.py`, which swaps in a pure-Python
scrypt checked against RFC 7914 at a low cost, so they run on any Python. Tests
of the real `hashlib.scrypt` are skipped when it is unavailable.
Cryptographic primitives are checked against published NIST/RFC vectors.

## Project conventions

- **No third-party dependencies.** CI rejects non-stdlib imports.
- **Never implement AES in Python.** Use `iauhty_export.crypto`, which wraps
  CommonCrypto. `ctypes` code stays in `_commoncrypto.py`.
- Keep parsing pure and I/O at the edges (`backup.py`, `exporter.py`, `cli.py`).
- Use type hints, small functions and frozen dataclasses for data passed
  between layers.
- Raise the specific exceptions in `errors.py`. Don't use bare `except Exception`.
- Never put secrets, keys, passwords or OTP codes in messages, `repr`s or output.
- Comments explain *why*, especially in binary parsing and crypto.
- Mocks may isolate the operating system (e.g. simulate a full disk) but must
  never fake cryptographic success.

## Issues

When reporting a problem, include your macOS version, Python version, the
iOS version of the backup, the Authy app version and the **non-sensitive**
output of `python3 -m iauhty_export inspect --unlock`.

**Never attach backups, keychain files, exported JSON, recovery reports with
account names, passwords, secrets or codes.** For security issues, follow
[SECURITY.md](SECURITY.md).

## Pull requests

1. Open an issue first for larger changes.
2. Add or update tests. Use fictitious data only.
3. Make sure `python3 -m unittest discover -s tests -v` passes.
4. Keep the change focused and explain the reasoning in the PR description.
