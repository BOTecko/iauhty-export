# iauhty-export

**English** | [Português (Brasil)](README.pt-BR.md)

[![CI](https://github.com/BOTecko/iauhty-export/actions/workflows/ci.yml/badge.svg)](https://github.com/BOTecko/iauhty-export/actions/workflows/ci.yml)

Recovers Authy TOTP secrets from an encrypted iPhone backup made by Finder on
macOS and exports them as a password-protected Aegis vault, which can be
imported into any Aegis-compatible authenticator. Tested with Proton
Authenticator.

Runs locally with the Python standard library only. The backup is never modified.

> Delete the export once the import is finished: it contains all your 2FA secrets.

## Requirements

- macOS
- Python 3.12+ ([python.org](https://www.python.org/downloads/macos/))
- An encrypted Finder backup of the iPhone with Authy installed, and its password
- Full Disk Access for the terminal (System Settings ▸ Privacy & Security)

## Usage

```bash
git clone https://github.com/BOTecko/iauhty-export.git && cd iauhty-export
```

```bash
python3 -m iauhty_export inspect --unlock
```

```bash
python3 -m iauhty_export extract
```

`extract` asks for the backup password and a new password for the export, then
writes `~/IauhtyExport/iauhty-export.json` and a report next to it. Import the
file into your authenticator (Proton Authenticator: Settings ▸ Import ▸ Aegis),
check the codes, then delete both files.

| Command | Description |
| --- | --- |
| `list` | List local backups. |
| `inspect [--unlock]` | Show backup details; with `--unlock`, check the Authy data. |
| `extract [--output FILE] [--force]` | Recover the tokens and write the encrypted export. |
| `verify --file FILE` | Validate an Aegis vault without showing secrets. |

`--backup PATH` selects a specific backup; by default the newest encrypted one
is used.

## How it works

- The backup keybag is unlocked with the backup password; `Manifest.db`, the
  Authy preferences and the keychain are decrypted in memory.
- Authy keeps one record per account in
  `group.authy.128FD4.plist` and the secret in a keychain item named
  `Google<id>App`. Authy does not store algorithm or period; SHA1 and 30 s are used.
- The export follows the Aegis vault format: one password slot (scrypt) and
  entries encrypted with AES-256-GCM.

## Limitations

- Authy-native tokens are not supported.
- Keychain items bound to the original device ("ThisDeviceOnly") cannot be recovered.
- macOS only.

## Development

```bash
python3 -m unittest discover -s tests -v
```

Tests use synthetic backups and published NIST/RFC vectors. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Not affiliated with Twilio, Authy, Apple, Proton or Aegis.
