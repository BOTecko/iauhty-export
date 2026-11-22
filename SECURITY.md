# Security Policy

`iauhty-export` handles material that can generate your two-factor codes.
Please treat both vulnerabilities and your own data with care.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's private vulnerability reporting instead: open the repository's
**Security** tab and choose **Report a vulnerability**. If that option is not
available, open a minimal public issue asking a maintainer to enable private
reporting, without including any technical details.

When reporting, include:

- the affected version or commit,
- a description of the issue and its impact,
- steps to reproduce using **synthetic data only**.

**Never include real backups, keychain files, exported JSON files, backup
passwords, TOTP secrets or codes in a report.** Maintainers will never ask
for them.

## How the tool handles sensitive data

| Data | Handling |
| --- | --- |
| Backup and export passwords | Read with `getpass` from the terminal (never CLI arguments), kept only in process memory, never written or logged. |
| Backup files | Opened read-only. Nothing in the backup directory is modified. |
| `Manifest.db` | Decrypted in memory (`sqlite3` `deserialize`, Python 3.11+). Older Pythons use a private `0700` temporary directory that is removed even on errors. |
| Keychain | Decrypted item by item in memory. Only items whose service matches the Authy pattern are kept; nothing is written to disk. |
| Export file | Always a password-protected Aegis vault (scrypt N=2^15, r=8, p=1; AES-256-GCM), written atomically with mode `0600` in `~/IauhtyExport/` (mode `0700`) by default. The export password must have at least 8 characters. |
| Recovery report | Same permissions as the export. Contains account names and failure reasons, never secrets. |
| Terminal output | Statistics only: no secrets, codes or account names. |
| Network | None. The tool makes no network connections and has no telemetry. |

### Known limitations

- Python cannot reliably wipe memory: immutable `bytes`/`str` objects holding
  keys or secrets live until garbage collection. Native CommonCrypto output
  buffers are zeroed after use, but copies in Python objects remain until
  the process exits. Run the tool on a machine you trust.
- The export is encrypted, but it still holds every secret, and its strength
  depends on the password you choose. Anyone with the file and the password
  can generate your codes. Delete it after a confirmed import, and do not
  store it in synchronised folders (Desktop, Documents, iCloud Drive,
  Dropbox, ...). The tool warns if you choose one.
- The recovery report is not encrypted. It contains account names and reasons,
  never secrets. Delete it together with the export.
