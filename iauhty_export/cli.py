"""Command-line interface: argument parsing, prompting and presentation only."""

from __future__ import annotations

import argparse
import getpass
import shlex
import sys
from collections import Counter
from pathlib import Path
from typing import Callable, Sequence, TextIO

from . import __version__, crypto
from .backup import DEFAULT_BACKUP_ROOT, discover_backups, require_usable, select_backup
from .errors import (
    EXIT_EXTRACTION_FAILED,
    EXIT_OK,
    EXIT_PARTIAL,
    IauhtyExportError,
    ExportError,
    InputError,
)
from .exporter import (
    DEFAULT_OUTPUT_DIR,
    DEFAULT_OUTPUT_NAME,
    MIN_PASSWORD_LENGTH,
    decrypt_vault,
    export_tokens,
    is_encrypted,
    read_vault,
    synced_location_warning,
    validate_vault,
    write_private_file,
)
from .models import AccountStatus, BackupInfo, ExportSummary, RecoveryReport
from .pipeline import inspect_components, recover

PasswordPrompt = Callable[[str], str]

BACKUP_PASSWORD_PROMPT = "iPhone backup password (input hidden): "
NEW_EXPORT_PASSWORD_PROMPT = "New password for the export file (input hidden): "
REPEAT_EXPORT_PASSWORD_PROMPT = "Repeat the export password: "
EXPORT_PASSWORD_PROMPT = "Export file password (input hidden): "

_FAILURE_STATUSES = (
    AccountStatus.SECRET_NOT_FOUND,
    AccountStatus.AMBIGUOUS_SECRET,
    AccountStatus.INVALID_SECRET,
)


def prompt_password(label: str) -> str:
    """Read a password from the controlling terminal without echo."""
    if not sys.stdin.isatty():
        raise InputError("passwords must be typed in an interactive terminal")
    password = getpass.getpass(label)
    if not password:
        raise InputError("an empty password was entered")
    return password


def encryption_supported() -> bool:
    """Encrypted exports need Python 3.12+ with OpenSSL scrypt (``hashlib.scrypt``)."""
    return sys.version_info >= (3, 12) and crypto.scrypt_available()


def require_encryption_support() -> None:
    if not encryption_supported():
        version = ".".join(map(str, sys.version_info[:3]))
        raise InputError(
            f"encrypted exports require Python 3.12 or newer with OpenSSL scrypt support; "
            f"this is Python {version} at {sys.executable}. Install Python 3.12+ "
            f"(e.g. from python.org) and run the command with it, e.g. 'python3 -m iauhty_export'."
        )


def ask_new_export_password(prompt: PasswordPrompt) -> str:
    password = prompt(NEW_EXPORT_PASSWORD_PROMPT)
    if len(password) < MIN_PASSWORD_LENGTH:
        raise InputError(f"the export password must have at least {MIN_PASSWORD_LENGTH} characters")
    if prompt(REPEAT_EXPORT_PASSWORD_PROMPT) != password:
        raise InputError("the export passwords do not match")
    return password


# --------------------------------------------------------------------------
# Presentation helpers (never print secrets or codes)
# --------------------------------------------------------------------------

def _describe_backup(info: BackupInfo) -> list[str]:
    date = info.backup_date.astimezone().strftime("%Y-%m-%d %H:%M %Z") if info.backup_date else "unknown"
    encrypted = {True: "yes", False: "no", None: "unknown"}[info.is_encrypted]
    lines = [
        f"  Path:       {info.path}",
        f"  Device:     {info.device_name or 'unknown'} ({info.product_type or 'unknown model'})",
        f"  iOS:        {info.ios_version or 'unknown'}",
        f"  Date:       {date}",
        f"  Encrypted:  {encrypted}",
        f"  Snapshot:   {info.snapshot_state or 'unknown'}",
    ]
    if info.problems:
        lines += [f"  Problem:    {problem}" for problem in info.problems]
    if info.is_usable:
        lines.append("  Status:     usable")
    elif not info.problems:
        lines.append("  Status:     not usable (backup is not encrypted)")
    else:
        lines.append("  Status:     not usable")
    return lines


def format_report_details(report: RecoveryReport, summary: ExportSummary | None) -> str:
    """Private, per-account report (names and reasons, never secrets)."""
    lines = ["iauhty-export recovery report", "", "Per-account results:"]
    for result in report.results:
        account = result.account
        label = account.name or "(no name)"
        issuer = account.issuer or "(no issuer)"
        lines.append(f"- [{result.status.value}] id={account.account_id} name={label!r} issuer={issuer!r}")
        if result.detail:
            lines.append(f"    reason: {result.detail}")
        for warning in result.warnings:
            lines.append(f"    warning: {warning}")
        if result.token is not None:
            p = result.token.parameters
            lines.append(f"    parameters: {p.algorithm.value}, {p.digits} digits, {p.period}s")
    lines += ["", *format_statistics(report, summary)]
    return "\n".join(lines) + "\n"


def format_statistics(report: RecoveryReport, summary: ExportSummary | None) -> list[str]:
    k = report.keychain
    secrets = report.count(AccountStatus.RECOVERED) + report.count(AccountStatus.DUPLICATE)
    not_recovered = sum(report.count(status) for status in _FAILURE_STATUSES)
    lines = [
        "Summary:",
        f"  Authy accounts identified:    {len(report.results)}",
        f"  Secrets recovered:            {secrets}",
        f"  Entries exported:             {summary.entries if summary else 0}",
        f"  Duplicates skipped:           {report.count(AccountStatus.DUPLICATE)}",
        f"  Accounts not recovered:       {not_recovered}",
        f"  Incompatible entries:         {report.count(AccountStatus.INCOMPATIBLE)}",
        f"  Keychain generic passwords:   {k.total} total, {k.decrypted} decrypted, "
        f"{k.device_bound} device-bound, {k.unsupported} unsupported, {k.corrupted} corrupted",
    ]
    if report.orphan_secrets:
        lines.append(f"  Authy secrets without account record (not exported): {report.orphan_secrets}")
    reasons = Counter(r.status.value for r in report.results if r.status is not AccountStatus.RECOVERED)
    for status, count in sorted(reasons.items()):
        lines.append(f"  Reason '{status}': {count}")
    if summary is not None:
        if summary.validation_issues:
            lines.append("  JSON validation:              FAILED")
            lines += [f"    - {issue}" for issue in summary.validation_issues]
        else:
            lines.append("  JSON validation:              passed (structure, parameters, re-read)")
        lines.append(f"  Export file:                  {summary.path}")
    return lines


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_list(args: argparse.Namespace, out: TextIO, _prompt: PasswordPrompt) -> int:
    backups = discover_backups(Path(args.root).expanduser())
    if not backups:
        print(f"No backups found in {args.root}", file=out)
        return EXIT_OK
    for index, info in enumerate(backups, 1):
        print(f"[{index}] {info.identifier}", file=out)
        for line in _describe_backup(info):
            print(line, file=out)
    return EXIT_OK


def cmd_inspect(args: argparse.Namespace, out: TextIO, prompt: PasswordPrompt) -> int:
    info = select_backup(args.backup, Path(args.root).expanduser())
    print(f"Backup {info.identifier}", file=out)
    for line in _describe_backup(info):
        print(line, file=out)
    require_usable(info)
    if not args.unlock:
        print("Run with --unlock to check the Authy data and keychain (requires the password).", file=out)
        return EXIT_OK
    print("Deriving keys from the password (this can take a few seconds)...", file=out, flush=True)
    components = inspect_components(info, prompt(BACKUP_PASSWORD_PROMPT))
    print("Components:", file=out)
    print(f"  Keybag classes unlocked:   {', '.join(map(str, components.available_classes))}", file=out)
    device_bound = ", ".join(map(str, components.device_bound_classes)) or "none"
    print(f"  Device-bound classes:      {device_bound} (not recoverable off-device)", file=out)
    print(f"  Authy app-group files:     {components.authy_domain_files}", file=out)
    print(f"  Authy preferences:         {'present' if components.authy_preferences_present else 'MISSING'}", file=out)
    print(f"  Keychain backup:           {'present' if components.keychain_present else 'MISSING'}", file=out)
    return EXIT_OK


def _shell_quote(path: Path) -> str:
    return shlex.quote(str(path))


def _default_report_path(output: Path) -> Path:
    return output.with_name(output.stem + "-report.txt")


def cmd_extract(args: argparse.Namespace, out: TextIO, prompt: PasswordPrompt) -> int:
    require_encryption_support()
    output = Path(args.output).expanduser() if args.output else DEFAULT_OUTPUT_DIR / DEFAULT_OUTPUT_NAME
    report_path = _default_report_path(output)
    for path in (output, report_path):
        if not args.force and (path.exists() or path.is_symlink()):
            raise ExportError(f"{path} already exists; use --force to overwrite it")
    warning = synced_location_warning(output)
    if warning:
        print(f"Warning: {warning}.", file=out)

    info = select_backup(args.backup, Path(args.root).expanduser())
    require_usable(info)
    print(f"Using backup {info.identifier} ({info.device_name or 'unknown device'}, iOS {info.ios_version or '?'})",
          file=out)
    backup_password = prompt(BACKUP_PASSWORD_PROMPT)
    print("The export file will be encrypted. Choose a password for it; the app "
          "you import into will ask for it.", file=out)
    export_password = ask_new_export_password(prompt)
    print("Deriving keys and decrypting (this can take a few seconds)...", file=out, flush=True)
    report = recover(info, backup_password)
    del backup_password

    summary = None
    if report.tokens:
        summary = export_tokens(report.tokens, output, export_password, overwrite=args.force)
    del export_password
    write_private_file(report_path, format_report_details(report, summary).encode("utf-8"), overwrite=args.force)

    for line in format_statistics(report, summary):
        print(line, file=out)
    print(f"  Detailed report:              {report_path}", file=out)
    print("", file=out)
    if summary is None:
        print("No token could be recovered; no export file was written.", file=out)
        return EXIT_EXTRACTION_FAILED
    if summary.validation_issues:
        return ExportError.exit_code
    print("Next steps:", file=out)
    print("  1. Import the file into an authenticator that supports encrypted Aegis vaults", file=out)
    print("     (e.g. Proton Authenticator: Settings > Import > Aegis)", file=out)
    print("     and enter the export password when asked.", file=out)
    print("  2. Compare a few codes with Authy and sign in to a few services.", file=out)
    print("  3. Keep Authy installed until every account works in the new app.", file=out)
    print("", file=out)
    print("IMPORTANT: after importing, delete the export file and the report. Even encrypted,", file=out)
    print("the export holds all your 2FA secrets and is only as strong as its password:", file=out)
    print(f"  rm {_shell_quote(summary.path)} {_shell_quote(report_path)}", file=out)
    complete = len(report.tokens) + report.count(AccountStatus.DUPLICATE) == len(report.results)
    return EXIT_OK if complete else EXIT_PARTIAL


def cmd_verify(args: argparse.Namespace, out: TextIO, prompt: PasswordPrompt) -> int:
    path = Path(args.file).expanduser()
    document = read_vault(path)
    encrypted = is_encrypted(document)
    if encrypted:
        require_encryption_support()
        document = decrypt_vault(document, prompt(EXPORT_PASSWORD_PROMPT))
    issues = validate_vault(document)
    if issues:
        print(f"{path}: INVALID", file=out)
        for issue in issues:
            print(f"  - {issue}", file=out)
        return ExportError.exit_code
    entries = document["db"]["entries"]
    shapes = Counter((e["info"]["algo"], e["info"]["digits"], e["info"]["period"]) for e in entries)
    kind = "password-protected" if encrypted else "UNENCRYPTED"
    print(f"{path}: valid {kind} Aegis vault with {len(entries)} TOTP entries", file=out)
    for (algo, digits, period), count in sorted(shapes.items()):
        print(f"  {count} x {algo}, {digits} digits, {period}s period", file=out)
    print("All secrets decode as base32 and generate RFC 6238 codes locally.", file=out)
    print("This does not prove the services will accept the codes; confirm after importing.", file=out)
    return EXIT_OK


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iauhty_export",
        description="Recover Authy TOTP secrets from an encrypted iPhone backup and export "
                    "them as a password-protected Aegis vault (Aegis, Proton Authenticator, ...).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    root_help = f"folder containing backups (default: {DEFAULT_BACKUP_ROOT})"

    p_list = sub.add_parser("list", help="list local iPhone backups")
    p_list.add_argument("--root", default=str(DEFAULT_BACKUP_ROOT), help=root_help)
    p_list.set_defaults(handler=cmd_list)

    p_inspect = sub.add_parser("inspect", help="show backup metadata and component availability")
    p_inspect.add_argument("--backup", type=Path, help="backup directory (default: newest usable)")
    p_inspect.add_argument("--root", default=str(DEFAULT_BACKUP_ROOT), help=root_help)
    p_inspect.add_argument("--unlock", action="store_true",
                           help="prompt for the password and check Authy data and keychain presence")
    p_inspect.set_defaults(handler=cmd_inspect)

    p_extract = sub.add_parser("extract", help="recover Authy tokens and write a password-protected Aegis vault")
    p_extract.add_argument("--backup", type=Path, help="backup directory (default: newest usable)")
    p_extract.add_argument("--root", default=str(DEFAULT_BACKUP_ROOT), help=root_help)
    p_extract.add_argument("--output", type=Path,
                           help=f"export file (default: {DEFAULT_OUTPUT_DIR / DEFAULT_OUTPUT_NAME})")
    p_extract.add_argument("--force", action="store_true", help="overwrite existing output files")
    p_extract.set_defaults(handler=cmd_extract)

    p_verify = sub.add_parser("verify", help="validate an Aegis vault (asks for its password if encrypted)")
    p_verify.add_argument("--file", required=True, type=Path, help="export file to validate")
    p_verify.set_defaults(handler=cmd_verify)
    return parser


def main(argv: Sequence[str] | None = None, out: TextIO | None = None,
         prompt: PasswordPrompt = prompt_password) -> int:
    out = out or sys.stdout
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args, out, prompt)
    except IauhtyExportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
