"""End-to-end tests: synthetic encrypted backup -> CLI -> encrypted Aegis vault."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from helpers import EXPORT_PASSWORD, fast_encryption, prompts
from synthetic import PASSWORD, SECRET_A, SECRET_B, SECRET_C, BackupBuilder, standard_authy_backup

from iauhty_export import cli, errors, exporter
from iauhty_export.backup import read_backup_info
from iauhty_export.cli import main
from iauhty_export.models import AccountStatus
from iauhty_export.pipeline import recover


def tree_digest(root: Path) -> dict[str, str]:
    digests = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            info = path.stat()
            digests[str(path.relative_to(root))] = (
                hashlib.sha256(path.read_bytes()).hexdigest() + f":{info.st_mtime_ns}:{stat.S_IMODE(info.st_mode)}"
            )
    return digests


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.base = Path(cls._tmp.name)
        cls.backups = cls.base / "backups"
        cls.builder = standard_authy_backup(cls.backups)
        cls.builder.build()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def run_cli(self, *argv: str, prompt=None) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stderr(err), fast_encryption():
            code = main(list(argv), out=out, prompt=prompt or prompts())
        return code, out.getvalue(), err.getvalue()

    def assert_no_secrets(self, *texts: str) -> None:
        for text in texts:
            for secret in (SECRET_A, SECRET_B, SECRET_C, SECRET_B.lower(), PASSWORD, EXPORT_PASSWORD):
                self.assertNotIn(secret, text)

    def test_pipeline_recovers_expected_accounts(self) -> None:
        report = recover(read_backup_info(self.builder.path), PASSWORD)
        statuses = {r.account.account_id: r.status for r in report.results}
        self.assertEqual(statuses, {
            "1001": AccountStatus.RECOVERED,
            "1002": AccountStatus.RECOVERED,
            "1003": AccountStatus.DUPLICATE,
            "1004": AccountStatus.SECRET_NOT_FOUND,
            "1005": AccountStatus.INVALID_SECRET,
            "1006": AccountStatus.INCOMPATIBLE,
            "1007": AccountStatus.SECRET_NOT_FOUND,
            "1008": AccountStatus.RECOVERED,
        })
        self.assertEqual({t.secret for t in report.tokens}, {SECRET_A, SECRET_B, SECRET_C})
        self.assertEqual(report.orphan_secrets, 1)
        self.assertEqual((report.keychain.total, report.keychain.device_bound), (9, 1))

    def test_extract_and_verify_end_to_end(self) -> None:
        before = tree_digest(self.backups)
        output = self.base / "export" / "iauhty-export.json"
        code, out, err = self.run_cli("extract", "--root", str(self.backups), "--output", str(output))
        self.assertEqual(code, errors.EXIT_PARTIAL, err)
        self.assertIn("Authy accounts identified:    8", out)
        self.assertIn("Entries exported:             3", out)
        self.assertIn("JSON validation:              passed", out)
        self.assertIn("delete the export file", out)
        self.assert_no_secrets(out, err)

        raw = output.read_text(encoding="utf-8")
        self.assert_no_secrets(raw)  # nothing sensitive in clear text
        stored = json.loads(raw)
        self.assertTrue(exporter.is_encrypted(stored))
        self.assertEqual(stored["header"]["slots"][0]["type"], 1)
        with fast_encryption():
            document = exporter.decrypt_vault(stored, EXPORT_PASSWORD)
        entries = {e["name"]: e for e in document["db"]["entries"]}
        self.assertEqual(set(entries), {"alice@example.com", "bob", "carol"})
        self.assertEqual(entries["bob"]["info"], {"secret": SECRET_B, "algo": "SHA1", "digits": 8, "period": 30})
        self.assertEqual(entries["carol"]["info"]["algo"], "SHA256")
        self.assertEqual(entries["carol"]["info"]["period"], 60)
        self.assertEqual(stat.S_IMODE(os.stat(output).st_mode), 0o600)

        report_file = output.with_name("iauhty-export-report.txt")
        report_text = report_file.read_text()
        self.assertEqual(stat.S_IMODE(os.stat(report_file).st_mode), 0o600)
        self.assertIn("[secret_not_found] id=1007", report_text)
        self.assert_no_secrets(report_text)

        code, out, _ = self.run_cli("verify", "--file", str(output))
        self.assertEqual(code, errors.EXIT_OK)
        self.assertIn("valid password-protected Aegis vault with 3 TOTP entries", out)
        self.assert_no_secrets(out)

        code, _, err = self.run_cli("verify", "--file", str(output), prompt=prompts(export="not-the-password"))
        self.assertEqual(code, errors.EXIT_WRONG_PASSWORD)
        self.assertIn("incorrect export password", err)

        # Re-running without --force must not touch the existing export.
        code, _, err = self.run_cli("extract", "--root", str(self.backups), "--output", str(output))
        self.assertEqual(code, errors.EXIT_EXPORT_FAILED)
        self.assertIn("already exists", err)

        self.assertEqual(tree_digest(self.backups), before, "backup directory was modified")

    def test_list_and_inspect(self) -> None:
        code, out, _ = self.run_cli("list", "--root", str(self.backups))
        self.assertEqual(code, 0)
        self.assertIn("Synthetic iPhone", out)
        self.assertIn("usable", out)
        code, out, _ = self.run_cli("inspect", "--root", str(self.backups), "--unlock")
        self.assertEqual(code, 0)
        self.assertIn("Authy preferences:         present", out)
        self.assertIn("Keychain backup:           present", out)
        self.assertIn("Device-bound classes:      5, 9, 10, 11, 19", out)

    def test_wrong_password_exit_code(self) -> None:
        code, _, err = self.run_cli("extract", "--root", str(self.backups),
                                    "--output", str(self.base / "never.json"), prompt=prompts(backup="wrong"))
        self.assertEqual(code, errors.EXIT_WRONG_PASSWORD)
        self.assertIn("incorrect backup password", err)
        self.assertFalse((self.base / "never.json").exists())

    def test_verify_rejects_invalid_files(self) -> None:
        bad = self.base / "bad.json"
        bad.write_text(json.dumps({"version": 1, "header": {"slots": [], "params": {}}, "db": "x"}))
        code, _, err = self.run_cli("verify", "--file", str(bad))
        self.assertEqual(code, errors.EXIT_EXPORT_FAILED)
        self.assertIn("no key slot", err)
        plain = self.base / "plain.json"
        plain.write_text(json.dumps({"version": 1, "header": {"slots": None, "params": None}, "db": "x"}))
        code, out, _ = self.run_cli("verify", "--file", str(plain))
        self.assertEqual(code, errors.EXIT_EXPORT_FAILED)
        self.assertIn("INVALID", out)

    def test_export_password_is_mandatory_and_checked(self) -> None:
        output = self.base / "pw" / "out.json"
        cases = (
            (prompts(export="short"), "at least 8 characters"),
            (prompts(repeat="something-else"), "do not match"),
        )
        for prompt, message in cases:
            with self.subTest(message=message):
                code, _, err = self.run_cli("extract", "--root", str(self.backups), "--output", str(output),
                                            prompt=prompt)
                self.assertEqual(code, errors.EXIT_USAGE)
                self.assertIn(message, err)
                self.assertFalse(output.parent.exists())

    def test_extract_requires_python_312_with_scrypt(self) -> None:
        asked = []
        out, err = io.StringIO(), io.StringIO()
        with redirect_stderr(err), mock.patch.object(cli, "encryption_supported", lambda: False):
            code = main(["extract", "--root", str(self.backups), "--output", str(self.base / "x.json")],
                        out=out, prompt=lambda label: asked.append(label) or PASSWORD)
        self.assertEqual(code, errors.EXIT_USAGE)
        self.assertIn("Python 3.12", err.getvalue())
        self.assertEqual(asked, [])  # fails before asking for any password

    @unittest.skipUnless(cli.encryption_supported(), "needs Python 3.12+ with OpenSSL scrypt")
    def test_real_scrypt_export_round_trip(self) -> None:
        output = self.base / "real" / "out.json"
        out, err = io.StringIO(), io.StringIO()
        with redirect_stderr(err):
            code = main(["extract", "--root", str(self.backups), "--output", str(output)],
                        out=out, prompt=prompts())
        self.assertEqual(code, errors.EXIT_PARTIAL, err.getvalue())
        slot = json.loads(output.read_text())["header"]["slots"][0]
        self.assertEqual((slot["n"], slot["r"], slot["p"]), (32768, 8, 1))
        with redirect_stderr(err):
            code = main(["verify", "--file", str(output)], out=out, prompt=prompts())
        self.assertEqual(code, errors.EXIT_OK, err.getvalue())


class IntegrationFailureTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def extract(self, backup: Path) -> tuple[int, str]:
        err = io.StringIO()
        with redirect_stderr(err), fast_encryption():
            code = main(["extract", "--backup", str(backup), "--output", str(self.root / "o.json")],
                        out=io.StringIO(), prompt=prompts())
        return code, err.getvalue()

    def test_unencrypted_backup(self) -> None:
        builder = standard_authy_backup(self.root, encrypted=False)
        code, err = self.extract(builder.build())
        self.assertEqual(code, errors.EXIT_BACKUP_INVALID)
        self.assertIn("not encrypted", err)

    def test_backup_without_authy(self) -> None:
        builder = BackupBuilder(self.root)
        builder.add_file("HomeDomain", "x", b"y")
        code, err = self.extract(builder.build())
        self.assertEqual(code, errors.EXIT_EXTRACTION_FAILED)
        self.assertIn("Authy preferences", err)

    def test_no_recoverable_token_writes_no_export(self) -> None:
        builder = BackupBuilder(self.root)
        builder.add_authy({"1": {"name": "x", "digits": 6}}, [])
        code, _ = self.extract(builder.build())
        self.assertEqual(code, errors.EXIT_EXTRACTION_FAILED)
        self.assertFalse((self.root / "o.json").exists())
        self.assertTrue((self.root / "o-report.txt").exists())

    def test_all_recovered_exit_ok(self) -> None:
        from synthetic import authy_item
        builder = BackupBuilder(self.root)
        builder.add_authy({"1": {"name": "x", "original_issuer": "I", "digits": 6}},
                          [authy_item(builder.keybag, "1", SECRET_A)])
        code, err = self.extract(builder.build())
        self.assertEqual(code, errors.EXIT_OK, err)


if __name__ == "__main__":
    unittest.main()
