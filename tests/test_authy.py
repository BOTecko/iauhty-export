from __future__ import annotations

import plistlib
import unittest

from synthetic import SECRET_A, SECRET_B, SECRET_C

from iauhty_export.authy import is_authy_service, parse_accounts, recover_accounts
from iauhty_export.models import AccountStatus, Algorithm, KeychainItem, KeychainStats


def item(account_id: str, secret: str | bytes) -> KeychainItem:
    data = secret.encode() if isinstance(secret, str) else secret
    return KeychainItem(f"Google{account_id}App", None, None, data)


def statuses(report) -> dict[str, AccountStatus]:
    return {r.account.account_id: r.status for r in report.results}


class ServicePatternTests(unittest.TestCase):
    def test_pattern(self) -> None:
        self.assertTrue(is_authy_service("Google123App"))
        for other in ("Google123", "GoogleApp", "GoogleabcApp", "xGoogle1App", "Google1Appx"):
            self.assertFalse(is_authy_service(other))


class ParseAccountsTests(unittest.TestCase):
    def test_only_numeric_keys_are_accounts(self) -> None:
        prefs = {"2": {"name": "b"}, "10": {"name": "c"}, "1": {"name": "a"},
                 "LastSync": "x", "": {}, "1.5": {}}
        self.assertEqual([a.account_id for a, _ in parse_accounts(prefs)], ["1", "2", "10"])

    def test_keyed_archive_record(self) -> None:
        uid = plistlib.UID
        archive = plistlib.dumps({
            "$archiver": "NSKeyedArchiver", "$version": 100000, "$top": {"root": uid(1)},
            "$objects": ["$null", {"$class": uid(4), "NS.keys": [uid(2), uid(3)], "NS.objects": [uid(5), uid(6)]},
                         "name", "digits", {"$classname": "NSDictionary"}, "keyed", 8],
        }, fmt=plistlib.FMT_BINARY)
        [(account, problem)] = parse_accounts({"5": archive})
        self.assertIsNone(problem)
        self.assertEqual((account.name, account.digits), ("keyed", 8))

    def test_unrecognised_record(self) -> None:
        [(_, problem)] = parse_accounts({"5": 42})
        self.assertIsNotNone(problem)


class RecoverTests(unittest.TestCase):
    def test_multiple_accounts(self) -> None:
        prefs = {
            "1": {"name": "alice", "original_issuer": "Example", "digits": 6},
            "2": {"name": "bob", "original_issuer": "Other", "digits": 8, "period": 60, "algorithm": "sha-512"},
        }
        report = recover_accounts(prefs, [item("1", SECRET_A), item("2", SECRET_B)], KeychainStats())
        self.assertEqual(statuses(report), {"1": AccountStatus.RECOVERED, "2": AccountStatus.RECOVERED})
        first, second = report.tokens
        self.assertEqual((first.name, first.issuer, first.secret), ("alice", "Example", SECRET_A))
        self.assertEqual(first.parameters.assumed, ("algorithm", "period"))
        self.assertEqual((second.parameters.algorithm, second.parameters.digits, second.parameters.period),
                         (Algorithm.SHA512, 8, 60))
        self.assertEqual(second.parameters.assumed, ())
        self.assertNotIn(SECRET_A, repr(first))

    def test_duplicates(self) -> None:
        prefs = {"1": {"name": "a", "digits": 6}, "2": {"name": "b", "digits": 6}, "3": {"name": "c", "digits": 8}}
        report = recover_accounts(prefs, [item("1", SECRET_A), item("2", SECRET_A.lower()), item("3", SECRET_A)],
                                  KeychainStats())
        self.assertEqual(statuses(report), {"1": AccountStatus.RECOVERED, "2": AccountStatus.DUPLICATE,
                                            "3": AccountStatus.RECOVERED})
        self.assertEqual(len(report.tokens), 2)

    def test_missing_issuer_and_name(self) -> None:
        prefs = {"1": {"digits": 6, "original_issuer": "OnlyIssuer"}, "2": {"digits": 6}}
        report = recover_accounts(prefs, [item("1", SECRET_A), item("2", SECRET_B)], KeychainStats())
        names = [(t.name, t.issuer) for t in report.tokens]
        self.assertEqual(names, [("OnlyIssuer", "OnlyIssuer"), ("Authy account 2", "")])
        self.assertTrue(all(r.warnings for r in report.results))

    def test_missing_digits_uses_documented_default(self) -> None:
        report = recover_accounts({"1": {"name": "x"}}, [item("1", SECRET_A)], KeychainStats())
        self.assertEqual(report.tokens[0].parameters.digits, 6)
        self.assertIn("digits", report.tokens[0].parameters.assumed)

    def test_failures_are_individual(self) -> None:
        prefs = {
            "1": {"name": "ok", "digits": 6},
            "2": {"name": "missing", "digits": 6},
            "3": {"name": "bad base32", "digits": 6},
            "4": {"name": "hex", "digits": 7},
            "5": {"name": "binary", "digits": 6},
            "6": {"name": "ambiguous", "digits": 6},
            "7": {"name": "ten digits", "digits": 10},
            "8": {"name": "md5", "digits": 6, "algorithm": "MD5"},
            "9": {"name": "short", "digits": 6},
            "10": "not a dict",
        }
        items = [item("1", SECRET_A), item("3", "not base32!"), item("4", "00112233445566778899aabbccddeeff"),
                 item("5", b"\xff\xfe"), item("6", SECRET_A), item("6", SECRET_B), item("7", SECRET_B),
                 item("8", SECRET_C), item("9", "JBSWY3DP"), item("777", SECRET_C)]
        report = recover_accounts(prefs, items, KeychainStats(total=12, device_bound=2))
        self.assertEqual(statuses(report), {
            "1": AccountStatus.RECOVERED,
            "2": AccountStatus.SECRET_NOT_FOUND,
            "3": AccountStatus.INVALID_SECRET,
            "4": AccountStatus.INCOMPATIBLE,
            "5": AccountStatus.INVALID_SECRET,
            "6": AccountStatus.AMBIGUOUS_SECRET,
            "7": AccountStatus.INCOMPATIBLE,
            "8": AccountStatus.INCOMPATIBLE,
            "9": AccountStatus.INVALID_SECRET,
            "10": AccountStatus.INCOMPATIBLE,
        })
        missing = next(r for r in report.results if r.account.account_id == "2")
        self.assertIn("2 device-bound", missing.detail)
        self.assertEqual(report.orphan_secrets, 1)
        self.assertEqual(len(report.tokens), 1)
        for result in report.results:
            for secret in (SECRET_A, SECRET_B, SECRET_C):
                self.assertNotIn(secret, result.detail)

    def test_missing_secret_without_undecryptable_items(self) -> None:
        report = recover_accounts({"1": {"name": "x"}}, [], KeychainStats(total=3, decrypted=3))
        self.assertNotIn("might contain", report.results[0].detail)


if __name__ == "__main__":
    unittest.main()
