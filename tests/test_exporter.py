from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import scrypt_reference
from helpers import EXPORT_PASSWORD, FAST_SCRYPT, fast_encryption
from synthetic import SECRET_A, SECRET_B

from iauhty_export import crypto, exporter
from iauhty_export.errors import ExportError, WrongPasswordError
from iauhty_export.models import Algorithm, TotpParameters, TotpToken

FIXTURE = Path(__file__).parent / "fixtures" / "aegis_plain_synthetic.json"

TOKENS = (
    TotpToken("alice@example.com", "Example", SECRET_A, TotpParameters(Algorithm.SHA1, 6, 30), "1"),
    TotpToken("bob", "", SECRET_B, TotpParameters(Algorithm.SHA256, 8, 60), "2"),
)


class BuildAndValidateTests(unittest.TestCase):
    def test_structure_matches_aegis_plain_format(self) -> None:
        vault = exporter.build_vault(TOKENS)
        self.assertEqual(vault["version"], 1)
        self.assertEqual(vault["header"], {"slots": None, "params": None})
        self.assertEqual(vault["db"]["version"], 3)
        self.assertEqual(vault["db"]["groups"], [])
        entry = vault["db"]["entries"][0]
        self.assertEqual(set(entry), {"type", "uuid", "name", "issuer", "note", "favorite", "icon", "info", "groups"})
        self.assertEqual(entry["info"], {"secret": SECRET_A, "algo": "SHA1", "digits": 6, "period": 30})
        self.assertEqual(entry["type"], "totp")
        self.assertEqual(uuid.UUID(entry["uuid"]).version, 4)
        self.assertEqual(exporter.validate_vault(vault), [])

    def test_metadata_preserved(self) -> None:
        vault = exporter.build_vault(TOKENS)
        second = vault["db"]["entries"][1]
        self.assertEqual((second["name"], second["issuer"]), ("bob", ""))
        self.assertEqual(second["info"], {"secret": SECRET_B, "algo": "SHA256", "digits": 8, "period": 60})
        self.assertTrue(exporter.entries_match_tokens(vault, TOKENS))
        self.assertFalse(exporter.entries_match_tokens(vault, TOKENS[:1]))

    def test_unique_uuids(self) -> None:
        vault = exporter.build_vault(TOKENS)
        uuids = [e["uuid"] for e in vault["db"]["entries"]]
        self.assertEqual(len(set(uuids)), len(uuids))

    def test_static_fixture_is_valid(self) -> None:
        document = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(exporter.validate_vault(document), [])

    def test_detects_invalid_documents(self) -> None:
        base = exporter.build_vault(TOKENS)
        cases = {
            "encrypted header": lambda d: d["header"].update(slots=[]),
            "db not object": lambda d: d.update(db="ciphertext"),
            "bad uuid": lambda d: d["db"]["entries"][0].update(uuid="nope"),
            "uuid v1": lambda d: d["db"]["entries"][0].update(uuid=str(uuid.uuid1())),
            "duplicate uuid": lambda d: d["db"]["entries"][1].update(uuid=d["db"]["entries"][0]["uuid"]),
            "bad secret": lambda d: d["db"]["entries"][0]["info"].update(secret="!!"),
            "ten digits": lambda d: d["db"]["entries"][0]["info"].update(digits=10),
            "md5": lambda d: d["db"]["entries"][0]["info"].update(algo="MD5"),
            "hotp": lambda d: d["db"]["entries"][0].update(type="hotp"),
            "missing note": lambda d: d["db"]["entries"][0].pop("note"),
            "string digits": lambda d: d["db"]["entries"][0]["info"].update(digits="6"),
            "duplicate token": lambda d: d["db"]["entries"][1].update(info=dict(d["db"]["entries"][0]["info"])),
            "entries not list": lambda d: d["db"].update(entries={}),
            "db version": lambda d: d["db"].update(version=4),
        }
        for label, mutate in cases.items():
            document = copy.deepcopy(base)
            mutate(document)
            with self.subTest(label=label):
                issues = exporter.validate_vault(document)
                self.assertTrue(issues)
                self.assertFalse(any(SECRET_A in issue or SECRET_B in issue for issue in issues))
        self.assertEqual(exporter.validate_vault([]), ["top level is not a JSON object"])


class FileTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def export(self, target: Path, **kwargs: object):
        with fast_encryption():
            return exporter.export_tokens(TOKENS, target, EXPORT_PASSWORD, **kwargs)

    def read_back(self, target: Path) -> dict:
        with fast_encryption():
            return exporter.decrypt_vault(exporter.read_vault(target), EXPORT_PASSWORD)

    def test_export_writes_private_encrypted_file(self) -> None:
        target = self.dir / "sub" / "iauhty-export.json"
        summary = self.export(target)
        self.assertEqual(summary.entries, 2)
        self.assertEqual(summary.validation_issues, ())
        self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(target.parent).st_mode), 0o700)
        raw = target.read_text()
        for secret in (SECRET_A, SECRET_B, "alice@example.com", EXPORT_PASSWORD):
            self.assertNotIn(secret, raw)
        self.assertEqual(exporter.validate_vault(self.read_back(target)), [])
        self.assertEqual(os.listdir(target.parent), ["iauhty-export.json"])  # no temp leftovers

    def test_existing_file_is_not_overwritten(self) -> None:
        target = self.dir / "out.json"
        target.write_text("keep me")
        with self.assertRaises(ExportError):
            self.export(target)
        self.assertEqual(target.read_text(), "keep me")
        self.export(target, overwrite=True)
        self.assertEqual(exporter.validate_vault(self.read_back(target)), [])

    def test_short_or_missing_password_is_refused(self) -> None:
        for password in ("", "short"):
            with self.subTest(password=password), self.assertRaises(ExportError):
                exporter.export_tokens(TOKENS, self.dir / "out.json", password)
        self.assertFalse((self.dir / "out.json").exists())

    def test_existing_symlink_is_not_followed(self) -> None:
        victim = self.dir / "victim.txt"
        victim.write_text("original")
        link = self.dir / "out.json"
        link.symlink_to(victim)
        with self.assertRaises(ExportError):
            exporter.write_private_file(link, b"data")
        exporter.write_private_file(link, b"data", overwrite=True)
        self.assertEqual(victim.read_text(), "original")
        self.assertFalse(link.is_symlink())

    def test_race_on_create_does_not_clobber(self) -> None:
        target = self.dir / "out.json"
        real_link = os.link

        def racing_link(src: str, dst: os.PathLike) -> None:
            Path(dst).write_text("created concurrently")
            real_link(src, dst)

        with mock.patch.object(exporter.os, "link", side_effect=racing_link):
            with self.assertRaises(ExportError):
                exporter.write_private_file(target, b"data")
        self.assertEqual(target.read_text(), "created concurrently")
        self.assertEqual(sorted(os.listdir(self.dir)), ["out.json"])

    def test_write_failure_is_reported_and_cleaned(self) -> None:
        with mock.patch.object(exporter.os, "fsync", side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(ExportError) as ctx:
                exporter.write_private_file(self.dir / "out.json", b"data")
        self.assertIn("No space left", str(ctx.exception))
        self.assertEqual(os.listdir(self.dir), [])

    def test_parent_is_a_file(self) -> None:
        blocker = self.dir / "blocker"
        blocker.write_text("x")
        with self.assertRaises(ExportError):
            exporter.write_private_file(blocker / "out.json", b"data")

    def test_target_is_directory(self) -> None:
        with self.assertRaises(ExportError):
            exporter.write_private_file(self.dir, b"data", overwrite=True)

    def test_read_vault_errors(self) -> None:
        with self.assertRaises(ExportError):
            exporter.read_vault(self.dir / "missing.json")
        bad = self.dir / "bad.json"
        bad.write_bytes(b"\xff{")
        with self.assertRaises(ExportError):
            exporter.read_vault(bad)

    def test_refuses_empty_export(self) -> None:
        with self.assertRaises(ExportError):
            exporter.export_tokens((), self.dir / "out.json", EXPORT_PASSWORD)

    def test_synced_location_warning(self) -> None:
        self.assertIsNotNone(exporter.synced_location_warning(Path.home() / "Documents" / "x.json"))
        self.assertIsNone(exporter.synced_location_warning(self.dir / "x.json"))


class ScryptTests(unittest.TestCase):
    # RFC 7914 §12 test vectors.
    VECTOR_1 = (b"", b"", 16, 1, 1, bytes.fromhex(
        "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
        "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"))
    VECTOR_2 = (b"password", b"NaCl", 1024, 8, 16, bytes.fromhex(
        "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
        "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"))

    def test_reference_salsa20_8_core(self) -> None:
        # RFC 7914 §8.
        block = bytes.fromhex(
            "7e879a214f3ec9867ca940e641718f26baee555b8c61c1b50df846116dcd3b1d"
            "ee24f319df9b3d8514121e4b5ac5aa3276021d2909c74829edebc68db8b8c25e")
        expected = bytes.fromhex(
            "a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29"
            "b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f81")
        self.assertEqual(scrypt_reference.salsa20_8(block), expected)

    def test_reference_matches_rfc7914(self) -> None:
        password, salt, n, r, p, expected = self.VECTOR_1
        self.assertEqual(scrypt_reference.scrypt(password, salt, n, r, p, 64), expected)

    @unittest.skipUnless(crypto.scrypt_available(), "hashlib.scrypt needs Python built with OpenSSL")
    def test_hashlib_scrypt_matches_rfc7914_and_reference(self) -> None:
        # Vector 1 has an empty salt, which the product wrapper rejects on
        # purpose (exports always use a 32-byte random salt): check it raw.
        password, salt, n, r, p, expected = self.VECTOR_1
        self.assertEqual(hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=64), expected)
        with self.assertRaises(crypto.CryptoError):
            crypto.scrypt(password, salt, n, r, p, 64)
        password, salt, n, r, p, expected = self.VECTOR_2
        self.assertEqual(crypto.scrypt(password, salt, n, r, p, 64), expected)
        self.assertEqual(crypto.scrypt(b"pw", b"salt", 1024, 8, 1),
                         scrypt_reference.scrypt(b"pw", b"salt", 1024, 8, 1))

    def test_scrypt_parameter_validation(self) -> None:
        for n, r, p in ((1000, 8, 1), (1, 8, 1), (1 << 15, 0, 1), (1 << 15, 8, 0), (1 << 22, 8, 1)):
            with self.subTest(n=n, r=r, p=p), self.assertRaises(crypto.CryptoError):
                crypto.scrypt(b"pw", b"salt", n, r, p)

    @unittest.skipIf(crypto.scrypt_available(), "only meaningful without OpenSSL scrypt")
    def test_missing_scrypt_is_reported(self) -> None:
        with self.assertRaises(crypto.CryptoError):
            crypto.scrypt(b"pw", b"salt", 1 << 15, 8, 1)


class EncryptedVaultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plain = exporter.build_vault(TOKENS)

    def encrypt(self, password: str = EXPORT_PASSWORD) -> dict:
        return exporter.encrypt_vault(self.plain, password, params=FAST_SCRYPT, kdf=scrypt_reference.scrypt)

    def decrypt(self, document: dict, password: str = EXPORT_PASSWORD) -> dict:
        return exporter.decrypt_vault(document, password, kdf=scrypt_reference.scrypt)

    def test_structure_matches_aegis_encrypted_format(self) -> None:
        document = self.encrypt()
        self.assertEqual(document["version"], 1)
        self.assertTrue(exporter.is_encrypted(document))
        [slot] = document["header"]["slots"]
        self.assertEqual(slot["type"], 1)
        self.assertEqual(uuid.UUID(slot["uuid"]).version, 4)
        self.assertEqual(len(bytes.fromhex(slot["key"])), 32)
        self.assertEqual(len(bytes.fromhex(slot["salt"])), 32)
        self.assertEqual(len(bytes.fromhex(slot["key_params"]["nonce"])), 12)
        self.assertEqual(len(bytes.fromhex(slot["key_params"]["tag"])), 16)
        self.assertEqual((slot["n"], slot["r"], slot["p"]), (16, 1, 1))
        self.assertIs(slot["repaired"], True)
        self.assertIs(slot["is_backup"], False)
        self.assertEqual(len(bytes.fromhex(document["header"]["params"]["nonce"])), 12)
        self.assertEqual(len(bytes.fromhex(document["header"]["params"]["tag"])), 16)
        self.assertIsInstance(document["db"], str)
        self.assertEqual(exporter.ScryptParams(), exporter.ScryptParams(32768, 8, 1))  # Aegis defaults

    def test_round_trip_preserves_entries(self) -> None:
        self.assertEqual(self.decrypt(self.encrypt())["db"], self.plain["db"])

    def test_fresh_randomness_per_export(self) -> None:
        first, second = self.encrypt(), self.encrypt()
        self.assertNotEqual(first["header"]["slots"][0]["salt"], second["header"]["slots"][0]["salt"])
        self.assertNotEqual(first["db"], second["db"])

    def test_non_ascii_password(self) -> None:
        document = self.encrypt("sênha-çom-acentos")
        self.assertEqual(self.decrypt(document, "sênha-çom-acentos")["db"], self.plain["db"])

    def test_wrong_password(self) -> None:
        with self.assertRaises(WrongPasswordError):
            self.decrypt(self.encrypt(), "another password")

    def test_tampering_is_detected(self) -> None:
        def flip_hex(value: str) -> str:
            return ("1" if value[0] == "0" else "0") + value[1:]

        cases = {
            "slot tag": (lambda d: d["header"]["slots"][0]["key_params"].update(
                tag=flip_hex(d["header"]["slots"][0]["key_params"]["tag"])), WrongPasswordError),
            "db tag": (lambda d: d["header"]["params"].update(tag=flip_hex(d["header"]["params"]["tag"])),
                       ExportError),
            "db ciphertext": (lambda d: d.update(db="A" + d["db"][1:] if d["db"][0] != "A" else "B" + d["db"][1:]),
                              ExportError),
        }
        for label, (mutate, error) in cases.items():
            document = copy.deepcopy(self.encrypt())
            mutate(document)
            with self.subTest(label=label), self.assertRaises(error):
                self.decrypt(document)

    def test_malformed_encrypted_vaults(self) -> None:
        cases = {
            "no slots": lambda d: d["header"].update(slots=[]),
            "non-password first slot": lambda d: d["header"]["slots"][0].update(type=2),
            "bad hex": lambda d: d["header"]["slots"][0].update(salt="zz"),
            "short nonce": lambda d: d["header"]["params"].update(nonce="00"),
            "bad base64": lambda d: d.update(db="!!!"),
            "db not string": lambda d: d.update(db={}),
            "bad n": lambda d: d["header"]["slots"][0].update(n="16"),
            "n not power of two": lambda d: d["header"]["slots"][0].update(n=1000),
        }
        for label, mutate in cases.items():
            document = copy.deepcopy(self.encrypt())
            mutate(document)
            with self.subTest(label=label), self.assertRaises(ExportError):
                self.decrypt(document)
        with self.assertRaises(ExportError):
            self.decrypt(self.plain)


if __name__ == "__main__":
    unittest.main()
