from __future__ import annotations

import plistlib
import struct
import unittest

from synthetic import (
    PASSWORD,
    SECRET_A,
    SyntheticKeybag,
    authy_item,
    keychain_item,
    keychain_plist,
    unrelated_item,
)

from iauhty_export.authy import is_authy_service
from iauhty_export.errors import (
    DecryptionError,
    DeviceBoundKeyError,
    IncompatibleFormatError,
    KeychainUnavailableError,
)
from iauhty_export.keybag import Keybag
from iauhty_export.keychain import decode_der_attributes, decrypt_item, extract_generic_passwords


class DerTests(unittest.TestCase):
    def test_hand_encoded_attribute_set(self) -> None:
        # SET { SEQ { UTF8 "svce", UTF8 "Google1App" },
        #       SEQ { UTF8 "v_Data", OCTET STRING 01 02 },
        #       SEQ { PrintableString "sync", INTEGER 1 },
        #       SEQ { UTF8 "tomb", BOOLEAN false } }
        data = bytes.fromhex(
            "3138"
            "3012" "0c0473766365" "0c0a476f6f676c6531417070"
            "300c" "0c06765f44617461" "04020102"
            "3009" "130473796e63" "020101"
            "3009" "0c04746f6d62" "010100"
        )
        self.assertEqual(decode_der_attributes(data), {
            "svce": "Google1App", "v_Data": b"\x01\x02", "sync": 1, "tomb": False,
        })

    def test_long_form_length(self) -> None:
        value = b"x" * 300
        inner = b"\x0c\x01k" + b"\x04\x82\x01\x2c" + value
        seq = b"\x30\x82" + struct.pack(">H", len(inner)) + inner
        data = b"\x31\x82" + struct.pack(">H", len(seq)) + seq
        self.assertEqual(decode_der_attributes(data), {"k": value})

    def test_rejects_malformed_der(self) -> None:
        bad_inputs = [
            b"",
            b"\x31",
            b"\x31\x05\x30\x03",  # truncated content
            b"\x31\x80\x00\x00",  # indefinite length
            b"\x04\x00",  # not a SET
            b"\x31\x03\x04\x01\x00",  # child is not a SEQUENCE
            b"\x31\x05\x30\x03\x0c\x01k",  # SEQUENCE with one element
            b"\x31\x02\x30\x00\xff",  # trailing garbage
            b"\x1f\x01\x00",  # high tag number
        ]
        for data in bad_inputs:
            with self.subTest(data=data.hex()), self.assertRaises(IncompatibleFormatError):
                decode_der_attributes(data)


class DecryptItemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.synthetic = SyntheticKeybag()
        cls.keybag = Keybag.parse(cls.synthetic.encode()).unlock(PASSWORD)

    def test_version3_item(self) -> None:
        blob = authy_item(self.synthetic, "42", SECRET_A)
        attributes = decrypt_item(blob, self.keybag)
        self.assertEqual(attributes["svce"], "Google42App")
        self.assertEqual(attributes["v_Data"], SECRET_A.encode())

    def test_version2_plist_item(self) -> None:
        blob = keychain_item(self.synthetic, {"svce": "Google7App", "v_Data": b"abc"}, version=2)
        self.assertEqual(decrypt_item(blob, self.keybag)["svce"], "Google7App")

    def test_twelve_byte_zero_iv_fallback(self) -> None:
        blob = keychain_item(self.synthetic, {"svce": "s", "v_Data": b"d"}, iv=bytes(12), label="iv12")
        self.assertEqual(decrypt_item(blob, self.keybag)["v_Data"], b"d")

    def test_class_flags_in_upper_bits_are_ignored(self) -> None:
        blob = bytearray(authy_item(self.synthetic, "42", SECRET_A))
        blob[4:8] = struct.pack("<I", 7 | 0x100)
        self.assertEqual(decrypt_item(bytes(blob), self.keybag)["svce"], "Google42App")

    def test_class_above_15_uses_full_value(self) -> None:
        blob = authy_item(self.synthetic, "42", SECRET_A, protection_class=17)
        self.assertEqual(decrypt_item(blob, self.keybag)["svce"], "Google42App")
        with self.assertRaises(DeviceBoundKeyError):
            decrypt_item(authy_item(self.synthetic, "43", SECRET_A, protection_class=19), self.keybag)

    def test_unsupported_version(self) -> None:
        blob = bytearray(authy_item(self.synthetic, "42", SECRET_A))
        blob[0:4] = struct.pack("<I", 4)
        with self.assertRaises(IncompatibleFormatError):
            decrypt_item(bytes(blob), self.keybag)

    def test_tampered_ciphertext(self) -> None:
        blob = bytearray(authy_item(self.synthetic, "42", SECRET_A))
        blob[-20] ^= 1
        with self.assertRaises(DecryptionError):
            decrypt_item(bytes(blob), self.keybag)

    def test_truncated_and_bad_lengths(self) -> None:
        blob = authy_item(self.synthetic, "42", SECRET_A)
        for bad in (blob[:8], blob[:40], blob[:12] + b"x"):
            with self.subTest(length=len(bad)), self.assertRaises(IncompatibleFormatError):
                decrypt_item(bad, self.keybag)
        oversized = bytearray(blob)
        oversized[8:12] = struct.pack("<I", 10_000)
        with self.assertRaises(IncompatibleFormatError):
            decrypt_item(bytes(oversized), self.keybag)

    def test_device_bound_item(self) -> None:
        blob = authy_item(self.synthetic, "42", SECRET_A, protection_class=10)
        with self.assertRaises(DeviceBoundKeyError):
            decrypt_item(blob, self.keybag)


class ExtractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.synthetic = SyntheticKeybag()
        cls.keybag = Keybag.parse(cls.synthetic.encode()).unlock(PASSWORD)

    def test_filters_and_counts(self) -> None:
        corrupted = bytearray(authy_item(self.synthetic, "3", SECRET_A))
        corrupted[-1] ^= 1
        unsupported = bytearray(authy_item(self.synthetic, "4", SECRET_A))
        unsupported[0:4] = struct.pack("<I", 9)
        data = keychain_plist([
            authy_item(self.synthetic, "1", SECRET_A),
            unrelated_item(self.synthetic, "mail"),
            authy_item(self.synthetic, "2", SECRET_A, protection_class=11),
            bytes(corrupted),
            bytes(unsupported),
        ])
        items, stats = extract_generic_passwords(data, self.keybag, is_authy_service)
        self.assertEqual([i.service for i in items], ["Google1App"])
        self.assertEqual(items[0].account, "account-1")
        self.assertEqual(items[0].access_group, "9XYZ.com.authy")
        self.assertNotIn(SECRET_A, repr(items[0]))
        self.assertEqual((stats.total, stats.decrypted, stats.matched), (5, 2, 1))
        self.assertEqual((stats.device_bound, stats.corrupted, stats.unsupported), (1, 1, 1))

    def test_malformed_entries_are_counted(self) -> None:
        data = plistlib.dumps({"genp": [{"v_PersistentRef": b"x"}, "junk"]}, fmt=plistlib.FMT_BINARY)
        items, stats = extract_generic_passwords(data, self.keybag, is_authy_service)
        self.assertEqual((items, stats.corrupted), ([], 2))

    def test_missing_genp_section(self) -> None:
        data = plistlib.dumps({"inet": []}, fmt=plistlib.FMT_BINARY)
        items, stats = extract_generic_passwords(data, self.keybag, is_authy_service)
        self.assertEqual((items, stats.total), ([], 0))

    def test_unreadable_keychain(self) -> None:
        with self.assertRaises(KeychainUnavailableError):
            extract_generic_passwords(b"not a plist", self.keybag, is_authy_service)
        with self.assertRaises(KeychainUnavailableError):
            extract_generic_passwords(plistlib.dumps({"genp": "x"}), self.keybag, is_authy_service)


if __name__ == "__main__":
    unittest.main()
