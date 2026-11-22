from __future__ import annotations

import unittest

from synthetic import PASSWORD, SyntheticKeybag, tlv, u32

from iauhty_export.errors import (
    DecryptionError,
    DeviceBoundKeyError,
    IncompatibleFormatError,
    WrongPasswordError,
)
from iauhty_export.keybag import Keybag, iter_tlv


class KeybagParseTests(unittest.TestCase):
    def test_parses_header_and_class_keys(self) -> None:
        keybag = Keybag.parse(SyntheticKeybag().encode())
        self.assertEqual(keybag.keybag_type, 1)
        self.assertEqual(keybag.iterations, 10)
        self.assertEqual(keybag.dp_iterations, 100)
        self.assertEqual([k.class_id for k in keybag.class_keys], [*range(1, 12), 17, 18, 19])
        self.assertTrue(all(k.is_device_bound for k in keybag.class_keys if k.class_id in (5, 9, 10, 11, 19)))

    def test_rejects_truncated_tlv(self) -> None:
        data = SyntheticKeybag().encode()
        for cut in (3, len(data) - 1):
            with self.subTest(cut=cut), self.assertRaises(IncompatibleFormatError):
                Keybag.parse(data[:cut])

    def test_rejects_oversized_length(self) -> None:
        with self.assertRaises(IncompatibleFormatError):
            list(iter_tlv(b"SALT" + b"\xff\xff\xff\xff" + b"x"))

    def test_rejects_missing_kdf_parameters(self) -> None:
        data = tlv("VERS", u32(4)) + tlv("UUID", bytes(16)) + tlv("UUID", bytes(16)) + \
            tlv("CLAS", u32(1)) + tlv("WRAP", u32(2)) + tlv("WPKY", bytes(40))
        with self.assertRaises(IncompatibleFormatError):
            Keybag.parse(data)

    def test_rejects_keybag_without_class_keys(self) -> None:
        data = tlv("UUID", bytes(16)) + tlv("SALT", bytes(20)) + tlv("ITER", u32(1))
        with self.assertRaises(IncompatibleFormatError):
            Keybag.parse(data)

    def test_rejects_bad_integer_field_size(self) -> None:
        data = tlv("UUID", bytes(16)) + tlv("SALT", bytes(20)) + tlv("ITER", b"\x01")
        with self.assertRaises(IncompatibleFormatError):
            Keybag.parse(data)


class KeybagUnlockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.synthetic = SyntheticKeybag()
        self.keybag = Keybag.parse(self.synthetic.encode())

    def test_correct_password_unwraps_passcode_classes(self) -> None:
        unlocked = self.keybag.unlock(PASSWORD)
        for class_id in (1, 2, 3, 4, 6, 7, 8, 17, 18):
            self.assertEqual(unlocked.class_keys[class_id], self.synthetic.class_keys[class_id])
        self.assertEqual(unlocked.device_bound_classes, frozenset({5, 9, 10, 11, 19}))

    def test_wrong_password(self) -> None:
        with self.assertRaises(WrongPasswordError):
            self.keybag.unlock("wrong password")

    def test_legacy_sha1_only_derivation(self) -> None:
        synthetic = SyntheticKeybag(use_dp_round=False)
        keybag = Keybag.parse(synthetic.encode())
        self.assertIsNone(keybag.dp_iterations)
        self.assertEqual(keybag.unlock(PASSWORD).class_keys[3], synthetic.class_keys[3])

    def test_unwrap_key_errors(self) -> None:
        unlocked = self.keybag.unlock(PASSWORD)
        wrapped = self.synthetic.wrap_for_class(3, bytes(32))
        self.assertEqual(unlocked.unwrap_key(3, wrapped), bytes(32))
        with self.assertRaises(DeviceBoundKeyError):
            unlocked.unwrap_key(10, wrapped)
        with self.assertRaises(DecryptionError):
            unlocked.unwrap_key(42, wrapped)
        with self.assertRaises(DecryptionError):
            unlocked.unwrap_key(4, wrapped)  # wrong class key -> integrity failure


if __name__ == "__main__":
    unittest.main()
