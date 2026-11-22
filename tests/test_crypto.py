"""Crypto primitives checked against independent published vectors."""

from __future__ import annotations

import struct
import unittest

from iauhty_export import _commoncrypto as cc
from iauhty_export import crypto
from iauhty_export.errors import CryptoError, DecryptionError

h = bytes.fromhex


class Pbkdf2Tests(unittest.TestCase):
    def test_rfc6070_sha1_vectors(self) -> None:
        self.assertEqual(crypto.pbkdf2("sha1", b"password", b"salt", 1, 20),
                         h("0c60c80f961f0e71f3a9b524af6012062fe037a6"))
        self.assertEqual(crypto.pbkdf2("sha1", b"password", b"salt", 4096, 20),
                         h("4b007901b765489abead49d926f721d065a429c1"))
        self.assertEqual(
            crypto.pbkdf2("sha1", b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25),
            h("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"))

    def test_rfc7914_sha256_vector(self) -> None:
        self.assertEqual(
            crypto.pbkdf2("sha256", b"passwd", b"salt", 1, 64),
            h("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
              "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"))

    def test_rejects_bad_parameters(self) -> None:
        with self.assertRaises(CryptoError):
            crypto.pbkdf2("md5", b"p", b"s", 1, 16)
        with self.assertRaises(CryptoError):
            crypto.pbkdf2("sha1", b"p", b"s", 0, 16)
        with self.assertRaises(CryptoError):
            crypto.pbkdf2("sha1", b"p", b"s", crypto.MAX_PBKDF2_ITERATIONS + 1, 16)
        with self.assertRaises(CryptoError):
            crypto.pbkdf2("sha1", b"p", b"", 1, 16)


class AesCbcTests(unittest.TestCase):
    # NIST SP 800-38A, F.2.5 / F.2.6 (CBC-AES256).
    KEY = h("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    IV = h("000102030405060708090a0b0c0d0e0f")
    PLAIN = h("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
              "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    CIPHER = h("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"
               "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b")

    def test_nist_encrypt(self) -> None:
        self.assertEqual(crypto.aes_cbc_encrypt(self.KEY, self.PLAIN, self.IV), self.CIPHER)

    def test_nist_decrypt(self) -> None:
        self.assertEqual(crypto.aes_cbc_decrypt(self.KEY, self.CIPHER, self.IV), self.PLAIN)

    def test_nist_aes128_cbc(self) -> None:
        # SP 800-38A F.2.1 first block.
        key = h("2b7e151628aed2a6abf7158809cf4f3c")
        self.assertEqual(crypto.aes_cbc_encrypt(key, self.PLAIN[:16], self.IV),
                         h("7649abac8119b246cee98e9b12e9197d"))

    def test_rejects_unaligned_data(self) -> None:
        with self.assertRaises(DecryptionError):
            crypto.aes_cbc_decrypt(self.KEY, self.CIPHER[:-1], self.IV)

    def test_rejects_invalid_key_and_iv(self) -> None:
        with self.assertRaises(CryptoError):
            crypto.aes_cbc_decrypt(b"short", self.CIPHER, self.IV)
        with self.assertRaises(CryptoError):
            crypto.aes_cbc_decrypt(self.KEY, self.CIPHER, b"\x00" * 8)

    def test_commoncrypto_error_is_reported(self) -> None:
        # Bypass validation to make CommonCrypto itself reject the key size.
        with self.assertRaises(CryptoError) as ctx:
            cc.cc_crypt(cc.K_CC_DECRYPT, b"x" * 7, bytes(16), bytes(16))
        self.assertIn("CCCrypt", str(ctx.exception))


class Pkcs7Tests(unittest.TestCase):
    def test_round_trip(self) -> None:
        for length in (0, 1, 15, 16, 17, 31):
            data = bytes(range(length))
            padded = crypto.pkcs7_pad(data)
            self.assertEqual(len(padded) % 16, 0)
            self.assertEqual(crypto.pkcs7_unpad(padded), data)

    def test_rejects_invalid_padding(self) -> None:
        for bad in (b"", bytes(15), bytes(16), b"A" * 15 + b"\x11", b"A" * 14 + b"\x01\x02"):
            with self.assertRaises(DecryptionError):
                crypto.pkcs7_unpad(bad)


class KeyWrapTests(unittest.TestCase):
    # RFC 3394 §4.1, §4.3 and §4.6.
    VECTORS = (
        ("000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF",
         "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"),
        ("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
         "00112233445566778899AABBCCDDEEFF",
         "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"),
        ("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
         "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
         "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"),
    )

    def test_rfc3394_vectors(self) -> None:
        for kek, key, wrapped in self.VECTORS:
            with self.subTest(kek=kek, key=key):
                self.assertEqual(crypto.aes_key_wrap(h(kek), h(key)), h(wrapped))
                self.assertEqual(crypto.aes_key_unwrap(h(kek), h(wrapped)), h(key))

    def test_wrong_kek_fails_integrity_check(self) -> None:
        kek, _, wrapped = self.VECTORS[0]
        with self.assertRaises(DecryptionError):
            crypto.aes_key_unwrap(bytes(16), h(wrapped))

    def test_tampered_or_truncated_input(self) -> None:
        kek, _, wrapped = self.VECTORS[0]
        tampered = bytearray(h(wrapped))
        tampered[-1] ^= 1
        with self.assertRaises(DecryptionError):
            crypto.aes_key_unwrap(h(kek), bytes(tampered))
        for bad in (h(wrapped)[:-8], h(wrapped)[:-3], b""):
            with self.assertRaises(DecryptionError):
                crypto.aes_key_unwrap(h(kek), bad)

    def test_invalid_kek_length(self) -> None:
        with self.assertRaises(CryptoError):
            crypto.aes_key_unwrap(bytes(10), bytes(24))


def _gf_mult(x: int, y: int) -> int:
    """GF(2^128) multiplication per NIST SP 800-38D §6.3 (test-only reference)."""
    r = 0xE1 << 120
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ r if v & 1 else v >> 1
    return z


def _reference_gcm_empty_iv(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Independent GCM construction for a zero-length IV (J0 = GHASH_H(0^128) = 0).

    Uses only single-block AES (CBC with zero IV on one block == ECB) from
    CommonCrypto; CTR and GHASH are computed here from the SP 800-38D spec.
    """
    def aes_block(block: bytes) -> bytes:
        return crypto.aes_cbc_encrypt(key, block, bytes(16))

    hash_key = int.from_bytes(aes_block(bytes(16)), "big")
    j0 = bytes(16)
    ciphertext = b""
    for index in range(0, len(plaintext), 16):
        counter = (int.from_bytes(j0[12:], "big") + 1 + index // 16) & 0xFFFFFFFF
        keystream = aes_block(j0[:12] + struct.pack(">I", counter))
        chunk = plaintext[index:index + 16]
        ciphertext += bytes(a ^ b for a, b in zip(chunk, keystream))
    padded = ciphertext + bytes(-len(ciphertext) % 16)
    blocks = [padded[i:i + 16] for i in range(0, len(padded), 16)]
    blocks.append(struct.pack(">QQ", 0, len(ciphertext) * 8))
    y = 0
    for block in blocks:
        y = _gf_mult(y ^ int.from_bytes(block, "big"), hash_key)
    tag = bytes(a ^ b for a, b in zip(y.to_bytes(16, "big"), aes_block(j0)))
    return ciphertext, tag


class AesGcmTests(unittest.TestCase):
    # NIST GCM specification (McGrew & Viega) test cases 2, 3, 13, 14.
    VECTORS = (
        ("00000000000000000000000000000000", "000000000000000000000000",
         "00000000000000000000000000000000", "0388dace60b6a392f328c2b971b2fe78",
         "ab6e47d42cec13bdf53a67b21257bddf"),
        ("feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
         "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
         "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
         "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
         "4d5c2af327cd64a62cf35abd2ba6fab4"),
        ("0000000000000000000000000000000000000000000000000000000000000000",
         "000000000000000000000000", "", "", "530f8afbc74536b9a963b4f1c4cb738b"),
        ("0000000000000000000000000000000000000000000000000000000000000000",
         "000000000000000000000000", "00000000000000000000000000000000",
         "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919"),
    )

    def test_nist_vectors(self) -> None:
        for key, iv, plain, cipher, tag in self.VECTORS:
            with self.subTest(key=key, plain=plain[:16]):
                self.assertEqual(crypto.aes_gcm_encrypt(h(key), h(iv), h(plain)), (h(cipher), h(tag)))
                self.assertEqual(crypto.aes_gcm_decrypt(h(key), h(iv), h(cipher), h(tag)), h(plain))

    def test_empty_iv_matches_independent_reference(self) -> None:
        key = bytes(range(32))
        for length in (0, 5, 16, 33, 100):
            plaintext = bytes((i * 7) & 0xFF for i in range(length))
            with self.subTest(length=length):
                expected = _reference_gcm_empty_iv(key, plaintext)
                self.assertEqual(crypto.aes_gcm_encrypt(key, b"", plaintext), expected)
                self.assertEqual(crypto.aes_gcm_decrypt(key, b"", *expected), plaintext)

    def test_tag_mismatch_is_rejected(self) -> None:
        key, iv, _, cipher, tag = self.VECTORS[1]
        bad_tag = bytearray(h(tag))
        bad_tag[0] ^= 0x80
        with self.assertRaises(DecryptionError):
            crypto.aes_gcm_decrypt(h(key), h(iv), h(cipher), bytes(bad_tag))
        bad_cipher = bytearray(h(cipher))
        bad_cipher[5] ^= 1
        with self.assertRaises(DecryptionError):
            crypto.aes_gcm_decrypt(h(key), h(iv), bytes(bad_cipher), h(tag))

    def test_wrong_iv_is_rejected(self) -> None:
        key, _, plain, _, _ = self.VECTORS[3]
        cipher, tag = crypto.aes_gcm_encrypt(h(key), b"", h(plain))
        with self.assertRaises(DecryptionError):
            crypto.aes_gcm_decrypt(h(key), bytes(12), cipher, tag)

    def test_invalid_tag_or_key_length(self) -> None:
        with self.assertRaises(DecryptionError):
            crypto.aes_gcm_decrypt(bytes(16), b"", b"", bytes(8))
        with self.assertRaises(CryptoError):
            crypto.aes_gcm_encrypt(bytes(15), b"", b"")


if __name__ == "__main__":
    unittest.main()
