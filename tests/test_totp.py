from __future__ import annotations

import base64
import unittest

from iauhty_export.errors import InvalidSecretError
from iauhty_export.models import Algorithm, TotpParameters
from iauhty_export.totp import (
    decode_base32,
    hotp,
    normalize_base32,
    self_check,
    totp,
    validate_parameters,
)

# RFC 6238 Appendix B seeds (ASCII) for each hash.
SEEDS = {
    Algorithm.SHA1: b"12345678901234567890",
    Algorithm.SHA256: b"12345678901234567890123456789012",
    Algorithm.SHA512: b"1234567890123456789012345678901234567890123456789012345678901234",
}
RFC6238 = (
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
)


class TotpVectorTests(unittest.TestCase):
    def test_rfc6238_vectors(self) -> None:
        for timestamp, sha1, sha256, sha512 in RFC6238:
            for algorithm, expected in ((Algorithm.SHA1, sha1), (Algorithm.SHA256, sha256),
                                        (Algorithm.SHA512, sha512)):
                with self.subTest(timestamp=timestamp, algorithm=algorithm):
                    params = TotpParameters(algorithm, 8, 30)
                    self.assertEqual(totp(SEEDS[algorithm], timestamp, params), expected)

    def test_rfc4226_hotp_vectors(self) -> None:
        expected = ["755224", "287082", "359152", "969429", "338314",
                    "254676", "287922", "162583", "399871", "520489"]
        for counter, code in enumerate(expected):
            self.assertEqual(hotp(SEEDS[Algorithm.SHA1], counter, 6, Algorithm.SHA1), code)

    def test_period_and_digit_variants(self) -> None:
        key = SEEDS[Algorithm.SHA1]
        # Same counter (T=1) for period 60 at t=60..119 and period 30 at t=30..59.
        p60 = TotpParameters(Algorithm.SHA1, 6, 60)
        p30 = TotpParameters(Algorithm.SHA1, 6, 30)
        self.assertEqual(totp(key, 119, p60), totp(key, 59, p30))
        self.assertEqual(totp(key, 59, p30), "287082")  # HOTP counter 1
        self.assertEqual(totp(key, 59, TotpParameters(Algorithm.SHA1, 7, 30)), "4287082")
        self.assertEqual(len(totp(key, 59, TotpParameters(Algorithm.SHA1, 9, 30))), 9)


class Base32Tests(unittest.TestCase):
    def test_normalisation(self) -> None:
        self.assertEqual(normalize_base32(" jbsw y3dp-ehpk_3pxp== "), "JBSWY3DPEHPK3PXP")

    def test_decodes_unpadded_and_padded(self) -> None:
        raw = b"hello!!"
        encoded = base64.b32encode(raw).decode()
        self.assertEqual(decode_base32(encoded), raw)
        self.assertEqual(decode_base32(encoded.rstrip("=").lower()), raw)

    def test_rejects_invalid(self) -> None:
        for bad in ("", "====", "JBSW1", "JBSWY3DP!", "A", "ABC", "ABCDEF", "0189"):
            with self.subTest(bad=bad), self.assertRaises(InvalidSecretError):
                decode_base32(bad)


class ValidationTests(unittest.TestCase):
    def test_parameter_ranges(self) -> None:
        validate_parameters(TotpParameters(Algorithm.SHA512, 8, 60))
        for digits, period in ((5, 30), (10, 30), (6, 0), (6, 3601)):
            with self.subTest(digits=digits, period=period), self.assertRaises(InvalidSecretError):
                validate_parameters(TotpParameters(Algorithm.SHA1, digits, period))

    def test_self_check(self) -> None:
        self_check("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", TotpParameters(Algorithm.SHA1, 6, 30))
        with self.assertRaises(InvalidSecretError):
            self_check("JBSWY3DP", TotpParameters(Algorithm.SHA1, 6, 30))  # 40-bit secret


if __name__ == "__main__":
    unittest.main()
