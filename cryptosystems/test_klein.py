import unittest

from cryptosystems.klein import decrypt_hex, encrypt_hex


class TestKLEIN(unittest.TestCase):
    def test_klein64_vectors(self) -> None:
        vectors = [
            ("0000000000000000", "FFFFFFFFFFFFFFFF", "CDC0B51F14722BBE"),
            ("FFFFFFFFFFFFFFFF", "0000000000000000", "6456764E8602E154"),
            ("1234567890ABCDEF", "FFFFFFFFFFFFFFFF", "592356C4997176C8"),
            ("0000000000000000", "1234567890ABCDEF", "629F9D6DFF95800E"),
        ]
        for key, pt, expected_ct in vectors:
            self.assertEqual(expected_ct, encrypt_hex(pt, key))
            self.assertEqual(pt, decrypt_hex(expected_ct, key))

    def test_klein80_vectors(self) -> None:
        vectors = [
            ("00000000000000000000", "FFFFFFFFFFFFFFFF", "6677E20D1A53A431"),
            ("FFFFFFFFFFFFFFFFFFFF", "0000000000000000", "82247502273DCC5F"),
            ("1234567890ABCDEF1234", "FFFFFFFFFFFFFFFF", "3F210F67CB23687A"),
            ("00000000000000000000", "1234567890ABCDEF", "BA5239E93E784366"),
        ]
        for key, pt, expected_ct in vectors:
            self.assertEqual(expected_ct, encrypt_hex(pt, key))
            self.assertEqual(pt, decrypt_hex(expected_ct, key))

    def test_klein96_vectors(self) -> None:
        vectors = [
            ("000000000000000000000000", "FFFFFFFFFFFFFFFF", "DB9FA7D33D8E8E36"),
            ("FFFFFFFFFFFFFFFFFFFFFFFF", "0000000000000000", "15A3A03386A7FEC6"),
            ("1234567890ABCDEF12345678", "FFFFFFFFFFFFFFFF", "79687798AFDA0BC3"),
            ("000000000000000000000000", "1234567890ABCDEF", "5006A987A500BFDD"),
        ]
        for key, pt, expected_ct in vectors:
            self.assertEqual(expected_ct, encrypt_hex(pt, key))
            self.assertEqual(pt, decrypt_hex(expected_ct, key))


if __name__ == "__main__":
    unittest.main()
