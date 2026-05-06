import unittest

from cryptosystems.aes import encrypt_hex as aes_encrypt_hex
from cryptosystems.klein import encrypt_hex as klein_encrypt_hex
from cryptosystems.reduced_aes import ReducedAES
from cryptosystems.reduced_klein import ReducedKLEIN


class TestReducedAES(unittest.TestCase):
    def test_compat_with_aes128(self) -> None:
        cipher = ReducedAES(rounds=10, block_bits=128, key_bits=128)
        key = "000102030405060708090A0B0C0D0E0F"
        pt = "00112233445566778899AABBCCDDEEFF"

        expected = aes_encrypt_hex(pt, key)
        got = cipher.encrypt_hex(pt, key)
        back = cipher.decrypt_hex(got, key)

        self.assertEqual(expected, got)
        self.assertEqual(pt, back)

    def test_roundtrip_reduced_params(self) -> None:
        cipher = ReducedAES(rounds=4, block_bits=64, key_bits=64)
        key = "0011223344556677"
        vectors = ["0000000000000000", "0123456789ABCDEF", "FFFFFFFFFFFFFFFF"]
        for pt in vectors:
            ct = cipher.encrypt_hex(pt, key)
            back = cipher.decrypt_hex(ct, key)
            self.assertEqual(pt, back)


class TestReducedKLEIN(unittest.TestCase):
    def test_compat_with_klein64(self) -> None:
        cipher = ReducedKLEIN(rounds=12, block_bits=64, key_bits=64)
        key = "0000000000000000"
        pt = "FFFFFFFFFFFFFFFF"

        expected = klein_encrypt_hex(pt, key)
        got = cipher.encrypt_hex(pt, key)
        back = cipher.decrypt_hex(got, key)

        self.assertEqual(expected, got)
        self.assertEqual(pt, back)

    def test_roundtrip_reduced_params(self) -> None:
        cipher = ReducedKLEIN(rounds=6, block_bits=32, key_bits=64)
        key = "0011223344556677"
        vectors = ["00000000", "89ABCDEF", "FFFFFFFF"]
        for pt in vectors:
            ct = cipher.encrypt_hex(pt, key)
            back = cipher.decrypt_hex(ct, key)
            self.assertEqual(pt, back)


if __name__ == "__main__":
    unittest.main()
