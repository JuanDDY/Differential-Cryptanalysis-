import unittest

from cryptosystems.aes import aes_decrypt_block, aes_encrypt_block, expand_key_from_hex


class TestAES128(unittest.TestCase):
    def test_fips_vector_encrypt(self) -> None:
        key = "000102030405060708090A0B0C0D0E0F"
        pt = int("00112233445566778899AABBCCDDEEFF", 16)
        expected_ct = int("69C4E0D86A7B0430D8CDB78070B4C55A", 16)

        rks = expand_key_from_hex(key)
        ct = aes_encrypt_block(pt, rks)
        self.assertEqual(expected_ct, ct)

    def test_fips_vector_decrypt(self) -> None:
        key = "000102030405060708090A0B0C0D0E0F"
        ct = int("69C4E0D86A7B0430D8CDB78070B4C55A", 16)
        expected_pt = int("00112233445566778899AABBCCDDEEFF", 16)

        rks = expand_key_from_hex(key)
        pt = aes_decrypt_block(ct, rks)
        self.assertEqual(expected_pt, pt)

    def test_roundtrip_multiple_values(self) -> None:
        key = "2B7E151628AED2A6ABF7158809CF4F3C"
        rks = expand_key_from_hex(key)
        vectors = [
            int("00000000000000000000000000000000", 16),
            int("11111111111111111111111111111111", 16),
            int("00112233445566778899AABBCCDDEEFF", 16),
            int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16),
        ]
        for pt in vectors:
            ct = aes_encrypt_block(pt, rks)
            back = aes_decrypt_block(ct, rks)
            self.assertEqual(pt, back)


if __name__ == "__main__":
    unittest.main()
