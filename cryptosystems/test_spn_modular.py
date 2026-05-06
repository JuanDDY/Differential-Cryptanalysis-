import unittest

from cryptosystems import spn16
from cryptosystems.dc_key_recovery import recover_last_whitening_subkey
from cryptosystems.spn_modular import ModularSPN


SBOX_4X4 = [
    0xE, 0x4, 0xD, 0x1,
    0x2, 0xF, 0xB, 0x8,
    0x3, 0xA, 0x6, 0xC,
    0x5, 0x9, 0x0, 0x7,
]

PERM_16 = [
    0, 4, 8, 12,
    1, 5, 9, 13,
    2, 6, 10, 14,
    3, 7, 11, 15,
]

MASTER_KEY_HEX = "00112233445566778899AABB"


class TestModularSPN(unittest.TestCase):
    def setUp(self) -> None:
        self.rounds = 5
        self.cipher = ModularSPN(
            sbox=SBOX_4X4,
            permutation=PERM_16,
            rounds=self.rounds,
            block_bits=16,
        )
        self.subkeys = self.cipher.expand_key_from_hex(MASTER_KEY_HEX)

    def test_encrypt_decrypt_roundtrip(self) -> None:
        vectors = [0x0000, 0x1234, 0xBEEF, 0xACE1, 0xFFFF]
        for pt in vectors:
            ct = self.cipher.encrypt_block(pt, self.subkeys)
            back = self.cipher.decrypt_block(ct, self.subkeys)
            self.assertEqual(pt, back)

    def test_compat_with_existing_spn16(self) -> None:
        subkeys_fixed = spn16.expand_key_from_hex(MASTER_KEY_HEX, self.rounds)
        vectors = [0x0000, 0x1234, 0x2222, 0xBEEF, 0xFFFF]
        for pt in vectors:
            ct_modular = self.cipher.encrypt_block(pt, self.subkeys)
            ct_fixed = spn16.spn_encrypt_block(pt, subkeys_fixed, self.rounds)
            self.assertEqual(ct_fixed, ct_modular)

    def test_differential_attack_runs(self) -> None:
        oracle = lambda x: self.cipher.encrypt_block(x, self.subkeys)
        partial_key, scores = recover_last_whitening_subkey(
            cipher=self.cipher,
            oracle_encrypt=oracle,
            delta_in=0x0B00,
            expected_delta_u_by_sbox={1: 0x6, 3: 0x6},
            n_pairs=400,
            seed=2026,
            return_scores=True,
        )

        self.assertIsInstance(partial_key, int)
        self.assertTrue(0 <= partial_key <= 0xFFFF)
        self.assertIn(1, scores)
        self.assertIn(3, scores)
        self.assertGreater(len(scores[1]), 0)
        self.assertGreater(len(scores[3]), 0)


if __name__ == "__main__":
    unittest.main()
