import unittest

from differential_cryptoanalysis.aes_dc_key_recovery import (
    TRAIL_DELTA_PENULTIMATE as AES_DELTA_PENULTIMATE,
    generate_right_pairs_from_penultimate_delta as generate_aes_pairs,
    recover_last_round_subkey_from_right_pairs,
)
from differential_cryptoanalysis.klein_dc_key_recovery import (
    TRAIL_DELTA_PENULTIMATE as KLEIN_DELTA_PENULTIMATE,
    enumerate_final_whitening_candidates,
    generate_right_pairs_from_penultimate_delta as generate_klein_pairs,
    recover_transformed_final_whitening_from_right_pairs,
    transform_final_whitening_key,
)
from cryptosystems.reduced_aes import ReducedAES
from cryptosystems.reduced_klein import ReducedKLEIN


class TestReducedAESKeyRecovery(unittest.TestCase):
    def test_recovers_last_round_subkey_from_right_pairs(self) -> None:
        cipher = ReducedAES(rounds=4, block_bits=64, key_bits=64)
        round_keys = cipher.expand_key_from_hex("0011223344556677")
        true_last_round_key = round_keys[-1]

        pairs = generate_aes_pairs(
            cipher=cipher,
            last_round_key=true_last_round_key,
            delta_penultimate=AES_DELTA_PENULTIMATE,
            n_pairs=64,
            seed=7,
        )
        recovered_key, _ = recover_last_round_subkey_from_right_pairs(
            cipher=cipher,
            ciphertext_pairs=pairs,
            delta_penultimate=AES_DELTA_PENULTIMATE,
            return_scores=True,
        )
        self.assertEqual(true_last_round_key, recovered_key)


class TestReducedKLEINKeyRecovery(unittest.TestCase):
    def test_recovers_active_nibbles_of_transformed_final_whitening(self) -> None:
        cipher = ReducedKLEIN(rounds=6, block_bits=32, key_bits=64)
        round_keys = cipher.expand_round_keys_from_hex("0011223344556677")
        true_last_round_key = round_keys[cipher.rounds - 1]
        true_final_whitening_key = round_keys[cipher.rounds]
        true_transformed_key = transform_final_whitening_key(cipher, true_final_whitening_key)

        pairs = generate_klein_pairs(
            cipher=cipher,
            last_round_key=true_last_round_key,
            final_whitening_key=true_final_whitening_key,
            delta_penultimate=KLEIN_DELTA_PENULTIMATE,
            n_pairs=128,
            seed=9,
        )
        partial_transformed_key, _ = recover_transformed_final_whitening_from_right_pairs(
            cipher=cipher,
            ciphertext_pairs=pairs,
            delta_penultimate=KLEIN_DELTA_PENULTIMATE,
            return_scores=True,
        )

        expected_nibbles = [(true_transformed_key >> shift) & 0xF for shift in range(28, -1, -4)]
        active_positions = [0, 2, 3, 4, 5, 6]
        for pos in active_positions:
            self.assertEqual(expected_nibbles[pos], partial_transformed_key[pos])

        candidates = enumerate_final_whitening_candidates(cipher, partial_transformed_key)
        self.assertIn(true_final_whitening_key, candidates)
        self.assertEqual(256, len(candidates))


if __name__ == "__main__":
    unittest.main()
