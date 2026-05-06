import unittest

from differential_cryptoanalysis.dc_key_recovery import (
    build_oracle,
    recover_last_whitening_subkey,
)


class TestSPN16KeyRecovery(unittest.TestCase):
    def test_recovers_targeted_final_nibble(self) -> None:
        oracle = build_oracle("00112233445566778899AABB", rounds=5)
        partial_key, scores = recover_last_whitening_subkey(
            oracle_encrypt=oracle,
            delta_in=0x0B00,
            expected_delta_u_by_nibble={2: 0x5},
            n_pairs=4000,
            seed=2026,
            return_scores=True,
        )

        recovered_nibble = (partial_key >> 4) & 0xF
        self.assertEqual(recovered_nibble, 0xB)
        self.assertIn(2, scores)
        self.assertGreater(scores[2][0][1], scores[2][1][1])


if __name__ == "__main__":
    unittest.main()
