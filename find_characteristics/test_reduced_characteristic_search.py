import unittest

from find_characteristics.reduced_characteristic_search import (
    search_best_characteristics_to_penultimate,
    search_high_probability_characteristics_to_penultimate,
)


class TestReducedCharacteristicSearch(unittest.TestCase):
    def test_klein_reduced_search_returns_paths(self) -> None:
        items = search_high_probability_characteristics_to_penultimate(
            cipher_name="klein",
            total_rounds=6,
            block_bits=32,
            key_bits=64,
            delta_in=0x0000000F,
            top_k=3,
            beam_width=80,
            max_outputs_per_active_chunk=4,
            max_candidates_per_state=96,
        )
        self.assertGreater(len(items), 0)
        self.assertEqual(len(items[0].deltas), 6)  # Delta_0 ... Delta_5

    def test_aes_reduced_search_returns_paths(self) -> None:
        items = search_high_probability_characteristics_to_penultimate(
            cipher_name="aes",
            total_rounds=4,
            block_bits=64,
            key_bits=64,
            delta_in=0x0100000000000000,
            top_k=3,
            beam_width=80,
            max_outputs_per_active_chunk=4,
            max_candidates_per_state=96,
        )
        self.assertGreater(len(items), 0)
        self.assertEqual(len(items[0].deltas), 4)  # Delta_0 ... Delta_3

    def test_best_klein_reduced_search_returns_paths(self) -> None:
        items = search_best_characteristics_to_penultimate(
            cipher_name="klein",
            total_rounds=5,
            block_bits=32,
            key_bits=64,
            top_k=3,
            beam_width=40,
            max_outputs_per_active_chunk=4,
            max_candidates_per_state=64,
            max_initial_active_chunks=1,
            max_initial_deltas=6,
        )
        self.assertGreater(len(items), 0)
        self.assertEqual(len(items[0].deltas), 5)


if __name__ == "__main__":
    unittest.main()
