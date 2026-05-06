import unittest

from find_characteristics.spn16_characteristic_search import (
    build_ddt,
    build_perm_lut,
    ddt_probabilities,
    search_best_characteristics_to_penultimate,
    search_high_probability_characteristics_to_penultimate,
)
from cryptosystems import spn16


class TestSPN16CharacteristicSearch(unittest.TestCase):
    def setUp(self) -> None:
        ddt = build_ddt(spn16.S_BOX)
        self.trans = ddt_probabilities(ddt)
        self.perm_lut = build_perm_lut()

    def test_penultimate_search_returns_paths(self) -> None:
        items = search_high_probability_characteristics_to_penultimate(
            delta_in=0x0B00,
            total_rounds=5,
            top_k=3,
            trans=self.trans,
            perm_lut=self.perm_lut,
            beam_width=80,
            max_outputs_per_active_nibble=4,
        )
        self.assertGreater(len(items), 0)
        self.assertEqual(len(items[0].deltas), 5)

    def test_best_penultimate_search_returns_paths(self) -> None:
        items = search_best_characteristics_to_penultimate(
            total_rounds=5,
            top_k=3,
            trans=self.trans,
            perm_lut=self.perm_lut,
            beam_width=80,
            max_outputs_per_active_nibble=4,
            max_initial_active_nibbles=2,
            max_initial_deltas=8,
        )
        self.assertGreater(len(items), 0)
        self.assertEqual(len(items[0].deltas), 5)
        self.assertNotEqual(items[0].deltas[0], 0)


if __name__ == "__main__":
    unittest.main()
