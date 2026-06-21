import unittest

from cryptosystems import aes
from find_characteristics.standard_characteristic_search import (
    THRESHOLD_PROBABILITY,
    build_klein_6_round_characteristic,
    search_aes_3_round_characteristic,
)


class TestStandardCharacteristics(unittest.TestCase):
    def test_aes_uses_128_bit_blocks(self) -> None:
        self.assertEqual(128, aes.BLOCK_BITS)
        self.assertEqual(16, aes.BLOCK_BYTES)
        self.assertEqual(128, aes.KEY_BITS)

    def test_aes_3_round_characteristic_passes_threshold(self) -> None:
        characteristic = search_aes_3_round_characteristic()

        self.assertEqual(128, characteristic.block_bits)
        self.assertEqual(3, len(characteristic.rounds))
        self.assertEqual(54.0, characteristic.weight)
        self.assertGreater(characteristic.probability, THRESHOLD_PROBABILITY)
        self.assertEqual(
            [4, 1, 4],
            [round_record.active_sboxes for round_record in characteristic.rounds],
        )

    def test_klein_6_round_characteristic_passes_threshold(self) -> None:
        characteristic = build_klein_6_round_characteristic()

        self.assertEqual(64, characteristic.block_bits)
        self.assertEqual(6, len(characteristic.rounds))
        self.assertEqual(62.0, characteristic.weight)
        self.assertGreater(characteristic.probability, THRESHOLD_PROBABILITY)
        self.assertEqual(
            [2.0, 10.0, 13.0, 11.0, 15.0, 11.0],
            [round_record.weight for round_record in characteristic.rounds],
        )


if __name__ == "__main__":
    unittest.main()
