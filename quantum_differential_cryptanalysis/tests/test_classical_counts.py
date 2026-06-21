"""Pruebas de ``RP(y_r,i)`` y ``R(y_r)``."""

from quantum_differential_cryptanalysis.src.classical_attack import (
    count_right_pairs,
    encrypt_pairs,
    right_pair,
)
from quantum_differential_cryptanalysis.src.spn16 import split_master_key
from quantum_differential_cryptanalysis.src.utils import format_partial_key


ALPHA_EXPECTED = 0x0606
CORRECT_CANDIDATE = 0x8899


def _required_pairs():
    subkeys = split_master_key("00112233445566778899")
    return encrypt_pairs(
        [
            (0x002B, 0x0B2B),
            (0x0000, 0x0B00),
        ],
        subkeys,
    )


def test_required_right_pair_is_marked() -> None:
    correct_pair, _ = _required_pairs()
    assert right_pair(CORRECT_CANDIDATE, correct_pair, ALPHA_EXPECTED) == 1


def test_required_wrong_pair_is_not_marked() -> None:
    _, wrong_pair = _required_pairs()
    assert right_pair(CORRECT_CANDIDATE, wrong_pair, ALPHA_EXPECTED) == 0


def test_R_equals_sum_of_RP_indicators() -> None:
    pairs = _required_pairs()
    indicators = [
        right_pair(CORRECT_CANDIDATE, pair, ALPHA_EXPECTED)
        for pair in pairs
    ]
    assert count_right_pairs(CORRECT_CANDIDATE, pairs, ALPHA_EXPECTED) == sum(
        indicators
    )


def test_partial_key_notation_hides_inactive_nibbles() -> None:
    assert format_partial_key(0x0809, ALPHA_EXPECTED) == "0x?8?9"
    assert format_partial_key(0x8899, ALPHA_EXPECTED) == "0x?8?9"
