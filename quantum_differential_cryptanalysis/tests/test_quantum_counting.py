"""Pruebas pequeñas del conteo cuántico."""

import pytest

from quantum_differential_cryptanalysis.src.quantum_counting import (
    quantum_count_marked,
)


@pytest.mark.parametrize(
    ("marked_bits", "expected", "tolerance"),
    [
        ([0] * 8, 0, 1e-9),
        ([1] + [0] * 7, 1, 0.25),
        ([1, 0, 1, 0, 1, 0, 0, 0], 3, 0.35),
    ],
)
def test_quantum_counting_known_solution_counts(
    marked_bits: list[int],
    expected: int,
    tolerance: float,
) -> None:
    estimated = quantum_count_marked(marked_bits, t=6)
    assert estimated == pytest.approx(expected, abs=tolerance)

