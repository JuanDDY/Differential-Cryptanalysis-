"""Pruebas de Grover y del máximo tipo Dürr--Høyer."""

from quantum_differential_cryptanalysis.src.durr_hoyer_max import durr_hoyer_max
from quantum_differential_cryptanalysis.src.grover_search import (
    grover_search_details,
)


def test_grover_finds_marked_candidate_with_high_probability() -> None:
    result = grover_search_details([3], key_bits=3, shots=2048, seed=7)
    assert result.candidate == 3
    assert result.success_probability > 0.90


def test_durr_hoyer_improves_threshold_when_better_candidate_exists() -> None:
    result = durr_hoyer_max(
        K_cand=[0, 1, 2, 3],
        pairs=None,
        alpha_expected=0,
        score_function=lambda candidate: 5.0 if candidate == 2 else 0.0,
        initial_threshold=0,
        iterations=3,
        shots=1024,
        seed=11,
    )
    assert result.initial_score == 0.0
    assert result.score > result.initial_score
    assert result.candidate == 2

