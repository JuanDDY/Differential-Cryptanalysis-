"""Procedimiento iterativo tipo Dürr--Høyer para maximizar ``R_tilde``."""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Literal

from .classical_attack import KnownPair, count_right_pairs
from .grover_search import grover_search_details
from .oracles import build_O1
from .quantum_counting import quantum_counting
from .utils import required_qubits, validate_u16


@dataclass(frozen=True)
class DurrHoyerStep:
    """Una comparación y posible actualización ``y <- y'``."""

    iteration: int
    threshold_before: int
    score_before: float
    marked_count: int
    measured_index: int | None
    measured_candidate: int | None
    measured_score: float | None
    updated: bool


@dataclass(frozen=True)
class DurrHoyerResult:
    """Resultado final del máximo experimental."""

    candidate: int
    score: float
    initial_candidate: int
    initial_score: float
    mode: str
    c: float
    iterations: int
    history: tuple[DurrHoyerStep, ...]


def durr_hoyer_max(
    K_cand: Sequence[int],
    pairs: Sequence[KnownPair | Sequence[int]] | None,
    alpha_expected: int,
    *,
    t: int = 6,
    mode: Literal["exact", "estimated"] = "exact",
    iterations: int | None = None,
    c: float = 2.0,
    seed: int | None = None,
    initial_threshold: int | None = None,
    score_function: Callable[[int], float] | None = None,
    shots: int = 1024,
) -> DurrHoyerResult:
    """Busca una candidata con conteo máximo mediante umbrales sucesivos.

    Cuando ``iterations`` es ``None``, ``c`` fija el presupuesto
    ``ceil(c*sqrt(|K_cand|))``. La simulación conoce la lista marcada para
    construir ``O_1``; esto no representa una síntesis reversible optimizada.
    """
    if not K_cand:
        raise ValueError("K_cand no puede estar vacío.")
    candidates = tuple(validate_u16(value, "candidate") for value in K_cand)
    if len(set(candidates)) != len(candidates):
        raise ValueError("K_cand no debe contener duplicados.")
    if mode not in {"exact", "estimated"}:
        raise ValueError("mode debe ser 'exact' o 'estimated'.")
    if c <= 0:
        raise ValueError("c debe ser positivo.")
    custom_score_function = score_function is not None
    if score_function is None and pairs is None:
        raise ValueError("Se requieren pairs o score_function.")

    if score_function is None:
        if mode == "exact":
            score_function = lambda candidate: float(
                count_right_pairs(candidate, pairs or (), alpha_expected)
            )
        else:
            score_function = lambda candidate: float(
                quantum_counting(candidate, pairs or (), alpha_expected, t)
            )

    cache: dict[int, float] = {}

    def score(candidate: int) -> float:
        if candidate not in cache:
            cache[candidate] = float(score_function(candidate))
        return cache[candidate]

    rng = random.Random(seed)
    if initial_threshold is None:
        y = rng.choice(candidates)
    else:
        validate_u16(initial_threshold, "initial_threshold")
        if initial_threshold not in candidates:
            raise ValueError("initial_threshold debe pertenecer a K_cand.")
        y = initial_threshold
    initial_candidate = y
    initial_score = score(y)

    max_iterations = (
        math.ceil(c * math.sqrt(len(candidates)))
        if iterations is None
        else iterations
    )
    if max_iterations < 0:
        raise ValueError("iterations no puede ser negativo.")
    key_bits = required_qubits(len(candidates))
    history: list[DurrHoyerStep] = []

    for iteration in range(max_iterations):
        threshold_before = y
        score_before = score(y)

        if custom_score_function:
            marked_indices = [
                index
                for index, candidate in enumerate(candidates)
                if score(candidate) > score_before
            ]
        else:
            O_1 = build_O1(
                candidates,
                y,
                pairs or (),
                alpha_expected,
                mode=mode,
                t=t,
            )
            cache.update(zip(candidates, O_1.candidate_scores, strict=True))
            cache[y] = O_1.threshold_score
            score_before = O_1.threshold_score
            marked_indices = list(O_1.marked_indices)

        if not marked_indices:
            history.append(
                DurrHoyerStep(
                    iteration=iteration,
                    threshold_before=threshold_before,
                    score_before=score_before,
                    marked_count=0,
                    measured_index=None,
                    measured_candidate=None,
                    measured_score=None,
                    updated=False,
                )
            )
            break

        grover_result = grover_search_details(
            marked_indices,
            key_bits,
            shots=shots,
            seed=rng.randrange(1 << 32),
        )
        measured_index = grover_result.candidate
        measured_candidate = (
            candidates[measured_index]
            if measured_index < len(candidates)
            else None
        )
        measured_score = (
            score(measured_candidate) if measured_candidate is not None else None
        )
        updated = bool(
            measured_candidate is not None and measured_score > score_before
        )
        if updated:
            y = measured_candidate

        history.append(
            DurrHoyerStep(
                iteration=iteration,
                threshold_before=threshold_before,
                score_before=score_before,
                marked_count=len(marked_indices),
                measured_index=measured_index,
                measured_candidate=measured_candidate,
                measured_score=measured_score,
                updated=updated,
            )
        )

    return DurrHoyerResult(
        candidate=y,
        score=score(y),
        initial_candidate=initial_candidate,
        initial_score=initial_score,
        mode=mode,
        c=c,
        iterations=len(history),
        history=tuple(history),
    )
