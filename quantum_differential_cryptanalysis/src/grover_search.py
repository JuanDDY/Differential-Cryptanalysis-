"""Búsqueda de Grover sobre índices de candidatas de subclave."""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector

from .oracles import diffuser, phase_oracle


@dataclass(frozen=True)
class GroverResult:
    """Resultado medido y distribución simulada de Grover."""

    candidate: int
    iterations: int
    success_probability: float
    probabilities: tuple[float, ...]
    counts: tuple[int, ...]


def optimal_grover_iterations(number_of_states: int, marked_count: int) -> int:
    """Número de iteraciones para un número conocido de estados marcados."""
    if not 0 < marked_count <= number_of_states:
        raise ValueError("marked_count debe estar entre 1 y number_of_states.")
    theta = math.asin(math.sqrt(marked_count / number_of_states))
    return max(0, int(round(math.pi / (4 * theta) - 0.5)))


def build_grover_circuit(
    marked_candidates: list[int],
    key_bits: int,
    iterations: int | None = None,
) -> tuple[QuantumCircuit, int]:
    """Prepara ``|Psi>`` y aplica ``G`` el número indicado de veces."""
    if key_bits < 1:
        raise ValueError("key_bits debe ser positivo.")
    domain_size = 1 << key_bits
    marked = sorted(set(marked_candidates))
    if not marked:
        raise ValueError("Debe existir al menos una candidata marcada.")
    if any(candidate < 0 or candidate >= domain_size for candidate in marked):
        raise ValueError("Hay una candidata marcada fuera del dominio.")
    if iterations is None:
        iterations = optimal_grover_iterations(domain_size, len(marked))
    if iterations < 0:
        raise ValueError("iterations no puede ser negativo.")

    circuit = QuantumCircuit(key_bits, name="GroverSearch")
    circuit.h(range(key_bits))
    oracle = phase_oracle(marked, key_bits, name="O_1")
    diffusion = diffuser(key_bits)
    for _ in range(iterations):
        circuit.compose(oracle, inplace=True)
        circuit.compose(diffusion, inplace=True)
    return circuit, iterations


def grover_search_details(
    marked_candidates: list[int],
    key_bits: int,
    *,
    iterations: int | None = None,
    shots: int = 1024,
    seed: int | None = None,
) -> GroverResult:
    """Simula la medición de Grover y devuelve la candidata modal."""
    if shots < 1:
        raise ValueError("shots debe ser positivo.")
    circuit, used_iterations = build_grover_circuit(
        marked_candidates,
        key_bits,
        iterations,
    )
    probabilities = np.asarray(
        Statevector.from_instruction(circuit).probabilities(),
        dtype=float,
    )
    rng = np.random.default_rng(seed)
    samples = rng.choice(len(probabilities), size=shots, p=probabilities)
    counts = np.bincount(samples, minlength=len(probabilities))
    candidate = int(np.argmax(counts))
    success_probability = float(
        sum(probabilities[index] for index in set(marked_candidates))
    )
    return GroverResult(
        candidate=candidate,
        iterations=used_iterations,
        success_probability=success_probability,
        probabilities=tuple(float(value) for value in probabilities),
        counts=tuple(int(value) for value in counts),
    )


def grover_search(
    marked_candidates: list[int],
    key_bits: int,
    *,
    iterations: int | None = None,
    shots: int = 1024,
    seed: int | None = None,
) -> int:
    """Mide y devuelve un índice candidato."""
    return grover_search_details(
        marked_candidates,
        key_bits,
        iterations=iterations,
        shots=shots,
        seed=seed,
    ).candidate

