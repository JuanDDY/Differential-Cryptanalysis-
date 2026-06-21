"""Oráculos simulados ``O_2`` y ``O_1`` del capítulo 6.

No se sintetiza reversiblemente el cifrador. Los indicadores ``RP`` se
calculan desde la tabla clásica Q1 y se cargan como oráculos de fase. Esto
reproduce el comportamiento lógico requerido y mantiene viable la simulación.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

import numpy as np
from qiskit import QuantumCircuit

from .classical_attack import KnownPair, count_right_pairs, right_pair
from .utils import next_power_of_two, required_qubits, validate_u16


@dataclass(frozen=True)
class O2Oracle:
    """Oráculo ``O_2`` y tabla clásica ``e(x,j)`` que representa."""

    candidate: int
    marked_bits: tuple[int, ...]
    number_of_pairs: int
    domain_size: int
    index_qubits: int
    circuit: QuantumCircuit

    @property
    def marked_indices(self) -> tuple[int, ...]:
        return tuple(index for index, bit in enumerate(self.marked_bits) if bit)


@dataclass(frozen=True)
class O1Oracle:
    """Oráculo ``O_1`` sobre índices de la lista explícita ``K_cand``."""

    K_cand: tuple[int, ...]
    threshold: int
    threshold_score: float
    candidate_scores: tuple[float, ...]
    marked_indices: tuple[int, ...]
    key_bits: int
    mode: str
    circuit: QuantumCircuit

    @property
    def marked_candidates(self) -> tuple[int, ...]:
        return tuple(self.K_cand[index] for index in self.marked_indices)


def apply_multi_controlled_z(circuit: QuantumCircuit, qubits: Sequence[int]) -> None:
    """Aplica Z controlada por todos los qubits indicados."""
    if not qubits:
        raise ValueError("Se necesita al menos un qubit.")
    if len(qubits) == 1:
        circuit.z(qubits[0])
        return
    target = qubits[-1]
    controls = list(qubits[:-1])
    circuit.h(target)
    circuit.mcx(controls, target)
    circuit.h(target)


def phase_oracle(
    marked_values: Sequence[int],
    num_qubits: int,
    name: str = "O",
) -> QuantumCircuit:
    """Construye ``|j> -> (-1)^[j marcado] |j>``."""
    if num_qubits < 1:
        raise ValueError("num_qubits debe ser positivo.")
    domain_size = 1 << num_qubits
    unique_marked = sorted(set(marked_values))
    if any(value < 0 or value >= domain_size for value in unique_marked):
        raise ValueError("Hay un estado marcado fuera del dominio.")

    oracle = QuantumCircuit(num_qubits, name=name)
    qubits = list(range(num_qubits))
    for value in unique_marked:
        for qubit in qubits:
            if ((value >> qubit) & 1) == 0:
                oracle.x(qubit)
        apply_multi_controlled_z(oracle, qubits)
        for qubit in qubits:
            if ((value >> qubit) & 1) == 0:
                oracle.x(qubit)
    return oracle


def diffuser(num_qubits: int) -> QuantumCircuit:
    """Implementa ``D = 2|s><s| - I``."""
    if num_qubits < 1:
        raise ValueError("num_qubits debe ser positivo.")
    circuit = QuantumCircuit(num_qubits, name="D")
    qubits = list(range(num_qubits))
    circuit.h(qubits)
    circuit.x(qubits)
    apply_multi_controlled_z(circuit, qubits)
    circuit.x(qubits)
    circuit.h(qubits)
    # El circuito anterior implementa I - 2|s><s|; se corrige la fase global.
    circuit.global_phase += np.pi
    return circuit


def grover_iteration(oracle: QuantumCircuit) -> QuantumCircuit:
    """Construye la iteración ``G = D O`` asociada a un oráculo de fase."""
    num_qubits = oracle.num_qubits
    circuit = QuantumCircuit(num_qubits, name="G")
    circuit.compose(oracle, inplace=True)
    circuit.compose(diffuser(num_qubits), inplace=True)
    return circuit


def build_O2(
    candidate: int,
    pairs: Sequence[KnownPair | Sequence[int]],
    alpha_expected: int,
) -> O2Oracle:
    """Construye ``O_2`` para una candidata fija ``x``.

    Si el número de pares no es potencia de dos, el dominio se rellena con
    índices ficticios no marcados. Por ello la convención de conteo usa
    ``N = 2^m`` y no el número bruto de pares.
    """
    validate_u16(candidate, "candidate")
    if not pairs:
        raise ValueError("pairs no puede estar vacío.")
    domain_size = max(2, next_power_of_two(len(pairs)))
    index_qubits = required_qubits(domain_size)
    marked_bits = [
        right_pair(candidate, pair, alpha_expected) for pair in pairs
    ]
    marked_bits.extend([0] * (domain_size - len(marked_bits)))
    marked_indices = [
        index for index, marked in enumerate(marked_bits) if marked
    ]
    circuit = phase_oracle(marked_indices, index_qubits, name="O_2")
    return O2Oracle(
        candidate=candidate,
        marked_bits=tuple(marked_bits),
        number_of_pairs=len(pairs),
        domain_size=domain_size,
        index_qubits=index_qubits,
        circuit=circuit,
    )


def build_O1(
    K_cand: Sequence[int],
    threshold: int,
    pairs: Sequence[KnownPair | Sequence[int]],
    alpha_expected: int,
    *,
    mode: Literal["exact", "estimated"] = "exact",
    t: int = 6,
) -> O1Oracle:
    """Construye ``O_1`` para ``R(x) > R_tilde(y)``.

    ``O_1`` actúa sobre índices de la lista explícita ``K_cand``. Esta
    codificación permite experimentar con un subconjunto pequeño de subclaves
    de 16 bits sin confundir el índice de Grover con el valor de la subclave.
    """
    if not K_cand:
        raise ValueError("K_cand no puede estar vacío.")
    candidates = tuple(validate_u16(value, "candidate") for value in K_cand)
    validate_u16(threshold, "threshold")
    if mode not in {"exact", "estimated"}:
        raise ValueError("mode debe ser 'exact' o 'estimated'.")

    if mode == "exact":
        scores = tuple(
            float(count_right_pairs(candidate, pairs, alpha_expected))
            for candidate in candidates
        )
        threshold_score = float(
            count_right_pairs(threshold, pairs, alpha_expected)
        )
    else:
        # Importación local para evitar el ciclo oracles <-> quantum_counting.
        from .quantum_counting import quantum_counting

        scores = tuple(
            float(quantum_counting(candidate, pairs, alpha_expected, t))
            for candidate in candidates
        )
        threshold_score = float(
            quantum_counting(threshold, pairs, alpha_expected, t)
        )

    marked_indices = tuple(
        index for index, score in enumerate(scores) if score > threshold_score
    )
    key_bits = required_qubits(len(candidates))
    circuit = phase_oracle(marked_indices, key_bits, name="O_1")
    return O1Oracle(
        K_cand=candidates,
        threshold=threshold,
        threshold_score=threshold_score,
        candidate_scores=scores,
        marked_indices=marked_indices,
        key_bits=key_bits,
        mode=mode,
        circuit=circuit,
    )

