"""Conteo cuántico de ``R(x)`` mediante estimación de fase sobre Grover.

Convención usada: para un dominio acolchado ``N=2^m`` y ``M=R(x)``,
``sin^2(theta)=M/N``. La iteración de Grover tiene autofases ``exp(±2i theta)``
y QPE estima ``phi=theta/pi``; por tanto ``M=N sin^2(pi phi)``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector

from .classical_attack import KnownPair
from .oracles import build_O2, grover_iteration, phase_oracle
from .utils import required_qubits


@dataclass(frozen=True)
class QuantumCountingResult:
    """Diagnóstico completo de ``R_tilde(x)``."""

    candidate: int | None
    real_count: int
    estimated_count: float
    absolute_error: float
    t: int
    m: int
    N: int
    measured_value: int
    phase: float
    epsilon: float
    count_error_bound: float
    probabilities: tuple[float, ...]


def inverse_qft(num_qubits: int) -> QuantumCircuit:
    """QFT inversa sin aproximaciones."""
    if num_qubits < 1:
        raise ValueError("num_qubits debe ser positivo.")
    circuit = QuantumCircuit(num_qubits, name="QFT_dagger")
    for left in range(num_qubits // 2):
        circuit.swap(left, num_qubits - left - 1)
    for target in range(num_qubits):
        for control in range(target):
            angle = -np.pi / (2 ** (target - control))
            circuit.cp(angle, control, target)
        circuit.h(target)
    return circuit


def build_quantum_counting_circuit(
    marked_bits: Sequence[int],
    t: int,
) -> QuantumCircuit:
    """Construye QPE sobre la iteración de Grover asociada a ``O_2``."""
    if t < 1:
        raise ValueError("t debe ser positivo.")
    if len(marked_bits) < 2 or (len(marked_bits) & (len(marked_bits) - 1)):
        raise ValueError("marked_bits debe tener longitud potencia de dos >= 2.")
    if any(bit not in (0, 1, False, True) for bit in marked_bits):
        raise ValueError("marked_bits solo puede contener 0 y 1.")

    N = len(marked_bits)
    m = required_qubits(N)
    marked_indices = [
        index for index, marked in enumerate(marked_bits) if marked
    ]
    O_2 = phase_oracle(marked_indices, m, name="O_2")
    G = grover_iteration(O_2).to_gate(label="G")
    controlled_G = G.control(1)

    total_qubits = t + m
    counting_register = list(range(t))
    index_register = list(range(t, total_qubits))
    circuit = QuantumCircuit(total_qubits, name="QuantumCounting")
    circuit.h(counting_register)
    circuit.h(index_register)

    for power, control in enumerate(counting_register):
        for _ in range(1 << power):
            circuit.append(controlled_G, [control, *index_register])

    circuit.compose(
        inverse_qft(t),
        qubits=counting_register,
        inplace=True,
    )
    return circuit


def _count_error_bound(real_count: int, N: int, t: int) -> float:
    """Cota estándar de error del conteo basada en la resolución de QPE."""
    scale = 1 << t
    return (
        2 * np.pi * np.sqrt(real_count * (N - real_count)) / scale
        + (np.pi**2) * N / (scale**2)
    )


def quantum_count_marked(
    marked_bits: Sequence[int],
    t: int,
    *,
    candidate: int | None = None,
    debug: bool = False,
    return_details: bool = False,
) -> float | QuantumCountingResult:
    """Estima el número de unos de una tabla clásica mediante conteo cuántico."""
    circuit = build_quantum_counting_circuit(marked_bits, t)
    statevector = Statevector.from_instruction(circuit)
    counting_register = list(range(t))
    probabilities = np.asarray(
        statevector.probabilities(qargs=counting_register),
        dtype=float,
    )
    measured_value = int(np.argmax(probabilities))
    raw_phase = measured_value / (1 << t)
    phase = min(raw_phase, 1.0 - raw_phase)
    N = len(marked_bits)
    estimated_count = float(N * np.sin(np.pi * phase) ** 2)
    real_count = int(sum(int(bit) for bit in marked_bits))
    result = QuantumCountingResult(
        candidate=candidate,
        real_count=real_count,
        estimated_count=estimated_count,
        absolute_error=abs(estimated_count - real_count),
        t=t,
        m=required_qubits(N),
        N=N,
        measured_value=measured_value,
        phase=phase,
        epsilon=1.0 / (1 << t),
        count_error_bound=float(_count_error_bound(real_count, N, t)),
        probabilities=tuple(float(value) for value in probabilities),
    )
    if debug:
        print(
            "R(x)={real}, R_tilde(x)={estimated:.6f}, error={error:.6f}, "
            "t={t}, m={m}, epsilon={epsilon:.6f}, cota={bound:.6f}".format(
                real=result.real_count,
                estimated=result.estimated_count,
                error=result.absolute_error,
                t=result.t,
                m=result.m,
                epsilon=result.epsilon,
                bound=result.count_error_bound,
            )
        )
    return result if return_details else result.estimated_count


def quantum_counting(
    candidate: int,
    pairs: Sequence[KnownPair | Sequence[int]],
    alpha_expected: int,
    t: int,
    *,
    debug: bool = False,
    return_details: bool = False,
) -> float | QuantumCountingResult:
    """Estima ``R(candidate)`` usando el oráculo ``O_2``."""
    O_2 = build_O2(candidate, pairs, alpha_expected)
    return quantum_count_marked(
        O_2.marked_bits,
        t,
        candidate=candidate,
        debug=debug,
        return_details=return_details,
    )

