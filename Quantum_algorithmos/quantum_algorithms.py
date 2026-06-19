from __future__ import annotations

import numpy as np
from qiskit import QuantumCircuit


def qft(num_qubits: int) -> QuantumCircuit:
    """Transformada cuántica de Fourier sobre num_qubits."""
    if num_qubits < 1:
        raise ValueError("num_qubits debe ser al menos 1.")

    circuit = QuantumCircuit(num_qubits, name="QFT")

    for target in reversed(range(num_qubits)):
        circuit.h(target)

        for control in reversed(range(target)):
            angle = np.pi / (2 ** (target - control))
            circuit.cp(angle, control, target)

    for left in range(num_qubits // 2):
        circuit.swap(left, num_qubits - left - 1)

    return circuit


def inverse_qft(num_qubits: int) -> QuantumCircuit:
    """Transformada cuántica de Fourier inversa sobre num_qubits."""
    if num_qubits < 1:
        raise ValueError("num_qubits debe ser al menos 1.")

    circuit = QuantumCircuit(num_qubits, name="QFT_inv")

    for left in range(num_qubits // 2):
        circuit.swap(left, num_qubits - left - 1)

    for target in range(num_qubits):
        for control in range(target):
            angle = -np.pi / (2 ** (target - control))
            circuit.cp(angle, control, target)

        circuit.h(target)

    return circuit


def apply_multi_controlled_z(circuit: QuantumCircuit, num_qubits: int) -> None:
    """Aplica una compuerta Z multicontrolada sobre todos los qubits del circuito."""
    if num_qubits < 1:
        raise ValueError("num_qubits debe ser al menos 1.")

    if num_qubits == 1:
        circuit.z(0)
        return

    target = num_qubits - 1
    controls = list(range(num_qubits - 1))

    circuit.h(target)
    circuit.mcx(controls, target)
    circuit.h(target)


def _validate_marked_states(marked_states: list[str]) -> int:
    if not marked_states:
        raise ValueError("Debe haber al menos un estado marcado.")

    num_qubits = len(marked_states[0])

    if num_qubits == 0:
        raise ValueError("Los estados marcados no pueden ser cadenas vacías.")

    for state in marked_states:
        if len(state) != num_qubits:
            raise ValueError("Todos los estados marcados deben tener la misma longitud.")

        if any(bit not in {"0", "1"} for bit in state):
            raise ValueError("Cada estado marcado debe ser una cadena binaria.")

    return num_qubits


def phase_oracle(marked_states: list[str]) -> QuantumCircuit:
    """
    Oráculo de fase para uno o varios estados marcados.

    Implementa:
        |x> -> -|x> si x está marcado,
        |x> ->  |x> si x no está marcado.
    """
    num_qubits = _validate_marked_states(marked_states)
    oracle = QuantumCircuit(num_qubits, name="O")

    for marked_state in marked_states:
        for qubit, bit in enumerate(reversed(marked_state)):
            if bit == "0":
                oracle.x(qubit)

        apply_multi_controlled_z(oracle, num_qubits)

        for qubit, bit in enumerate(reversed(marked_state)):
            if bit == "0":
                oracle.x(qubit)

    return oracle


def diffuser(num_qubits: int) -> QuantumCircuit:
    """Operador de difusión de Grover."""
    if num_qubits < 1:
        raise ValueError("num_qubits debe ser al menos 1.")

    diffusion = QuantumCircuit(num_qubits, name="D")

    diffusion.h(range(num_qubits))
    diffusion.x(range(num_qubits))

    apply_multi_controlled_z(diffusion, num_qubits)

    diffusion.x(range(num_qubits))
    diffusion.h(range(num_qubits))

    # Fase global para que coincida con la convención usual 2|gamma><gamma| - I.
    diffusion.global_phase += np.pi

    return diffusion


def grover_operator(marked_states: list[str]) -> QuantumCircuit:
    """Iteración de Grover G = D O."""
    num_qubits = _validate_marked_states(marked_states)

    operator = QuantumCircuit(num_qubits, name="G")
    operator.append(phase_oracle(marked_states).to_gate(label="O"), range(num_qubits))
    operator.append(diffuser(num_qubits).to_gate(label="D"), range(num_qubits))

    return operator


def quantum_counting_unitary(
    marked_states: list[str],
    counting_qubits: int,
) -> QuantumCircuit:
    """
    Circuito unitario del algoritmo de conteo cuántico.

    El primer registro tiene counting_qubits.
    El segundo registro tiene search_qubits = len(marked_states[0]).
    """
    if counting_qubits < 1:
        raise ValueError("counting_qubits debe ser al menos 1.")

    search_qubits = _validate_marked_states(marked_states)

    total_qubits = counting_qubits + search_qubits
    counting_register = list(range(counting_qubits))
    search_register = list(range(counting_qubits, total_qubits))

    circuit = QuantumCircuit(total_qubits, name="QuantumCounting")

    circuit.h(counting_register)
    circuit.h(search_register)

    grover_gate = grover_operator(marked_states).to_gate(label="G")
    controlled_grover = grover_gate.control(1)

    for control_power, control in enumerate(counting_register):
        repetitions = 2 ** control_power

        for _ in range(repetitions):
            circuit.append(controlled_grover, [control] + search_register)

    circuit.append(
        inverse_qft(counting_qubits).to_gate(label="QFT†"),
        counting_register,
    )

    return circuit


def estimate_marked_items(
    measured_value: int,
    counting_qubits: int,
    search_qubits: int,
) -> tuple[float, float]:
    """
    A partir del resultado medido en el registro de conteo, estima la fase
    y el número de estados marcados.
    """
    if counting_qubits < 1:
        raise ValueError("counting_qubits debe ser al menos 1.")

    if search_qubits < 1:
        raise ValueError("search_qubits debe ser al menos 1.")

    max_value = 2 ** counting_qubits

    if not 0 <= measured_value < max_value:
        raise ValueError(f"measured_value debe estar entre 0 y {max_value - 1}.")

    phase = measured_value / max_value

    # Corrección simétrica: omega y 1 - omega codifican el mismo conteo.
    if phase > 0.5:
        phase = 1 - phase

    estimated_marked = (2 ** search_qubits) * (np.sin(np.pi * phase) ** 2)

    return phase, estimated_marked


def top_counting_results(
    probabilities: np.ndarray,
    counting_qubits: int,
    search_qubits: int,
    top_k: int = 4,
    min_probability: float = 1e-10,
) -> list[dict[str, float | str | int]]:
    """Devuelve los resultados de fase más probables del conteo cuántico."""
    top_values = np.argsort(probabilities)[::-1][:top_k]
    results = []

    for measured_value in top_values:
        probability = float(probabilities[measured_value])

        if probability < min_probability:
            continue

        bitstring = format(measured_value, f"0{counting_qubits}b")
        phase, estimated_marked = estimate_marked_items(
            measured_value,
            counting_qubits,
            search_qubits,
        )

        results.append(
            {
                "measured_value": int(measured_value),
                "bits": bitstring,
                "phase": float(phase),
                "probability": probability,
                "estimated_marked": float(estimated_marked),
            }
        )

    return results