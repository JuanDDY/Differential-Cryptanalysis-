"""Utilidades de representación y reducción del espacio ``K_cand``."""

from __future__ import annotations

import math


def validate_u16(value: int, name: str = "value") -> int:
    """Valida y devuelve un entero sin signo de 16 bits."""
    if not isinstance(value, int) or not 0 <= value <= 0xFFFF:
        raise ValueError(f"{name} debe ser un entero de 16 bits.")
    return value


def format_hex16(value: int) -> str:
    """Representa un valor como hexadecimal de 16 bits."""
    return f"0x{validate_u16(value):04X}"


def format_bin16(value: int) -> str:
    """Representa un valor como binario de 16 bits."""
    return f"{validate_u16(value):016b}"


def next_power_of_two(value: int) -> int:
    """Menor potencia de dos mayor o igual que ``value``."""
    if value < 1:
        raise ValueError("value debe ser positivo.")
    return 1 << (value - 1).bit_length()


def required_qubits(number_of_states: int) -> int:
    """Número mínimo de qubits para codificar al menos ese número de estados."""
    if number_of_states < 1:
        raise ValueError("number_of_states debe ser positivo.")
    return max(1, math.ceil(math.log2(number_of_states)))


def active_nibble_mask(alpha_expected: int) -> int:
    """Máscara de nibbles activos de ``alpha^(r-1)``.

    El ataque clásico de referencia recupera únicamente los nibbles cuya
    diferencia esperada no es cero. Para ``0x0606`` la máscara es ``0x0F0F``.
    """
    validate_u16(alpha_expected, "alpha_expected")
    mask = 0
    for shift in (12, 8, 4, 0):
        if ((alpha_expected >> shift) & 0xF) != 0:
            mask |= 0xF << shift
    if mask == 0:
        raise ValueError("alpha_expected debe contener al menos un nibble activo.")
    return mask


def embed_active_candidate(
    compact_candidate: int,
    alpha_expected: int,
    inactive_template: int = 0,
) -> int:
    """Inserta un candidato compacto en los nibbles activos.

    Para ``alpha_expected=0x0606``, ``compact_candidate=0x89`` se representa
    como ``0x0809``. Los nibbles inactivos no son recuperables con esta única
    característica y se toman de ``inactive_template``.
    """
    mask = active_nibble_mask(alpha_expected)
    validate_u16(inactive_template, "inactive_template")
    active_shifts = [
        shift for shift in (12, 8, 4, 0) if ((mask >> shift) & 0xF) == 0xF
    ]
    max_candidate = 1 << (4 * len(active_shifts))
    if not isinstance(compact_candidate, int) or not 0 <= compact_candidate < max_candidate:
        raise ValueError(
            f"compact_candidate debe estar entre 0 y {max_candidate - 1}."
        )

    result = inactive_template & (~mask & 0xFFFF)
    for index, shift in enumerate(reversed(active_shifts)):
        nibble = (compact_candidate >> (4 * index)) & 0xF
        result |= nibble << shift
    return result


def project_active_candidate(candidate: int, alpha_expected: int) -> int:
    """Compacta en un entero los nibbles atacados de una subclave."""
    validate_u16(candidate, "candidate")
    mask = active_nibble_mask(alpha_expected)
    compact = 0
    for shift in (12, 8, 4, 0):
        if ((mask >> shift) & 0xF) == 0xF:
            compact = (compact << 4) | ((candidate >> shift) & 0xF)
    return compact


def format_partial_key(candidate: int, alpha_expected: int) -> str:
    """Representa los nibbles recuperables y marca los demás con ``?``.

    Por ejemplo, para ``alpha_expected=0x0606`` tanto ``0x0809`` como
    ``0x8899`` se representan como ``0x?8?9``.
    """
    validate_u16(candidate, "candidate")
    mask = active_nibble_mask(alpha_expected)
    digits: list[str] = []
    for shift in (12, 8, 4, 0):
        if ((mask >> shift) & 0xF) == 0xF:
            digits.append(f"{(candidate >> shift) & 0xF:X}")
        else:
            digits.append("?")
    return "0x" + "".join(digits)
