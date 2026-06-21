"""SPN16 de Heys usado por el experimento del capítulo 6.

El cifrador tiene bloques de 16 bits, cuatro S-boxes de 4 bits por capa y la
permutación clásica de Heys. Con cuatro rondas usa cinco subclaves: las tres
primeras rondas terminan en permutación y la cuarta termina en blanqueo.
"""

from __future__ import annotations

from collections.abc import Sequence

from .utils import format_bin16, format_hex16, validate_u16

SBOX = [
    0xE,
    0x4,
    0xD,
    0x1,
    0x2,
    0xF,
    0xB,
    0x8,
    0x3,
    0xA,
    0x6,
    0xC,
    0x5,
    0x9,
    0x0,
    0x7,
]

INV_SBOX = [0] * 16
for _source, _target in enumerate(SBOX):
    INV_SBOX[_target] = _source

# Alias compatible con la notación usada en los notebooks previos.
SBOX_INV = INV_SBOX

# Mapeo 1-based: el bit de entrada i se mueve a PBOX[i].
PBOX = [0, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16]
PBOX_INV = [0] * 17
for _source in range(1, 17):
    PBOX_INV[PBOX[_source]] = _source


def substitute_nibbles(value: int) -> int:
    """Aplica cuatro S-boxes de Heys en paralelo."""
    validate_u16(value)
    result = 0
    for shift in (12, 8, 4, 0):
        result |= SBOX[(value >> shift) & 0xF] << shift
    return result


def inverse_substitute_nibbles(value: int) -> int:
    """Aplica la S-box inversa a los cuatro nibbles."""
    validate_u16(value)
    result = 0
    for shift in (12, 8, 4, 0):
        result |= INV_SBOX[(value >> shift) & 0xF] << shift
    return result


def _permute_with_table(value: int, table: Sequence[int]) -> int:
    validate_u16(value)
    result = 0
    for source_position in range(1, 17):
        source_bit = (value >> (16 - source_position)) & 1
        target_position = table[source_position]
        result |= source_bit << (16 - target_position)
    return result


def permute_bits(value: int) -> int:
    """Aplica la permutación de bits de Heys."""
    return _permute_with_table(value, PBOX)


def inverse_permute_bits(value: int) -> int:
    """Deshace la permutación de bits."""
    return _permute_with_table(value, PBOX_INV)


def split_master_key(master_key_hex: str, rounds: int = 4) -> list[int]:
    """Separa la clave maestra en ``rounds + 1`` subclaves de 16 bits."""
    if rounds < 1:
        raise ValueError("rounds debe ser positivo.")
    normalized = master_key_hex.removeprefix("0x").removeprefix("0X")
    expected_length = 4 * (rounds + 1)
    if len(normalized) != expected_length:
        raise ValueError(
            f"La clave debe tener exactamente {expected_length} dígitos hexadecimales."
        )
    try:
        int(normalized, 16)
    except ValueError as exc:
        raise ValueError("master_key_hex no es hexadecimal válido.") from exc
    return [
        int(normalized[offset : offset + 4], 16)
        for offset in range(0, expected_length, 4)
    ]


def encrypt_block(plaintext: int, subkeys: Sequence[int]) -> int:
    """Implementa ``E_K`` para el SPN16.

    Rondas 1 a r-1: ``XOR K -> SBOX -> PBOX``.
    Ronda r: ``XOR K_r -> SBOX -> XOR y_r``.
    """
    validate_u16(plaintext, "plaintext")
    if len(subkeys) < 2:
        raise ValueError("Se necesitan al menos dos subclaves.")
    for index, subkey in enumerate(subkeys):
        validate_u16(subkey, f"subkeys[{index}]")

    state = plaintext
    for subkey in subkeys[:-2]:
        state = permute_bits(substitute_nibbles(state ^ subkey))
    state = substitute_nibbles(state ^ subkeys[-2])
    return (state ^ subkeys[-1]) & 0xFFFF


def encryption_trace(plaintext: int, subkeys: Sequence[int]) -> list[tuple[str, int]]:
    """Devuelve los estados intermedios para documentación y pruebas."""
    validate_u16(plaintext, "plaintext")
    trace = [("plaintext", plaintext)]
    state = plaintext
    for round_index, subkey in enumerate(subkeys[:-2], start=1):
        state ^= subkey
        trace.append((f"round_{round_index}_after_key", state))
        state = substitute_nibbles(state)
        trace.append((f"round_{round_index}_after_sbox", state))
        state = permute_bits(state)
        trace.append((f"round_{round_index}_after_pbox", state))

    final_round = len(subkeys) - 1
    state ^= subkeys[-2]
    trace.append((f"round_{final_round}_before_sbox", state))
    state = substitute_nibbles(state)
    trace.append((f"round_{final_round}_after_sbox", state))
    state ^= subkeys[-1]
    trace.append(("ciphertext", state))
    return trace


def decrypt_last_round_partial(ciphertext: int, candidate: int) -> int:
    """Calcula ``SBOX_INV(C XOR y_r)`` para una candidata ``y_r``.

    El resultado es la estimación del estado antes de la última capa de
    sustitución. Esta es la operación usada por ``RP(y_r, i)``.
    """
    validate_u16(ciphertext, "ciphertext")
    validate_u16(candidate, "candidate")
    return inverse_substitute_nibbles(ciphertext ^ candidate)


# Alias explícitos para facilitar la lectura junto a los notebooks previos.
spn_encrypt_block = encrypt_block
partial_decrypt_last_round = decrypt_last_round_partial
to_hex16 = format_hex16
to_bin16 = format_bin16

