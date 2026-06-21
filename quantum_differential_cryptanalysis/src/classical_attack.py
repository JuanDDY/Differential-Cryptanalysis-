"""Soporte clásico del modelo Q1 y definición de ``RP`` y ``R``.

Los pares elegidos y sus cifrados se obtienen clásicamente. La parte cuántica
recibe solamente esta tabla clásica y el espacio reducido ``K_cand``.
"""

from __future__ import annotations

import random
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .spn16 import decrypt_last_round_partial, encrypt_block
from .utils import active_nibble_mask, validate_u16


@dataclass(frozen=True)
class KnownPair:
    """Par Q1 conocido: ``(P_i, P_i*, C_i, C_i*)``."""

    plaintext: int
    plaintext_star: int
    ciphertext: int
    ciphertext_star: int

    def __post_init__(self) -> None:
        for name, value in (
            ("plaintext", self.plaintext),
            ("plaintext_star", self.plaintext_star),
            ("ciphertext", self.ciphertext),
            ("ciphertext_star", self.ciphertext_star),
        ):
            validate_u16(value, name)


@dataclass(frozen=True)
class CandidateScore:
    """Resultado clásico ``(y_r, R(y_r))``."""

    candidate: int
    R_y: int


def generate_plaintext_pairs(
    alpha: int,
    number_of_pairs: int,
    seed: int | None = None,
) -> list[tuple[int, int]]:
    """Genera clásicamente pares ``(P_i, P_i*)`` con ``P_i XOR P_i*=alpha``."""
    validate_u16(alpha, "alpha")
    if number_of_pairs < 1:
        raise ValueError("number_of_pairs debe ser positivo.")
    rng = random.Random(seed)
    return [
        (plaintext, plaintext ^ alpha)
        for plaintext in (rng.randrange(1 << 16) for _ in range(number_of_pairs))
    ]


def encrypt_pairs(
    plaintext_pairs: Iterable[tuple[int, int]],
    subkeys: Sequence[int],
) -> list[KnownPair]:
    """Consulta clásicamente ``E_K`` para ambos textos de cada par."""
    pairs: list[KnownPair] = []
    for plaintext, plaintext_star in plaintext_pairs:
        validate_u16(plaintext, "plaintext")
        validate_u16(plaintext_star, "plaintext_star")
        pairs.append(
            KnownPair(
                plaintext=plaintext,
                plaintext_star=plaintext_star,
                ciphertext=encrypt_block(plaintext, subkeys),
                ciphertext_star=encrypt_block(plaintext_star, subkeys),
            )
        )
    return pairs


def _ciphertexts(pair: KnownPair | Sequence[int]) -> tuple[int, int]:
    if isinstance(pair, KnownPair):
        return pair.ciphertext, pair.ciphertext_star
    if len(pair) == 2:
        ciphertext, ciphertext_star = pair
    elif len(pair) == 4:
        ciphertext, ciphertext_star = pair[2], pair[3]
    else:
        raise ValueError("pair debe tener 2 cifrados o la forma (P, P*, C, C*).")
    return validate_u16(ciphertext, "ciphertext"), validate_u16(
        ciphertext_star, "ciphertext_star"
    )


def right_pair(
    candidate: int,
    pair: KnownPair | Sequence[int],
    alpha_expected: int,
) -> int:
    """Calcula ``RP(y_r, i)``.

    Se comparan los nibbles activos de ``alpha^(r-1)``. Esta es la convención
    del ataque SPN16 de referencia: con ``0606`` se recuperan los nibbles 1 y 3;
    los nibbles inactivos requieren otras características.
    """
    validate_u16(candidate, "candidate")
    mask = active_nibble_mask(alpha_expected)
    ciphertext, ciphertext_star = _ciphertexts(pair)
    state = decrypt_last_round_partial(ciphertext, candidate)
    state_star = decrypt_last_round_partial(ciphertext_star, candidate)
    observed = (state ^ state_star) & mask
    return int(observed == (alpha_expected & mask))


def count_right_pairs(
    candidate: int,
    pairs: Iterable[KnownPair | Sequence[int]],
    alpha_expected: int,
) -> int:
    """Calcula ``R(y_r) = sum_i RP(y_r, i)``."""
    return sum(right_pair(candidate, pair, alpha_expected) for pair in pairs)


def exhaustive_key_search(
    K_cand: Iterable[int],
    pairs: Sequence[KnownPair | Sequence[int]],
    alpha_expected: int,
) -> list[CandidateScore]:
    """Ordena ``K_cand`` por su conteo clásico ``R(y_r)``."""
    scores = [
        CandidateScore(
            candidate=validate_u16(candidate, "candidate"),
            R_y=count_right_pairs(candidate, pairs, alpha_expected),
        )
        for candidate in K_cand
    ]
    return sorted(scores, key=lambda item: (-item.R_y, item.candidate))

