from __future__ import annotations

from collections import Counter
from itertools import product
import os
import random
import sys
from typing import Dict, List, Sequence, Tuple


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from cryptosystems.klein import S_BOX_INV
from cryptosystems.reduced_klein import ReducedKLEIN


DEFAULT_MASTER_KEY_HEX = "0011223344556677"
DEFAULT_ROUNDS = 6
DEFAULT_BLOCK_BITS = 32
DEFAULT_KEY_BITS = 64

TRAIL_DELTA_IN = 0x10000000
TRAIL_DELTA_PENULTIMATE = 0xF07BCBB0


def _fmt_block(x: int, block_bits: int) -> str:
    width = (block_bits + 3) // 4
    return f"{x & ((1 << block_bits) - 1):0{width}X}"


def _split_nibbles(x: int, block_bits: int) -> List[int]:
    width = block_bits // 4
    return [((x >> (4 * (width - 1 - i))) & 0xF) for i in range(width)]


def _join_nibbles(nibbles: Sequence[int]) -> int:
    value = 0
    for nibble in nibbles:
        value = (value << 4) | (int(nibble) & 0xF)
    return value


def _state_bytes_to_nibbles(state: Sequence[int]) -> List[int]:
    nibbles: List[int] = []
    for byte in state:
        nibbles.append((int(byte) >> 4) & 0xF)
        nibbles.append(int(byte) & 0xF)
    return nibbles


def _nibbles_to_state_bytes(nibbles: Sequence[int]) -> List[int]:
    if len(nibbles) % 2 != 0:
        raise ValueError("nibbles length must be even")
    out: List[int] = []
    for i in range(0, len(nibbles), 2):
        out.append(((int(nibbles[i]) & 0xF) << 4) | (int(nibbles[i + 1]) & 0xF))
    return out


def _encrypt_last_round_only(
    cipher: ReducedKLEIN,
    state_in: int,
    last_round_key: int,
    final_whitening_key: int,
) -> int:
    state = cipher._int_to_state(state_in)
    state = cipher._xor_state(state, cipher._int_to_state(last_round_key))
    cipher._sub_nibbles(state)
    state = cipher._rotate(state)
    state = cipher._mix(state)
    state = cipher._xor_state(state, cipher._int_to_state(final_whitening_key))
    return cipher._state_to_int(state)


def generate_right_pairs_from_penultimate_delta(
    *,
    cipher: ReducedKLEIN,
    last_round_key: int,
    final_whitening_key: int,
    delta_penultimate: int,
    n_pairs: int = 128,
    seed: int = 12345,
) -> List[Tuple[int, int]]:
    """
    Genera pares correctos sinteticos a la entrada de la ultima ronda.

    En este trail la recuperacion practica desde texto plano no es razonable
    por la probabilidad de la caracteristica. Esta funcion aísla la fase de
    key recovery sobre el ultimo paso.
    """
    if n_pairs <= 0:
        raise ValueError("n_pairs must be > 0")

    rng = random.Random(seed)
    pairs: List[Tuple[int, int]] = []
    for _ in range(n_pairs):
        a1 = rng.randrange(0, 1 << cipher.block_bits)
        a2 = a1 ^ (delta_penultimate & cipher.block_mask)
        c1 = _encrypt_last_round_only(cipher, a1, last_round_key, final_whitening_key)
        c2 = _encrypt_last_round_only(cipher, a2, last_round_key, final_whitening_key)
        pairs.append((c1, c2))
    return pairs


def transform_final_whitening_key(cipher: ReducedKLEIN, final_whitening_key: int) -> int:
    state = cipher._int_to_state(final_whitening_key)
    state = cipher._inv_mix(state)
    state = cipher._inv_rotate(state)
    return cipher._state_to_int(state)


def invert_transformed_whitening_key(cipher: ReducedKLEIN, transformed_key: int) -> int:
    state = cipher._int_to_state(transformed_key)
    state = cipher._rotate(state)
    state = cipher._mix(state)
    return cipher._state_to_int(state)


def _masked_post_sbox_state(cipher: ReducedKLEIN, ciphertext: int) -> List[int]:
    state = cipher._int_to_state(ciphertext)
    state = cipher._inv_mix(state)
    state = cipher._inv_rotate(state)
    return _state_bytes_to_nibbles(state)


def recover_transformed_final_whitening_from_right_pairs(
    *,
    cipher: ReducedKLEIN,
    ciphertext_pairs: Sequence[Tuple[int, int]],
    delta_penultimate: int,
    return_scores: bool = False,
) -> Tuple[List[int | None], Dict[int, List[Tuple[int, int]]]]:
    if not ciphertext_pairs:
        raise ValueError("ciphertext_pairs cannot be empty")

    expected = _split_nibbles(delta_penultimate, cipher.block_bits)
    masked_pairs = [
        (_masked_post_sbox_state(cipher, c1), _masked_post_sbox_state(cipher, c2))
        for c1, c2 in ciphertext_pairs
    ]

    recovered: List[int | None] = [None] * len(expected)
    scores_by_pos: Dict[int, List[Tuple[int, int]]] = {}

    for pos, target_delta in enumerate(expected):
        if target_delta == 0:
            continue

        hist: Counter[int] = Counter()
        for t_guess in range(16):
            score = 0
            for c1, c2 in masked_pairs:
                u1 = S_BOX_INV[c1[pos] ^ t_guess]
                u2 = S_BOX_INV[c2[pos] ^ t_guess]
                if (u1 ^ u2) == target_delta:
                    score += 1
            hist[t_guess] = score

        best_guess, _ = max(hist.items(), key=lambda item: item[1])
        recovered[pos] = best_guess
        scores_by_pos[pos] = sorted(hist.items(), key=lambda item: item[1], reverse=True)

    if return_scores:
        return recovered, scores_by_pos
    return recovered, {}


def enumerate_final_whitening_candidates(
    cipher: ReducedKLEIN,
    partial_transformed_key_nibbles: Sequence[int | None],
) -> List[int]:
    unknown_positions = [i for i, value in enumerate(partial_transformed_key_nibbles) if value is None]
    if len(partial_transformed_key_nibbles) != cipher.block_bits // 4:
        raise ValueError("invalid transformed key length")

    candidates: List[int] = []
    for values in product(range(16), repeat=len(unknown_positions)):
        filled = list(partial_transformed_key_nibbles)
        for pos, value in zip(unknown_positions, values):
            filled[pos] = value
        transformed_key = _join_nibbles(int(v) for v in filled)
        candidates.append(invert_transformed_whitening_key(cipher, transformed_key))
    return candidates


def demo() -> None:
    cipher = ReducedKLEIN(
        rounds=DEFAULT_ROUNDS,
        block_bits=DEFAULT_BLOCK_BITS,
        key_bits=DEFAULT_KEY_BITS,
    )
    round_keys = cipher.expand_round_keys_from_hex(DEFAULT_MASTER_KEY_HEX)
    true_last_round_key = round_keys[cipher.rounds - 1]
    true_final_whitening_key = round_keys[cipher.rounds]
    true_transformed_key = transform_final_whitening_key(cipher, true_final_whitening_key)

    pairs = generate_right_pairs_from_penultimate_delta(
        cipher=cipher,
        last_round_key=true_last_round_key,
        final_whitening_key=true_final_whitening_key,
        delta_penultimate=TRAIL_DELTA_PENULTIMATE,
        n_pairs=128,
        seed=2026,
    )
    partial_transformed_key, scores = recover_transformed_final_whitening_from_right_pairs(
        cipher=cipher,
        ciphertext_pairs=pairs,
        delta_penultimate=TRAIL_DELTA_PENULTIMATE,
        return_scores=True,
    )
    whitening_candidates = enumerate_final_whitening_candidates(cipher, partial_transformed_key)

    print("KLEIN reducido - key recovery de la subclave final")
    print(f"Delta_in del trail:          0x{_fmt_block(TRAIL_DELTA_IN, cipher.block_bits)}")
    print(f"Delta penultima ronda:       0x{_fmt_block(TRAIL_DELTA_PENULTIMATE, cipher.block_bits)}")
    print("Pares usados:                correctos sinteticos en la ultima ronda")
    print(f"K_(r+1) real:                0x{_fmt_block(true_final_whitening_key, cipher.block_bits)}")
    print(f"T real:                      0x{_fmt_block(true_transformed_key, cipher.block_bits)}")
    print(
        "T recuperada parcial:        "
        + "".join("?" if value is None else f"{value:X}" for value in partial_transformed_key)
    )
    print(f"Candidatos K_(r+1):          {len(whitening_candidates)}")
    print(f"K_(r+1) real en candidatos:  {true_final_whitening_key in whitening_candidates}")
    print(
        "Nota: este diferencial recupera T = InvRotate(InvMix(K_(r+1))). "
        "La subclave de ronda previa se cancela tras InvS-box."
    )
    for pos in sorted(scores):
        print(f"Nibble {pos} top-5: {scores[pos][:5]}")


def main() -> None:
    demo()


if __name__ == "__main__":
    main()
