from __future__ import annotations

from collections import Counter
import os
import random
import sys
from typing import Dict, List, Sequence, Tuple


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from cryptosystems.aes import INV_S_BOX
from cryptosystems.reduced_aes import ReducedAES


DEFAULT_MASTER_KEY_HEX = "0011223344556677"
DEFAULT_ROUNDS = 4
DEFAULT_BLOCK_BITS = 64
DEFAULT_KEY_BITS = 64

TRAIL_DELTA_IN = 0x1800000000000000
TRAIL_DELTA_PENULTIMATE = 0xB8D172C63DC37207


def _fmt_block(x: int, block_bits: int) -> str:
    width = (block_bits + 3) // 4
    return f"{x & ((1 << block_bits) - 1):0{width}X}"


def _encrypt_last_round_only(
    cipher: ReducedAES,
    state_in: int,
    last_round_key: int,
) -> int:
    state = cipher._int_to_state(state_in)
    cipher._sub_bytes(state)
    cipher._shift_rows(state)
    cipher._add_round_key(state, cipher._int_to_state(last_round_key))
    return cipher._state_to_int(state)


def generate_right_pairs_from_penultimate_delta(
    *,
    cipher: ReducedAES,
    last_round_key: int,
    delta_penultimate: int,
    n_pairs: int = 64,
    seed: int = 12345,
) -> List[Tuple[int, int]]:
    """
    Genera pares correctos sinteticos en la entrada de la ultima ronda.

    Esto prueba la fase de key recovery del ultimo paso sin depender de
    encontrar pares correctos desde texto plano, lo cual seria impractico
    con la probabilidad del trail usado para AES reducido.
    """
    if n_pairs <= 0:
        raise ValueError("n_pairs must be > 0")

    rng = random.Random(seed)
    pairs: List[Tuple[int, int]] = []
    for _ in range(n_pairs):
        u1 = rng.randrange(0, 1 << cipher.block_bits)
        u2 = u1 ^ (delta_penultimate & cipher.block_mask)
        c1 = _encrypt_last_round_only(cipher, u1, last_round_key)
        c2 = _encrypt_last_round_only(cipher, u2, last_round_key)
        pairs.append((c1, c2))
    return pairs


def _shift_rows_origin_by_output_position(cipher: ReducedAES) -> List[int]:
    labels = list(range(cipher.block_bytes))
    cipher._shift_rows(labels)
    return labels


def recover_last_round_subkey_from_right_pairs(
    *,
    cipher: ReducedAES,
    ciphertext_pairs: Sequence[Tuple[int, int]],
    delta_penultimate: int,
    return_scores: bool = False,
) -> Tuple[int, Dict[int, List[Tuple[int, int]]]]:
    if not ciphertext_pairs:
        raise ValueError("ciphertext_pairs cannot be empty")

    expected = cipher._int_to_state(delta_penultimate)
    mapped_positions = _shift_rows_origin_by_output_position(cipher)
    byte_pairs = [
        (cipher._int_to_state(c1), cipher._int_to_state(c2))
        for c1, c2 in ciphertext_pairs
    ]

    recovered = [0] * cipher.block_bytes
    scores_by_pos: Dict[int, List[Tuple[int, int]]] = {}

    for out_pos in range(cipher.block_bytes):
        pre_sbox_pos = mapped_positions[out_pos]
        target_delta = expected[pre_sbox_pos]
        hist: Counter[int] = Counter()

        for k_guess in range(256):
            score = 0
            for c1, c2 in byte_pairs:
                u1 = INV_S_BOX[c1[out_pos] ^ k_guess]
                u2 = INV_S_BOX[c2[out_pos] ^ k_guess]
                if (u1 ^ u2) == target_delta:
                    score += 1
            hist[k_guess] = score

        best_guess, _ = max(hist.items(), key=lambda item: item[1])
        recovered[out_pos] = best_guess
        scores_by_pos[out_pos] = sorted(hist.items(), key=lambda item: item[1], reverse=True)

    recovered_key = cipher._state_to_int(recovered)
    if return_scores:
        return recovered_key, scores_by_pos
    return recovered_key, {}


def demo() -> None:
    cipher = ReducedAES(
        rounds=DEFAULT_ROUNDS,
        block_bits=DEFAULT_BLOCK_BITS,
        key_bits=DEFAULT_KEY_BITS,
    )
    round_keys = cipher.expand_key_from_hex(DEFAULT_MASTER_KEY_HEX)
    true_last_round_key = round_keys[-1]

    pairs = generate_right_pairs_from_penultimate_delta(
        cipher=cipher,
        last_round_key=true_last_round_key,
        delta_penultimate=TRAIL_DELTA_PENULTIMATE,
        n_pairs=64,
        seed=2026,
    )
    recovered_key, scores = recover_last_round_subkey_from_right_pairs(
        cipher=cipher,
        ciphertext_pairs=pairs,
        delta_penultimate=TRAIL_DELTA_PENULTIMATE,
        return_scores=True,
    )

    print("AES reducido - key recovery de la ultima ronda")
    print(f"Delta_in del trail:          0x{_fmt_block(TRAIL_DELTA_IN, cipher.block_bits)}")
    print(f"Delta penultima ronda:       0x{_fmt_block(TRAIL_DELTA_PENULTIMATE, cipher.block_bits)}")
    print("Pares usados:                correctos sinteticos en la ultima ronda")
    print(f"K_r real:                    0x{_fmt_block(true_last_round_key, cipher.block_bits)}")
    print(f"K_r recuperada:              0x{_fmt_block(recovered_key, cipher.block_bits)}")
    for pos in range(cipher.block_bytes):
        print(f"Byte {pos} top-5: {scores[pos][:5]}")


def main() -> None:
    demo()


if __name__ == "__main__":
    main()
