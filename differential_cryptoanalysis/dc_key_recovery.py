from __future__ import annotations

from collections import Counter
import os
import random
import sys
from typing import Callable, Dict, List, Tuple


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from cryptosystems import spn16 as spn16_cipher


def fmt16(x: int) -> str:
    return f"{x & 0xFFFF:04X}"


def split_nibbles16(x: int) -> List[int]:
    return [(x >> 12) & 0xF, (x >> 8) & 0xF, (x >> 4) & 0xF, x & 0xF]


def join_nibbles16(nibbles: List[int]) -> int:
    return (
        ((nibbles[0] & 0xF) << 12)
        | ((nibbles[1] & 0xF) << 8)
        | ((nibbles[2] & 0xF) << 4)
        | (nibbles[3] & 0xF)
    )


def sbox_ddt(sbox: List[int]) -> List[List[int]]:
    ddt = [[0] * 16 for _ in range(16)]
    for dx in range(16):
        for x in range(16):
            dy = sbox[x] ^ sbox[x ^ dx]
            ddt[dx][dy] += 1
    return ddt


def chosen_plaintext_pairs(
    n_pairs: int,
    delta_in: int,
    seed: int = 12345,
) -> List[Tuple[int, int]]:
    if n_pairs <= 0:
        raise ValueError("n_pairs must be > 0")

    rng = random.Random(seed)
    delta = delta_in & 0xFFFF
    pairs: List[Tuple[int, int]] = []
    for _ in range(n_pairs):
        p = rng.randrange(0, 1 << 16)
        pairs.append((p, p ^ delta))
    return pairs


def build_oracle(master_key_hex: str, rounds: int) -> Callable[[int], int]:
    subkeys = spn16_cipher.expand_key_from_hex(master_key_hex, rounds)

    def oracle_encrypt(block: int) -> int:
        return spn16_cipher.spn_encrypt_block(block, subkeys, rounds)

    return oracle_encrypt


def recover_last_whitening_subkey(
    oracle_encrypt: Callable[[int], int],
    delta_in: int,
    expected_delta_u_by_nibble: Dict[int, int],
    n_pairs: int = 5000,
    seed: int = 12345,
    return_scores: bool = False,
) -> Tuple[int, Dict[int, List[Tuple[int, int]]]]:
    """
    Recupera nibbles de la subclave final K_{r+1} del SPN16.

    - oracle_encrypt: bloque de 16 bits -> ciphertext de 16 bits
    - delta_in: diferencia elegida de entrada
    - expected_delta_u_by_nibble:
        dict {pos -> delta_u}, con pos en 0..3 (0 = nibble MSB)
        y delta_u como diferencia esperada a la entrada de la ultima S-box
    """
    if not callable(oracle_encrypt):
        raise TypeError("oracle_encrypt must be callable")
    if not expected_delta_u_by_nibble:
        raise ValueError("expected_delta_u_by_nibble cannot be empty")

    for pos, delta_u in expected_delta_u_by_nibble.items():
        if not (0 <= pos <= 3):
            raise ValueError("nibble positions must be in range 0..3")
        if not (0 <= delta_u <= 0xF):
            raise ValueError(f"invalid delta_u for nibble {pos}: {delta_u}")

    pairs = chosen_plaintext_pairs(n_pairs=n_pairs, delta_in=delta_in, seed=seed)
    ciphertext_pairs = [(oracle_encrypt(p1) & 0xFFFF, oracle_encrypt(p2) & 0xFFFF) for p1, p2 in pairs]

    recovered_nibbles = [0, 0, 0, 0]
    scores_by_pos: Dict[int, List[Tuple[int, int]]] = {}

    for pos, delta_u in sorted(expected_delta_u_by_nibble.items()):
        shift = 4 * (3 - pos)
        hist: Counter[int] = Counter()

        for k_guess in range(16):
            score = 0
            for c1, c2 in ciphertext_pairs:
                y1 = ((c1 >> shift) & 0xF) ^ k_guess
                y2 = ((c2 >> shift) & 0xF) ^ k_guess
                u1 = spn16_cipher.S_BOX_INV[y1]
                u2 = spn16_cipher.S_BOX_INV[y2]
                if (u1 ^ u2) == delta_u:
                    score += 1
            hist[k_guess] = score

        best_guess, _ = max(hist.items(), key=lambda item: item[1])
        recovered_nibbles[pos] = best_guess
        scores_by_pos[pos] = sorted(hist.items(), key=lambda item: item[1], reverse=True)

    partial_subkey = join_nibbles16(recovered_nibbles)
    if return_scores:
        return partial_subkey, scores_by_pos
    return partial_subkey, {}


def demo() -> None:
    rounds = 5
    master_key_hex = "123412341234123412341234"
    oracle = build_oracle(master_key_hex=master_key_hex, rounds=rounds)

    # Trail de ejemplo para SPN16 de 5 rondas:
    # Delta_0 = 0x0B00
    # Delta_4 = 0x0606 en la entrada de la ultima S-box
    delta_in = 0x0B00
    expected_delta_u_by_nibble = {
        1: 0x6,
        3: 0x6
    }

    partial_key, scores = recover_last_whitening_subkey(
        oracle_encrypt=oracle,
        delta_in=delta_in,
        expected_delta_u_by_nibble=expected_delta_u_by_nibble,
        n_pairs=5000,
        seed=4,
        return_scores=True,
    )

    true_subkeys = spn16_cipher.expand_key_from_hex(master_key_hex, rounds)
    true_final_subkey = true_subkeys[-1]

    print(f"K_(r+1) real:    {fmt16(true_final_subkey)}")
    print(f"K_(r+1) parcial: {fmt16(partial_key)}")
    for pos in sorted(scores):
        print(f"Pos {pos} top-5: {scores[pos][:5]}")


if __name__ == "__main__":
    demo()
