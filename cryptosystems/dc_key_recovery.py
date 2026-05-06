from __future__ import annotations

from collections import Counter
from typing import Callable, Dict, List, Tuple
import random
import os
import sys


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from cryptosystems.spn_modular import ModularSPN


def sbox_ddt(sbox: List[int]) -> List[List[int]]:
    """
    DDT[a][b] = |{x : S(x) ^ S(x^a) = b}|
    """
    size = len(sbox)
    ddt = [[0] * size for _ in range(size)]
    for a in range(size):
        for x in range(size):
            b = sbox[x] ^ sbox[x ^ a]
            ddt[a][b] += 1
    return ddt


def chosen_plaintext_pairs(
    n_pairs: int,
    delta_in: int,
    block_bits: int,
    seed: int = 12345,
) -> List[Tuple[int, int]]:
    """
    Genera pares (P, P ^ DeltaP) uniformes en el espacio de block_bits.
    """
    if n_pairs <= 0:
        raise ValueError("n_pairs must be > 0")
    if block_bits <= 0:
        raise ValueError("block_bits must be > 0")

    mask = (1 << block_bits) - 1
    delta = delta_in & mask
    rng = random.Random(seed)

    pairs: List[Tuple[int, int]] = []
    for _ in range(n_pairs):
        p = rng.randrange(0, 1 << block_bits)
        pairs.append((p, p ^ delta))
    return pairs


def _join_chunks_msb_first(chunks: List[int], chunk_bits: int) -> int:
    value = 0
    for c in chunks:
        value = (value << chunk_bits) | c
    return value


def fmt_block(x: int, block_bits: int) -> str:
    width = (block_bits + 3) // 4
    return f"{x & ((1 << block_bits) - 1):0{width}X}"


def recover_last_whitening_subkey(
    cipher: ModularSPN,
    oracle_encrypt: Callable[[int], int],
    delta_in: int,
    expected_delta_u_by_sbox: Dict[int, int],
    n_pairs: int = 5000,
    seed: int = 12345,
    return_scores: bool = False,
) -> Tuple[int, Dict[int, List[Tuple[int, int]]]]:
    """
    Recupera chunks de la subclave final K_{r+1} (whitening final).

    Parametros:
      - cipher: instancia de ModularSPN.
      - oracle_encrypt: funcion bloque -> bloque.
      - delta_in: DeltaP de entrada del ataque.
      - expected_delta_u_by_sbox:
          dict {pos -> DeltaU}, pos en [0..num_sboxes-1] (0 = chunk MSB).
          DeltaU es la diferencia esperada a la entrada de la ultima capa S.
      - n_pairs: numero de pares elegidos.
      - seed: semilla RNG.
      - return_scores: si True, retorna ranking de candidatos por posicion.

    Retorna:
      - partial_key: subclave final parcial (chunks atacados recuperados, resto 0).
      - scores_by_pos: ranking [(guess, score)] por posicion si return_scores=True.
    """
    if not isinstance(cipher, ModularSPN):
        raise TypeError("cipher must be an instance of ModularSPN")
    if not callable(oracle_encrypt):
        raise TypeError("oracle_encrypt must be callable")
    if not expected_delta_u_by_sbox:
        raise ValueError("expected_delta_u_by_sbox cannot be empty")

    num_sboxes = cipher.num_sboxes
    chunk_bits = cipher.sbox_bits
    chunk_mask = cipher.sbox_mask
    key_space = 1 << chunk_bits
    block_mask = (1 << cipher.block_bits) - 1

    for pos, delta_u in expected_delta_u_by_sbox.items():
        if not (0 <= pos < num_sboxes):
            raise ValueError(f"invalid sbox position: {pos}")
        if not (0 <= delta_u < key_space):
            raise ValueError(f"invalid DeltaU for position {pos}: {delta_u}")

    pairs = chosen_plaintext_pairs(
        n_pairs=n_pairs,
        delta_in=delta_in,
        block_bits=cipher.block_bits,
        seed=seed,
    )

    ciphertext_pairs: List[Tuple[int, int]] = []
    for p1, p2 in pairs:
        c1 = oracle_encrypt(p1) & block_mask
        c2 = oracle_encrypt(p2) & block_mask
        ciphertext_pairs.append((c1, c2))

    guessed_chunks = [0] * num_sboxes
    scores_by_pos: Dict[int, List[Tuple[int, int]]] = {}

    for pos, delta_u in sorted(expected_delta_u_by_sbox.items()):
        shift = chunk_bits * (num_sboxes - 1 - pos)
        hist: Counter[int] = Counter()

        for k_guess in range(key_space):
            score = 0
            for c1, c2 in ciphertext_pairs:
                y1 = ((c1 >> shift) & chunk_mask) ^ k_guess
                y2 = ((c2 >> shift) & chunk_mask) ^ k_guess
                u1 = cipher.sbox_inv[y1]
                u2 = cipher.sbox_inv[y2]
                if (u1 ^ u2) == delta_u:
                    score += 1
            hist[k_guess] = score

        best_guess, _ = max(hist.items(), key=lambda kv: kv[1])
        guessed_chunks[pos] = best_guess
        scores_by_pos[pos] = sorted(hist.items(), key=lambda kv: kv[1], reverse=True)

    partial_key = _join_chunks_msb_first(guessed_chunks, chunk_bits) & block_mask
    if return_scores:
        return partial_key, scores_by_pos
    return partial_key, {}


def _demo() -> None:
    # SPN solicitado:
    sbox = [
        0xE, 0x4, 0xD, 0x1,
        0x2, 0xF, 0xB, 0x8,
        0x3, 0xA, 0x6, 0xC,
        0x5, 0x9, 0x0, 0x7,
    ]
    permutation = [
        0, 4, 8, 12,
        1, 5, 9, 13,
        2, 6, 10, 14,
        3, 7, 11, 15,
    ]

    cipher = ModularSPN(
        sbox=sbox,
        permutation=permutation,
        rounds=4,
        block_bits=16,
    )

    master_key_hex = "00000000000000000000"
    subkeys = cipher.expand_key_from_hex(master_key_hex)
    oracle = lambda x: cipher.encrypt_block(x, subkeys)

    # Estos valores Delta son placeholders.
    delta_in = 0xB000
    expected_delta_u = {
        1: 0x1,
        2: 0x6,
        3: 0x6,
    }

    k_guess, scores = recover_last_whitening_subkey(
        cipher=cipher,
        oracle_encrypt=oracle,
        delta_in=delta_in,
        expected_delta_u_by_sbox=expected_delta_u,
        n_pairs=4000,
        seed=2026,
        return_scores=True,
    )

    print(f"K_(r+1) parcial recuperada: {fmt_block(k_guess, cipher.block_bits)}")
    for pos in sorted(scores):
        print(f"Pos {pos} top-5: {scores[pos][:5]}")


if __name__ == "__main__":
    _demo()
