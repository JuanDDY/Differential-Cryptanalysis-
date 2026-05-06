from __future__ import annotations

import argparse
import heapq
import math
import os
import sys
from dataclasses import dataclass
from itertools import combinations, product
from typing import Iterable, List, Sequence, Tuple

import numpy as np


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from cryptosystems import spn16


NIBBLE_VALUES = 16
STATE_BITS = 16
STATE_SPACE = 1 << STATE_BITS


@dataclass(frozen=True)
class Differential:
    delta_in: int
    delta_out: int
    probability: float

    @property
    def weight(self) -> float:
        if self.probability == 0.0:
            return float("inf")
        return -math.log2(self.probability)


@dataclass(frozen=True)
class Characteristic:
    # Delta_0, Delta_1, ..., Delta_r
    deltas: Tuple[int, ...]
    probability: float

    @property
    def weight(self) -> float:
        if self.probability == 0.0:
            return float("inf")
        return -math.log2(self.probability)


def fmt16(x: int) -> str:
    return f"0x{x & 0xFFFF:04X}"


def split_nibbles16(x: int) -> Tuple[int, int, int, int]:
    return ((x >> 12) & 0xF, (x >> 8) & 0xF, (x >> 4) & 0xF, x & 0xF)


def join_nibbles16(n3: int, n2: int, n1: int, n0: int) -> int:
    return ((n3 & 0xF) << 12) | ((n2 & 0xF) << 8) | ((n1 & 0xF) << 4) | (n0 & 0xF)


def build_ddt(sbox: Sequence[int]) -> np.ndarray:
    ddt = np.zeros((NIBBLE_VALUES, NIBBLE_VALUES), dtype=np.uint16)
    for dx in range(NIBBLE_VALUES):
        for x in range(NIBBLE_VALUES):
            dy = sbox[x] ^ sbox[x ^ dx]
            ddt[dx, dy] += 1
    return ddt


def ddt_probabilities(ddt: np.ndarray) -> np.ndarray:
    return ddt.astype(np.float64) / float(NIBBLE_VALUES)


def build_perm_lut() -> np.ndarray:
    lut = np.empty(STATE_SPACE, dtype=np.uint32)
    for x in range(STATE_SPACE):
        lut[x] = spn16._permute16(x)
    return lut


def _apply_transition_axis(dist: np.ndarray, trans: np.ndarray, axis: int) -> np.ndarray:
    moved = np.moveaxis(dist, axis, 0)
    flat = moved.reshape(NIBBLE_VALUES, -1)
    transformed = trans.T @ flat
    out = transformed.reshape(moved.shape)
    return np.moveaxis(out, 0, axis)


def differential_distribution_exact(
    delta_in: int,
    rounds: int,
    trans: np.ndarray,
    perm_lut: np.ndarray,
    use_short_last_round: bool = True,
) -> np.ndarray:
    if rounds <= 0:
        raise ValueError("rounds must be >= 1")
    if not (0 <= delta_in < STATE_SPACE):
        raise ValueError("delta_in must be 16-bit")

    dist = np.zeros((NIBBLE_VALUES, NIBBLE_VALUES, NIBBLE_VALUES, NIBBLE_VALUES), dtype=np.float64)
    n3, n2, n1, n0 = split_nibbles16(delta_in)
    dist[n3, n2, n1, n0] = 1.0

    for r in range(1, rounds + 1):
        for axis in range(4):
            dist = _apply_transition_axis(dist, trans, axis)

        apply_permutation = not (use_short_last_round and r == rounds)
        if apply_permutation:
            flat = dist.reshape(STATE_SPACE)
            permuted = np.empty_like(flat)
            permuted[perm_lut] = flat
            dist = permuted.reshape((NIBBLE_VALUES, NIBBLE_VALUES, NIBBLE_VALUES, NIBBLE_VALUES))

    return dist.reshape(STATE_SPACE)


def top_differentials(
    delta_in: int,
    rounds: int,
    top_k: int,
    trans: np.ndarray,
    perm_lut: np.ndarray,
    use_short_last_round: bool = True,
) -> List[Differential]:
    if top_k <= 0:
        raise ValueError("top_k must be > 0")

    distribution = differential_distribution_exact(
        delta_in,
        rounds,
        trans,
        perm_lut,
        use_short_last_round=use_short_last_round,
    )
    nz = np.flatnonzero(distribution)
    if nz.size == 0:
        return []

    k = min(top_k, int(nz.size))
    probs = distribution[nz]
    if k == int(nz.size):
        top_idx = nz
    else:
        sel = np.argpartition(probs, -k)[-k:]
        top_idx = nz[sel]

    order = np.argsort(distribution[top_idx])[::-1]
    out: List[Differential] = []
    for idx in top_idx[order]:
        out.append(
            Differential(
                delta_in=delta_in,
                delta_out=int(idx),
                probability=float(distribution[idx]),
            )
        )
    return out


def build_nibble_transitions(trans: np.ndarray) -> List[List[Tuple[int, float]]]:
    all_rows: List[List[Tuple[int, float]]] = []
    for dx in range(NIBBLE_VALUES):
        row: List[Tuple[int, float]] = []
        for dy in range(NIBBLE_VALUES):
            p = float(trans[dx, dy])
            if p > 0.0:
                row.append((dy, p))
        row.sort(key=lambda item: item[1], reverse=True)
        all_rows.append(row)
    return all_rows


def rank_candidate_delta_ins(
    nibble_rows: Sequence[Sequence[Tuple[int, float]]],
    *,
    num_nibbles: int,
    max_active_nibbles: int,
    max_initial_deltas: int | None,
) -> List[int]:
    if max_active_nibbles <= 0:
        raise ValueError("max_active_nibbles must be > 0")

    best_row_prob = [0.0] * NIBBLE_VALUES
    for dx in range(1, NIBBLE_VALUES):
        best_row_prob[dx] = nibble_rows[dx][0][1]

    ranked: List[Tuple[float, int]] = []
    nonzero_values = list(range(1, NIBBLE_VALUES))
    for active_count in range(1, max_active_nibbles + 1):
        for positions in combinations(range(num_nibbles), active_count):
            for values in product(nonzero_values, repeat=active_count):
                nibbles = [0] * num_nibbles
                score = 1.0
                for pos, value in zip(positions, values):
                    nibbles[pos] = value
                    score *= best_row_prob[value]
                delta_in = join_nibbles16(*nibbles)
                ranked.append((score, delta_in))

    ranked.sort(key=lambda item: item[0], reverse=True)
    if max_initial_deltas is not None:
        ranked = ranked[:max_initial_deltas]
    return [delta_in for _, delta_in in ranked]


def one_round_candidates(
    delta_in: int,
    nibble_rows: Sequence[Sequence[Tuple[int, float]]],
    apply_permutation: bool,
    perm_lut: np.ndarray,
    max_outputs_per_active_nibble: int | None,
    min_step_prob: float,
) -> List[Tuple[int, float]]:
    n3, n2, n1, n0 = split_nibbles16(delta_in)
    nibs = [n3, n2, n1, n0]

    options: List[List[Tuple[int, float]]] = []
    for nib in nibs:
        row = list(nibble_rows[nib])
        if max_outputs_per_active_nibble is not None and nib != 0:
            row = row[:max_outputs_per_active_nibble]
        options.append(row)

    out: List[Tuple[int, float]] = []
    for b3, p3 in options[0]:
        for b2, p2 in options[1]:
            p32 = p3 * p2
            for b1, p1 in options[2]:
                p321 = p32 * p1
                for b0, p0 in options[3]:
                    p = p321 * p0
                    if p < min_step_prob:
                        continue
                    delta_s = join_nibbles16(b3, b2, b1, b0)
                    delta_out = int(perm_lut[delta_s]) if apply_permutation else delta_s
                    out.append((delta_out, p))
    return out


def search_high_probability_characteristics(
    delta_in: int,
    rounds: int,
    top_k: int,
    trans: np.ndarray,
    perm_lut: np.ndarray,
    beam_width: int = 4000,
    max_outputs_per_active_nibble: int | None = None,
    min_step_prob: float = 0.0,
    target_out: int | None = None,
    use_short_last_round: bool = True,
) -> List[Characteristic]:
    if rounds <= 0:
        raise ValueError("rounds must be >= 1")
    if top_k <= 0:
        raise ValueError("top_k must be > 0")
    if beam_width <= 0:
        raise ValueError("beam_width must be > 0")

    nibble_rows = build_nibble_transitions(trans)

    # Heap: (log2_prob, tie, path)
    beam: List[Tuple[float, int, Tuple[int, ...]]] = [(0.0, 0, (delta_in,))]
    tie = 1

    for r in range(1, rounds + 1):
        is_last_searched_round = r == rounds
        apply_permutation = not (use_short_last_round and is_last_searched_round)
        next_heap: List[Tuple[float, int, Tuple[int, ...]]] = []

        for log2p, _, path in beam:
            current = path[-1]
            candidates = one_round_candidates(
                delta_in=current,
                nibble_rows=nibble_rows,
                apply_permutation=apply_permutation,
                perm_lut=perm_lut,
                max_outputs_per_active_nibble=max_outputs_per_active_nibble,
                min_step_prob=min_step_prob,
            )
            for nxt, step_p in candidates:
                if step_p <= 0.0:
                    continue
                if is_last_searched_round and target_out is not None and nxt != target_out:
                    continue
                new_log2 = log2p + math.log2(step_p)
                item = (new_log2, tie, path + (nxt,))
                tie += 1

                if len(next_heap) < beam_width:
                    heapq.heappush(next_heap, item)
                elif new_log2 > next_heap[0][0]:
                    heapq.heapreplace(next_heap, item)

        if not next_heap:
            return []
        beam = sorted(next_heap, key=lambda x: x[0], reverse=True)

    ranked = sorted(beam, key=lambda x: x[0], reverse=True)
    out: List[Characteristic] = []
    for log2p, _, path in ranked[:top_k]:
        out.append(Characteristic(deltas=path, probability=2.0 ** log2p))
    return out


def search_high_probability_characteristics_to_penultimate(
    delta_in: int,
    total_rounds: int,
    top_k: int,
    trans: np.ndarray,
    perm_lut: np.ndarray,
    beam_width: int = 4000,
    max_outputs_per_active_nibble: int | None = None,
    min_step_prob: float = 0.0,
    target_out: int | None = None,
) -> List[Characteristic]:
    if total_rounds < 2:
        raise ValueError("total_rounds must be >= 2")

    return search_high_probability_characteristics(
        delta_in=delta_in,
        rounds=total_rounds - 1,
        top_k=top_k,
        trans=trans,
        perm_lut=perm_lut,
        beam_width=beam_width,
        max_outputs_per_active_nibble=max_outputs_per_active_nibble,
        min_step_prob=min_step_prob,
        target_out=target_out,
        use_short_last_round=False,
    )


def search_best_characteristics_to_penultimate(
    total_rounds: int,
    top_k: int,
    trans: np.ndarray,
    perm_lut: np.ndarray,
    beam_width: int = 4000,
    max_outputs_per_active_nibble: int | None = None,
    min_step_prob: float = 0.0,
    target_out: int | None = None,
    max_initial_active_nibbles: int = 2,
    max_initial_deltas: int | None = 256,
) -> List[Characteristic]:
    nibble_rows = build_nibble_transitions(trans)
    candidate_delta_ins = rank_candidate_delta_ins(
        nibble_rows,
        num_nibbles=4,
        max_active_nibbles=max_initial_active_nibbles,
        max_initial_deltas=max_initial_deltas,
    )

    ranked: List[Characteristic] = []
    for delta_in in candidate_delta_ins:
        ranked.extend(
            search_high_probability_characteristics_to_penultimate(
                delta_in=delta_in,
                total_rounds=total_rounds,
                top_k=top_k,
                trans=trans,
                perm_lut=perm_lut,
                beam_width=beam_width,
                max_outputs_per_active_nibble=max_outputs_per_active_nibble,
                min_step_prob=min_step_prob,
                target_out=target_out,
            )
        )

    ranked.sort(key=lambda item: item.probability, reverse=True)
    return ranked[:top_k]


def parse_hex16(text: str) -> int:
    value = text.strip().lower()
    if value.startswith("0x"):
        value = value[2:]
    if len(value) > 4:
        raise argparse.ArgumentTypeError("expected max 4 hex chars")
    try:
        num = int(value, 16)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid hex value: {text}") from exc
    if not (0 <= num < STATE_SPACE):
        raise argparse.ArgumentTypeError("value must fit in 16 bits")
    return num


def print_differentials(items: Iterable[Differential]) -> None:
    print("Top diferenciales (DeltaX -> DeltaY):")
    for i, d in enumerate(items, start=1):
        print(
            f"{i:2d}. {fmt16(d.delta_in)} -> {fmt16(d.delta_out)}  "
            f"P = {d.probability:.12f}  w = {d.weight:.4f}"
        )


def print_characteristics(items: Iterable[Characteristic]) -> None:
    print("Top caracteristicas diferenciales de alta probabilidad:")
    for i, c in enumerate(items, start=1):
        path = " -> ".join(fmt16(x) for x in c.deltas)
        print(f"{i:2d}. {path}  P = {c.probability:.12f}  w = {c.weight:.4f}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Busqueda de diferenciales y caracteristicas de alta probabilidad "
            "para el SPN16 de cryptosystems/spn16.py"
        )
    )
    parser.add_argument("--delta-in", type=parse_hex16, default=0x0B00, help="DeltaX de entrada (hex, default: 0x0B00)")
    parser.add_argument("--rounds", type=int, default=5, help="Numero de rondas (default: 5)")
    parser.add_argument("--top-k", type=int, default=10, help="Cantidad de resultados a mostrar")
    parser.add_argument("--beam-width", type=int, default=4000, help="Beam width para trails")
    parser.add_argument("--target-out", type=parse_hex16, default=None, help="Si se define, fuerza DeltaY final")
    parser.add_argument(
        "--to-penultimate",
        action="store_true",
        help="Busca hasta r-1 rondas, sin aplicar la ultima ronda corta",
    )
    parser.add_argument(
        "--search-best",
        action="store_true",
        help="Busca automaticamente un Delta_in y Delta_out con caracteristica de alta probabilidad",
    )
    parser.add_argument(
        "--max-outputs-per-active-nibble",
        type=int,
        default=None,
        help="Poda por nibble activo (cantidad maxima de salidas por fila DDT)",
    )
    parser.add_argument(
        "--min-step-prob",
        type=float,
        default=0.0,
        help="Poda por probabilidad minima de transicion en cada ronda",
    )
    parser.add_argument(
        "--max-initial-active-nibbles",
        type=int,
        default=2,
        help="Cantidad maxima de nibbles activos para proponer Delta_in automaticos",
    )
    parser.add_argument(
        "--max-initial-deltas",
        type=int,
        default=256,
        help="Cantidad maxima de Delta_in candidatos al usar --search-best",
    )
    args = parser.parse_args()

    ddt = build_ddt(spn16.S_BOX)
    trans = ddt_probabilities(ddt)
    perm_lut = build_perm_lut()

    if args.search_best:
        chars = search_best_characteristics_to_penultimate(
            total_rounds=args.rounds,
            top_k=args.top_k,
            trans=trans,
            perm_lut=perm_lut,
            beam_width=args.beam_width,
            max_outputs_per_active_nibble=args.max_outputs_per_active_nibble,
            min_step_prob=args.min_step_prob,
            target_out=args.target_out,
            max_initial_active_nibbles=args.max_initial_active_nibbles,
            max_initial_deltas=args.max_initial_deltas,
        )
        print("Busqueda automatica de caracteristicas en r-1 rondas:")
    elif args.to_penultimate:
        diffs = top_differentials(
            delta_in=args.delta_in,
            rounds=args.rounds - 1,
            top_k=args.top_k,
            trans=trans,
            perm_lut=perm_lut,
            use_short_last_round=False,
        )
        print_differentials(diffs)
        print()
        chars = search_high_probability_characteristics_to_penultimate(
            delta_in=args.delta_in,
            total_rounds=args.rounds,
            top_k=args.top_k,
            trans=trans,
            perm_lut=perm_lut,
            beam_width=args.beam_width,
            max_outputs_per_active_nibble=args.max_outputs_per_active_nibble,
            min_step_prob=args.min_step_prob,
            target_out=args.target_out,
        )
    else:
        diffs = top_differentials(
            delta_in=args.delta_in,
            rounds=args.rounds,
            top_k=args.top_k,
            trans=trans,
            perm_lut=perm_lut,
        )
        print_differentials(diffs)
        print()
        chars = search_high_probability_characteristics(
            delta_in=args.delta_in,
            rounds=args.rounds,
            top_k=args.top_k,
            trans=trans,
            perm_lut=perm_lut,
            beam_width=args.beam_width,
            max_outputs_per_active_nibble=args.max_outputs_per_active_nibble,
            min_step_prob=args.min_step_prob,
            target_out=args.target_out,
        )
    print_characteristics(chars)


if __name__ == "__main__":
    main()
