from __future__ import annotations

import argparse
import heapq
import json
import math
import os
import sys
from dataclasses import dataclass
from itertools import combinations, product
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Sequence, Tuple


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from cryptosystems.aes import S_BOX as AES_SBOX
from cryptosystems.klein import S_BOX as KLEIN_SBOX
from cryptosystems.reduced_aes import ReducedAES
from cryptosystems.reduced_klein import ReducedKLEIN


@dataclass(frozen=True)
class Characteristic:
    deltas: Tuple[int, ...]
    probability: float

    @property
    def weight(self) -> float:
        if self.probability == 0.0:
            return float("inf")
        return -math.log2(self.probability)


def _fmt_block(x: int, block_bits: int) -> str:
    width = (block_bits + 3) // 4
    return f"0x{x & ((1 << block_bits) - 1):0{width}X}"


def _split_chunks(x: int, chunk_bits: int, num_chunks: int) -> List[int]:
    mask = (1 << chunk_bits) - 1
    out: List[int] = []
    for i in range(num_chunks):
        shift = chunk_bits * (num_chunks - 1 - i)
        out.append((x >> shift) & mask)
    return out


def _join_chunks(chunks: Sequence[int], chunk_bits: int) -> int:
    value = 0
    mask = (1 << chunk_bits) - 1
    for c in chunks:
        value = (value << chunk_bits) | (int(c) & mask)
    return value


def _build_ddt(sbox: Sequence[int]) -> List[List[int]]:
    size = len(sbox)
    ddt = [[0] * size for _ in range(size)]
    for dx in range(size):
        for x in range(size):
            dy = sbox[x] ^ sbox[x ^ dx]
            ddt[dx][dy] += 1
    return ddt


def _build_row_transitions(ddt: Sequence[Sequence[int]]) -> List[List[Tuple[int, float]]]:
    size = len(ddt)
    rows: List[List[Tuple[int, float]]] = []
    for dx in range(size):
        row: List[Tuple[int, float]] = []
        for dy, count in enumerate(ddt[dx]):
            if count > 0:
                row.append((dy, float(count) / float(size)))
        row.sort(key=lambda it: it[1], reverse=True)
        rows.append(row)
    return rows


def _rank_candidate_delta_ins(
    *,
    rows: Sequence[Sequence[Tuple[int, float]]],
    chunk_bits: int,
    num_chunks: int,
    max_active_chunks: int,
    max_initial_deltas: int | None,
) -> List[int]:
    if max_active_chunks <= 0:
        raise ValueError("max_active_chunks must be > 0")

    nonzero_values = list(range(1, 1 << chunk_bits))
    best_row_prob = [0.0] * (1 << chunk_bits)
    for dx in nonzero_values:
        best_row_prob[dx] = rows[dx][0][1]

    ranked: List[Tuple[float, int]] = []
    for active_count in range(1, max_active_chunks + 1):
        for positions in combinations(range(num_chunks), active_count):
            for values in product(nonzero_values, repeat=active_count):
                chunks = [0] * num_chunks
                score = 1.0
                for pos, value in zip(positions, values):
                    chunks[pos] = value
                    score *= best_row_prob[value]
                ranked.append((score, _join_chunks(chunks, chunk_bits)))

    ranked.sort(key=lambda item: item[0], reverse=True)
    if max_initial_deltas is not None:
        ranked = ranked[:max_initial_deltas]
    return [delta_in for _, delta_in in ranked]


def _build_aes_linear_map(cipher: ReducedAES) -> Callable[[List[int]], List[int]]:
    def linear_map(chunks: List[int]) -> List[int]:
        state = list(chunks)
        cipher._shift_rows(state)
        cipher._mix_columns(state)
        return state

    return linear_map


def _build_klein_linear_map(cipher: ReducedKLEIN) -> Callable[[List[int]], List[int]]:
    def linear_map(chunks: List[int]) -> List[int]:
        if len(chunks) != cipher.block_bytes * 2:
            raise ValueError("invalid nibble chunk length for KLEIN state")

        bytes_state: List[int] = []
        for i in range(cipher.block_bytes):
            hi = chunks[2 * i]
            lo = chunks[2 * i + 1]
            bytes_state.append(((hi & 0xF) << 4) | (lo & 0xF))

        bytes_state = cipher._rotate(bytes_state)
        bytes_state = cipher._mix(bytes_state)

        out_chunks: List[int] = []
        for b in bytes_state:
            out_chunks.append((b >> 4) & 0xF)
            out_chunks.append(b & 0xF)
        return out_chunks

    return linear_map


def one_round_candidates(
    delta_in: int,
    chunk_bits: int,
    num_chunks: int,
    rows: Sequence[Sequence[Tuple[int, float]]],
    linear_map: Callable[[List[int]], List[int]],
    max_outputs_per_active_chunk: int | None,
    min_step_prob: float,
    max_candidates_per_state: int,
) -> List[Tuple[int, float]]:
    if max_candidates_per_state <= 0:
        raise ValueError("max_candidates_per_state must be > 0")

    in_chunks = _split_chunks(delta_in, chunk_bits, num_chunks)
    options: List[List[Tuple[int, float]]] = []
    for dx in in_chunks:
        if dx == 0:
            options.append([(0, 1.0)])
            continue
        row = list(rows[dx])
        if max_outputs_per_active_chunk is not None:
            row = row[:max_outputs_per_active_chunk]
        options.append(row)

    max_by_chunk: List[float] = []
    for opts in options:
        if not opts:
            return []
        max_by_chunk.append(opts[0][1])

    suffix_upper = [1.0] * (num_chunks + 1)
    for i in range(num_chunks - 1, -1, -1):
        suffix_upper[i] = suffix_upper[i + 1] * max_by_chunk[i]

    partials: List[Tuple[float, List[int]]] = [(1.0, [])]
    for i, opts in enumerate(options):
        new_partials: List[Tuple[float, List[int]]] = []
        upper_rest = suffix_upper[i + 1]
        for p, current_chunks in partials:
            for out_diff, p_out in opts:
                p_new = p * p_out
                if p_new * upper_rest < min_step_prob:
                    continue
                new_partials.append((p_new, current_chunks + [out_diff]))

        if not new_partials:
            return []

        new_partials.sort(key=lambda it: it[0], reverse=True)
        partials = new_partials[:max_candidates_per_state]

    merged: Dict[int, float] = {}
    for p, out_chunks in partials:
        if p < min_step_prob:
            continue
        next_chunks = linear_map(out_chunks)
        delta_out = _join_chunks(next_chunks, chunk_bits)
        old = merged.get(delta_out, 0.0)
        if p > old:
            merged[delta_out] = p

    out = sorted(merged.items(), key=lambda it: it[1], reverse=True)
    return out[:max_candidates_per_state]


def search_high_probability_characteristics_to_penultimate(
    *,
    cipher_name: str,
    total_rounds: int,
    block_bits: int,
    key_bits: int,
    delta_in: int,
    top_k: int = 10,
    beam_width: int = 2000,
    max_outputs_per_active_chunk: int | None = None,
    min_step_prob: float = 0.0,
    max_candidates_per_state: int = 4096,
    target_out: int | None = None,
) -> List[Characteristic]:
    if total_rounds < 2:
        raise ValueError("total_rounds must be >= 2 to reach penultimate round")
    if top_k <= 0:
        raise ValueError("top_k must be > 0")
    if beam_width <= 0:
        raise ValueError("beam_width must be > 0")
    if max_candidates_per_state <= 0:
        raise ValueError("max_candidates_per_state must be > 0")

    if cipher_name == "aes":
        cipher = ReducedAES(rounds=total_rounds, block_bits=block_bits, key_bits=key_bits)
        sbox = AES_SBOX
        chunk_bits = 8
        num_chunks = cipher.block_bytes
        linear_map = _build_aes_linear_map(cipher)
        if max_outputs_per_active_chunk is None:
            max_outputs_per_active_chunk = 8
    elif cipher_name == "klein":
        cipher = ReducedKLEIN(rounds=total_rounds, block_bits=block_bits, key_bits=key_bits)
        sbox = KLEIN_SBOX
        chunk_bits = 4
        num_chunks = cipher.block_bits // 4
        linear_map = _build_klein_linear_map(cipher)
        if max_outputs_per_active_chunk is None:
            max_outputs_per_active_chunk = 16
    else:
        raise ValueError("cipher_name must be 'aes' or 'klein'")

    if not (0 <= delta_in < (1 << block_bits)):
        raise ValueError("delta_in out of range for selected block_bits")
    if target_out is not None and not (0 <= target_out < (1 << block_bits)):
        raise ValueError("target_out out of range for selected block_bits")

    ddt = _build_ddt(sbox)
    rows = _build_row_transitions(ddt)
    rounds_to_search = total_rounds - 1

    beam: List[Tuple[float, int, Tuple[int, ...]]] = [(0.0, 0, (delta_in,))]
    tie = 1

    for r in range(1, rounds_to_search + 1):
        next_heap: List[Tuple[float, int, Tuple[int, ...]]] = []
        for log2p, _, path in beam:
            current = path[-1]
            candidates = one_round_candidates(
                delta_in=current,
                chunk_bits=chunk_bits,
                num_chunks=num_chunks,
                rows=rows,
                linear_map=linear_map,
                max_outputs_per_active_chunk=max_outputs_per_active_chunk,
                min_step_prob=min_step_prob,
                max_candidates_per_state=max_candidates_per_state,
            )
            for nxt, step_p in candidates:
                if step_p <= 0.0:
                    continue
                if r == rounds_to_search and target_out is not None and nxt != target_out:
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
        beam = sorted(next_heap, key=lambda it: it[0], reverse=True)

    out: List[Characteristic] = []
    for log2p, _, path in beam[:top_k]:
        out.append(Characteristic(deltas=path, probability=2.0 ** log2p))
    return out


def search_best_characteristics_to_penultimate(
    *,
    cipher_name: str,
    total_rounds: int,
    block_bits: int,
    key_bits: int,
    top_k: int = 10,
    beam_width: int = 2000,
    max_outputs_per_active_chunk: int | None = None,
    min_step_prob: float = 0.0,
    max_candidates_per_state: int = 4096,
    target_out: int | None = None,
    max_initial_active_chunks: int | None = None,
    max_initial_deltas: int | None = 128,
) -> List[Characteristic]:
    if cipher_name == "aes":
        cipher = ReducedAES(rounds=total_rounds, block_bits=block_bits, key_bits=key_bits)
        rows = _build_row_transitions(_build_ddt(AES_SBOX))
        chunk_bits = 8
        num_chunks = cipher.block_bytes
        if max_initial_active_chunks is None:
            max_initial_active_chunks = 1
        if max_outputs_per_active_chunk is None:
            max_outputs_per_active_chunk = 8
    elif cipher_name == "klein":
        cipher = ReducedKLEIN(rounds=total_rounds, block_bits=block_bits, key_bits=key_bits)
        rows = _build_row_transitions(_build_ddt(KLEIN_SBOX))
        chunk_bits = 4
        num_chunks = cipher.block_bits // 4
        if max_initial_active_chunks is None:
            max_initial_active_chunks = 1
        if max_outputs_per_active_chunk is None:
            max_outputs_per_active_chunk = 16
    else:
        raise ValueError("cipher_name must be 'aes' or 'klein'")

    candidate_delta_ins = _rank_candidate_delta_ins(
        rows=rows,
        chunk_bits=chunk_bits,
        num_chunks=num_chunks,
        max_active_chunks=max_initial_active_chunks,
        max_initial_deltas=max_initial_deltas,
    )

    ranked: List[Characteristic] = []
    for delta_in in candidate_delta_ins:
        ranked.extend(
            search_high_probability_characteristics_to_penultimate(
                cipher_name=cipher_name,
                total_rounds=total_rounds,
                block_bits=block_bits,
                key_bits=key_bits,
                delta_in=delta_in,
                top_k=top_k,
                beam_width=beam_width,
                max_outputs_per_active_chunk=max_outputs_per_active_chunk,
                min_step_prob=min_step_prob,
                max_candidates_per_state=max_candidates_per_state,
                target_out=target_out,
            )
        )

    ranked.sort(key=lambda item: item.probability, reverse=True)
    return ranked[:top_k]


def _parse_hex_block(text: str, block_bits: int) -> int:
    raw = text.strip()
    if raw.startswith("0x") or raw.startswith("0X"):
        raw = raw[2:]
    try:
        value = int(raw, 16)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid hex value: {text}") from exc
    if not (0 <= value < (1 << block_bits)):
        raise argparse.ArgumentTypeError(f"value must fit in {block_bits} bits")
    return value


def print_characteristics(items: Iterable[Characteristic], block_bits: int) -> None:
    print("Top caracteristicas de alta probabilidad (hasta penultima ronda):")
    for i, c in enumerate(items, start=1):
        path = " -> ".join(_fmt_block(v, block_bits) for v in c.deltas)
        print(f"{i:2d}. {path}  P = {c.probability:.12e}  w = {c.weight:.4f}")


def save_characteristics_json(
    items: Sequence[Characteristic],
    *,
    output_path: str,
    block_bits: int,
    search_parameters: Dict[str, object],
) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "search_parameters": search_parameters,
        "characteristics": [
            {
                "rank": rank,
                "deltas": [_fmt_block(delta, block_bits) for delta in item.deltas],
                "probability": item.probability,
                "weight": item.weight,
            }
            for rank, item in enumerate(items, start=1)
        ],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Busqueda de caracteristicas diferenciales de alta probabilidad "
            "hasta la penultima ronda para AES/KLEIN reducidos."
        )
    )
    parser.add_argument("--cipher", choices=("aes", "klein"), required=True)
    parser.add_argument("--rounds", type=int, required=True, help="Rondas totales del cifrador reducido")
    parser.add_argument("--block-bits", type=int, required=True, help="Tamano de bloque en bits")
    parser.add_argument("--key-bits", type=int, required=True, help="Tamano de clave en bits")
    parser.add_argument("--delta-in", type=str, default=None, help="Diferencia de entrada en hex")
    parser.add_argument("--target-out", type=str, default=None, help="Diferencia objetivo en penultima ronda")
    parser.add_argument("--top-k", type=int, default=10, help="Cantidad de caracteristicas a mostrar")
    parser.add_argument("--beam-width", type=int, default=2000, help="Beam width")
    parser.add_argument(
        "--search-best",
        action="store_true",
        help="Busca automaticamente Delta_in y Delta_out con caracteristica de alta probabilidad",
    )
    parser.add_argument(
        "--max-outputs-per-active-chunk",
        type=int,
        default=None,
        help="Poda por S-box activa (salidas maximas por fila DDT)",
    )
    parser.add_argument(
        "--max-candidates-per-state",
        type=int,
        default=4096,
        help="Maximo de candidatos por estado y ronda",
    )
    parser.add_argument(
        "--min-step-prob",
        type=float,
        default=0.0,
        help="Probabilidad minima para una transicion de ronda",
    )
    parser.add_argument(
        "--max-initial-active-chunks",
        type=int,
        default=None,
        help="Cantidad maxima de chunks activos para proponer Delta_in automaticos",
    )
    parser.add_argument(
        "--max-initial-deltas",
        type=int,
        default=128,
        help="Cantidad maxima de Delta_in candidatos al usar --search-best",
    )
    parser.add_argument(
        "--output-json",
        type=str,
        default=None,
        help="Ruta opcional para guardar parametros y caracteristicas en JSON",
    )
    args = parser.parse_args()

    target_out = _parse_hex_block(args.target_out, args.block_bits) if args.target_out else None

    if args.search_best:
        chars = search_best_characteristics_to_penultimate(
            cipher_name=args.cipher,
            total_rounds=args.rounds,
            block_bits=args.block_bits,
            key_bits=args.key_bits,
            top_k=args.top_k,
            beam_width=args.beam_width,
            max_outputs_per_active_chunk=args.max_outputs_per_active_chunk,
            min_step_prob=args.min_step_prob,
            max_candidates_per_state=args.max_candidates_per_state,
            target_out=target_out,
            max_initial_active_chunks=args.max_initial_active_chunks,
            max_initial_deltas=args.max_initial_deltas,
        )
    else:
        if args.delta_in is None:
            parser.error("--delta-in es obligatorio si no usas --search-best")
        delta_in = _parse_hex_block(args.delta_in, args.block_bits)
        chars = search_high_probability_characteristics_to_penultimate(
            cipher_name=args.cipher,
            total_rounds=args.rounds,
            block_bits=args.block_bits,
            key_bits=args.key_bits,
            delta_in=delta_in,
            top_k=args.top_k,
            beam_width=args.beam_width,
            max_outputs_per_active_chunk=args.max_outputs_per_active_chunk,
            min_step_prob=args.min_step_prob,
            max_candidates_per_state=args.max_candidates_per_state,
            target_out=target_out,
        )

    print(
        f"Cipher={args.cipher}, rounds(total)={args.rounds}, "
        f"busqueda_hasta={args.rounds - 1} (penultima)"
    )
    print_characteristics(chars, args.block_bits)

    if args.output_json:
        output_path = save_characteristics_json(
            chars,
            output_path=args.output_json,
            block_bits=args.block_bits,
            search_parameters={
                "cipher": args.cipher,
                "total_rounds": args.rounds,
                "search_until_round": args.rounds - 1,
                "block_bits": args.block_bits,
                "key_bits": args.key_bits,
                "search_best": args.search_best,
                "delta_in": args.delta_in,
                "target_out": args.target_out,
                "top_k": args.top_k,
                "beam_width": args.beam_width,
                "max_outputs_per_active_chunk": args.max_outputs_per_active_chunk,
                "max_candidates_per_state": args.max_candidates_per_state,
                "min_step_prob": args.min_step_prob,
                "max_initial_active_chunks": args.max_initial_active_chunks,
                "max_initial_deltas": args.max_initial_deltas,
            },
        )
        print(f"Resultados guardados en: {output_path}")


if __name__ == "__main__":
    main()
