from __future__ import annotations

import argparse
import json
import math
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from cryptosystems import aes
from cryptosystems.klein import S_BOX as KLEIN_SBOX
from cryptosystems.reduced_klein import ReducedKLEIN


THRESHOLD_WEIGHT = 64.0
THRESHOLD_PROBABILITY = 2.0 ** -64

# Candidate found with beam search. It can be regenerated with
# --refresh-klein-search and is always verified exactly before being saved.
KLEIN_6_ROUND_PATH = (
    0x1000000000000000,
    0x0000000030506030,
    0x60E0E00010300020,
    0x60500000E07000D0,
    0x00E0709020C08000,
    0x000070509000E070,
    0xFB60405BDBAB9070,
)


@dataclass(frozen=True)
class RoundRecord:
    round_number: int
    input_difference: int
    sbox_output_difference: int
    output_difference: int
    active_sboxes: int
    probability: float
    weight: float
    active_transitions: Tuple[Dict[str, object], ...]
    linear_layer: str


@dataclass(frozen=True)
class Characteristic:
    cipher: str
    block_bits: int
    key_bits: int
    full_cipher_rounds: int
    rounds: Tuple[RoundRecord, ...]
    search_method: str
    optimality_note: str

    @property
    def probability(self) -> float:
        result = 1.0
        for round_record in self.rounds:
            result *= round_record.probability
        return result

    @property
    def weight(self) -> float:
        return sum(round_record.weight for round_record in self.rounds)

    @property
    def initial_difference(self) -> int:
        return self.rounds[0].input_difference

    @property
    def final_difference(self) -> int:
        return self.rounds[-1].output_difference

    @property
    def passes_threshold(self) -> bool:
        return self.weight < THRESHOLD_WEIGHT


def build_ddt(sbox: Sequence[int]) -> List[List[int]]:
    size = len(sbox)
    ddt = [[0] * size for _ in range(size)]
    for delta_in in range(size):
        for x in range(size):
            delta_out = sbox[x] ^ sbox[x ^ delta_in]
            ddt[delta_in][delta_out] += 1
    return ddt


def _fmt(value: int, bits: int) -> str:
    return f"0x{value:0{(bits + 3) // 4}X}"


def _split_chunks(value: int, chunk_bits: int, chunk_count: int) -> List[int]:
    mask = (1 << chunk_bits) - 1
    return [
        (value >> (chunk_bits * (chunk_count - 1 - i))) & mask
        for i in range(chunk_count)
    ]


def _join_chunks(chunks: Sequence[int], chunk_bits: int) -> int:
    value = 0
    mask = (1 << chunk_bits) - 1
    for chunk in chunks:
        value = (value << chunk_bits) | (int(chunk) & mask)
    return value


def _round_record(
    *,
    round_number: int,
    input_chunks: Sequence[int],
    sbox_output_chunks: Sequence[int],
    output_chunks: Sequence[int],
    chunk_bits: int,
    ddt: Sequence[Sequence[int]],
    linear_layer: str,
) -> RoundRecord:
    if len(input_chunks) != len(sbox_output_chunks):
        raise ValueError("input and S-box output must have the same number of chunks")

    sbox_size = 1 << chunk_bits
    probability = 1.0
    transitions: List[Dict[str, object]] = []

    for position, (delta_in, delta_out) in enumerate(
        zip(input_chunks, sbox_output_chunks)
    ):
        if delta_in == 0:
            if delta_out != 0:
                raise ValueError("zero input difference cannot produce a nonzero difference")
            continue

        count = int(ddt[delta_in][delta_out])
        if count == 0:
            raise ValueError(
                f"impossible S-box transition at position {position}: "
                f"{delta_in:#x} -> {delta_out:#x}"
            )

        transition_probability = count / float(sbox_size)
        probability *= transition_probability
        transitions.append(
            {
                "position": position,
                "delta_in": _fmt(delta_in, chunk_bits),
                "delta_out": _fmt(delta_out, chunk_bits),
                "ddt_count": count,
                "probability": transition_probability,
                "weight": -math.log2(transition_probability),
            }
        )

    block_bits = len(input_chunks) * chunk_bits
    return RoundRecord(
        round_number=round_number,
        input_difference=_join_chunks(input_chunks, chunk_bits),
        sbox_output_difference=_join_chunks(sbox_output_chunks, chunk_bits),
        output_difference=_join_chunks(output_chunks, chunk_bits),
        active_sboxes=len(transitions),
        probability=probability,
        weight=-math.log2(probability),
        active_transitions=tuple(transitions),
        linear_layer=linear_layer,
    )


def _aes_full_linear(state: Sequence[int]) -> List[int]:
    output = list(state)
    aes._shift_rows(output)
    aes._mix_columns(output)
    return output


def _aes_inverse_full_linear(state: Sequence[int]) -> List[int]:
    output = list(state)
    aes._inv_mix_columns(output)
    aes._inv_shift_rows(output)
    return output


def _aes_final_linear(state: Sequence[int]) -> List[int]:
    output = list(state)
    aes._shift_rows(output)
    return output


def search_aes_3_round_characteristic() -> Characteristic:
    """
    Search an AES-128 3-round characteristic with active pattern 4 -> 1 -> 4.

    Byte position 0 is representative because AES ShiftRows/MixColumns is
    symmetric with respect to the selected column/row for this construction.
    The search enumerates all 255 middle input differences and all possible
    nonzero outputs of its S-box.
    """
    ddt = build_ddt(aes.S_BOX)

    # Best input difference for every fixed S-box output difference.
    best_input_for_output: List[Tuple[int, int]] = []
    for delta_out in range(256):
        count, delta_in = max(
            (ddt[delta_in][delta_out], delta_in)
            for delta_in in range(256)
        )
        best_input_for_output.append((count, delta_in))

    # Best output difference for every fixed S-box input difference.
    best_output_for_input: List[Tuple[int, int]] = []
    for delta_in in range(256):
        count, delta_out = max(
            (ddt[delta_in][delta_out], delta_out)
            for delta_out in range(256)
        )
        best_output_for_input.append((count, delta_out))

    best: Tuple[
        float,
        List[int],
        List[int],
        List[int],
        List[int],
        List[int],
        List[int],
        List[int],
    ] | None = None

    active_position = 0
    for middle_input_value in range(1, 256):
        round_1_output = [0] * aes.BLOCK_BYTES
        round_1_output[active_position] = middle_input_value
        round_1_sbox_output = _aes_inverse_full_linear(round_1_output)

        round_1_input = [0] * aes.BLOCK_BYTES
        round_1_probability = 1.0
        for i, delta_out in enumerate(round_1_sbox_output):
            if delta_out == 0:
                continue
            count, delta_in = best_input_for_output[delta_out]
            round_1_input[i] = delta_in
            round_1_probability *= count / 256.0

        for middle_sbox_output_value in range(1, 256):
            count_2 = ddt[middle_input_value][middle_sbox_output_value]
            if count_2 == 0:
                continue

            round_2_sbox_output = [0] * aes.BLOCK_BYTES
            round_2_sbox_output[active_position] = middle_sbox_output_value
            round_2_output = _aes_full_linear(round_2_sbox_output)

            round_3_sbox_output = [0] * aes.BLOCK_BYTES
            round_3_probability = 1.0
            for i, delta_in in enumerate(round_2_output):
                if delta_in == 0:
                    continue
                count_3, delta_out_3 = best_output_for_input[delta_in]
                round_3_sbox_output[i] = delta_out_3
                round_3_probability *= count_3 / 256.0

            probability = (
                round_1_probability
                * (count_2 / 256.0)
                * round_3_probability
            )
            weight = -math.log2(probability)
            if best is None or weight < best[0]:
                best = (
                    weight,
                    round_1_input,
                    round_1_sbox_output,
                    round_1_output,
                    round_2_sbox_output,
                    round_2_output,
                    round_3_sbox_output,
                    _aes_final_linear(round_3_sbox_output),
                )

    if best is None:
        raise RuntimeError("AES search did not find a characteristic")

    (
        _,
        round_1_input,
        round_1_sbox_output,
        round_1_output,
        round_2_sbox_output,
        round_2_output,
        round_3_sbox_output,
        round_3_output,
    ) = best

    records = (
        _round_record(
            round_number=1,
            input_chunks=round_1_input,
            sbox_output_chunks=round_1_sbox_output,
            output_chunks=round_1_output,
            chunk_bits=8,
            ddt=ddt,
            linear_layer="ShiftRows + MixColumns",
        ),
        _round_record(
            round_number=2,
            input_chunks=round_1_output,
            sbox_output_chunks=round_2_sbox_output,
            output_chunks=round_2_output,
            chunk_bits=8,
            ddt=ddt,
            linear_layer="ShiftRows + MixColumns",
        ),
        _round_record(
            round_number=3,
            input_chunks=round_2_output,
            sbox_output_chunks=round_3_sbox_output,
            output_chunks=round_3_output,
            chunk_bits=8,
            ddt=ddt,
            linear_layer="ShiftRows (final AES round, no MixColumns)",
        ),
    )

    result = Characteristic(
        cipher="AES-128",
        block_bits=aes.BLOCK_BITS,
        key_bits=aes.KEY_BITS,
        full_cipher_rounds=aes.NR,
        rounds=records,
        search_method=(
            "Exhaustive search inside the 3-round 4->1->4 active-S-box "
            "construction, using exact AES S-box DDT probabilities."
        ),
        optimality_note=(
            "Best characteristic found in this structured family; this is not "
            "a proof of global optimality over every possible AES trail."
        ),
    )
    validate_aes_characteristic(result)
    return result


def validate_aes_characteristic(characteristic: Characteristic) -> None:
    if characteristic.block_bits != 128 or len(characteristic.rounds) != 3:
        raise ValueError("expected an AES-128 3-round characteristic")

    for index, record in enumerate(characteristic.rounds):
        sbox_output = list(
            record.sbox_output_difference.to_bytes(aes.BLOCK_BYTES, "big")
        )
        expected = (
            _aes_final_linear(sbox_output)
            if index == len(characteristic.rounds) - 1
            else _aes_full_linear(sbox_output)
        )
        actual = list(record.output_difference.to_bytes(aes.BLOCK_BYTES, "big"))
        if expected != actual:
            raise ValueError(f"invalid AES linear propagation in round {index + 1}")

        if index + 1 < len(characteristic.rounds):
            next_input = characteristic.rounds[index + 1].input_difference
            if record.output_difference != next_input:
                raise ValueError("AES characteristic states are not connected")

    if not characteristic.passes_threshold:
        raise ValueError("AES characteristic does not pass the 2^-64 threshold")


def _klein_inverse_linear(
    cipher: ReducedKLEIN,
    output_difference: int,
) -> List[int]:
    state = list(output_difference.to_bytes(cipher.block_bytes, "big"))
    state = cipher._inv_mix(state)
    state = cipher._inv_rotate(state)

    chunks: List[int] = []
    for byte in state:
        chunks.extend(((byte >> 4) & 0xF, byte & 0xF))
    return chunks


def _klein_forward_linear(
    cipher: ReducedKLEIN,
    sbox_output_chunks: Sequence[int],
) -> List[int]:
    state: List[int] = []
    for i in range(cipher.block_bytes):
        state.append(
            ((sbox_output_chunks[2 * i] & 0xF) << 4)
            | (sbox_output_chunks[2 * i + 1] & 0xF)
        )
    state = cipher._rotate(state)
    state = cipher._mix(state)

    chunks: List[int] = []
    for byte in state:
        chunks.extend(((byte >> 4) & 0xF, byte & 0xF))
    return chunks


def search_klein_6_round_path() -> Tuple[int, ...]:
    """
    Refresh the KLEIN candidate with beam search.

    The returned trail is verified exactly by build_klein_6_round_characteristic.
    """
    from find_characteristics.reduced_characteristic_search import (
        search_high_probability_characteristics_to_penultimate,
    )

    items = search_high_probability_characteristics_to_penultimate(
        cipher_name="klein",
        total_rounds=7,
        block_bits=64,
        key_bits=64,
        delta_in=0x1000000000000000,
        top_k=1,
        beam_width=500,
        max_outputs_per_active_chunk=4,
        max_candidates_per_state=512,
    )
    if not items:
        raise RuntimeError("KLEIN beam search did not find a characteristic")
    return tuple(items[0].deltas)


def build_klein_6_round_characteristic(
    path: Sequence[int] = KLEIN_6_ROUND_PATH,
) -> Characteristic:
    if len(path) != 7:
        raise ValueError("a 6-round characteristic must contain 7 state differences")

    cipher = ReducedKLEIN(rounds=6, block_bits=64, key_bits=64)
    ddt = build_ddt(KLEIN_SBOX)
    records: List[RoundRecord] = []

    for round_number, (delta_in, delta_out) in enumerate(
        zip(path, path[1:]),
        start=1,
    ):
        input_chunks = _split_chunks(delta_in, 4, 16)
        sbox_output_chunks = _klein_inverse_linear(cipher, delta_out)
        expected_output_chunks = _klein_forward_linear(cipher, sbox_output_chunks)
        if _join_chunks(expected_output_chunks, 4) != delta_out:
            raise ValueError(f"invalid KLEIN linear propagation in round {round_number}")

        records.append(
            _round_record(
                round_number=round_number,
                input_chunks=input_chunks,
                sbox_output_chunks=sbox_output_chunks,
                output_chunks=expected_output_chunks,
                chunk_bits=4,
                ddt=ddt,
                linear_layer="RotateNibbles + MixNibbles",
            )
        )

    result = Characteristic(
        cipher="KLEIN-64",
        block_bits=64,
        key_bits=64,
        full_cipher_rounds=12,
        rounds=tuple(records),
        search_method=(
            "Beam search over exact KLEIN S-box DDT transitions, followed by "
            "exact round-by-round verification."
        ),
        optimality_note=(
            "High-probability candidate found by beam search; this is not a "
            "proof of global optimality over every possible KLEIN trail."
        ),
    )
    validate_klein_characteristic(result)
    return result


def validate_klein_characteristic(characteristic: Characteristic) -> None:
    if characteristic.block_bits != 64 or len(characteristic.rounds) != 6:
        raise ValueError("expected a KLEIN-64 6-round characteristic")

    for index, record in enumerate(characteristic.rounds):
        if index + 1 < len(characteristic.rounds):
            next_input = characteristic.rounds[index + 1].input_difference
            if record.output_difference != next_input:
                raise ValueError("KLEIN characteristic states are not connected")

    if not characteristic.passes_threshold:
        raise ValueError("KLEIN characteristic does not pass the 2^-64 threshold")


def characteristic_to_dict(characteristic: Characteristic) -> Dict[str, object]:
    block_bits = characteristic.block_bits
    return {
        "cipher": characteristic.cipher,
        "block_bits": block_bits,
        "key_bits": characteristic.key_bits,
        "full_cipher_rounds": characteristic.full_cipher_rounds,
        "characteristic_rounds": len(characteristic.rounds),
        "threshold": {
            "condition": "probability > 2^-64",
            "probability": THRESHOLD_PROBABILITY,
            "maximum_weight_exclusive": THRESHOLD_WEIGHT,
        },
        "passes_threshold": characteristic.passes_threshold,
        "initial_difference": _fmt(characteristic.initial_difference, block_bits),
        "final_difference": _fmt(characteristic.final_difference, block_bits),
        "probability": characteristic.probability,
        "probability_power_of_two": f"2^-{characteristic.weight:g}",
        "weight": characteristic.weight,
        "active_sboxes_total": sum(r.active_sboxes for r in characteristic.rounds),
        "search_method": characteristic.search_method,
        "optimality_note": characteristic.optimality_note,
        "rounds": [
            {
                "round": record.round_number,
                "input_difference": _fmt(record.input_difference, block_bits),
                "sbox_output_difference": _fmt(
                    record.sbox_output_difference,
                    block_bits,
                ),
                "output_difference": _fmt(record.output_difference, block_bits),
                "linear_layer": record.linear_layer,
                "active_sboxes": record.active_sboxes,
                "probability": record.probability,
                "weight": record.weight,
                "active_transitions": list(record.active_transitions),
            }
            for record in characteristic.rounds
        ],
    }


def save_characteristic(
    characteristic: Characteristic,
    output_path: Path,
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(characteristic_to_dict(characteristic), indent=2),
        encoding="utf-8",
    )
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Calculate and save high-probability differential characteristics "
            "for standard AES-128 and KLEIN-64."
        )
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Directory where JSON result files are saved",
    )
    parser.add_argument(
        "--refresh-klein-search",
        action="store_true",
        help="Run the slower KLEIN beam search instead of using the verified candidate",
    )
    args = parser.parse_args()

    aes_characteristic = search_aes_3_round_characteristic()
    klein_path = (
        search_klein_6_round_path()
        if args.refresh_klein_search
        else KLEIN_6_ROUND_PATH
    )
    klein_characteristic = build_klein_6_round_characteristic(klein_path)

    aes_path = save_characteristic(
        aes_characteristic,
        args.output_dir / "aes_128_3round_characteristic.json",
    )
    klein_path_output = save_characteristic(
        klein_characteristic,
        args.output_dir / "klein_64_6round_characteristic.json",
    )

    print(
        f"AES-128: 3 rounds, P=2^-{aes_characteristic.weight:g}, "
        f"saved to {aes_path}"
    )
    print(
        f"KLEIN-64: 6 rounds, P=2^-{klein_characteristic.weight:g}, "
        f"saved to {klein_path_output}"
    )


if __name__ == "__main__":
    main()
