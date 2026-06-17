from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Dict, List, Sequence, Tuple


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from cryptosystems import spn16 as spn16_cipher
from cryptosystems.reduced_aes import ReducedAES
from cryptosystems.reduced_klein import ReducedKLEIN
from differential_cryptoanalysis.aes_dc_key_recovery import (
    DEFAULT_BLOCK_BITS as AES_DEFAULT_BLOCK_BITS,
    DEFAULT_KEY_BITS as AES_DEFAULT_KEY_BITS,
    DEFAULT_MASTER_KEY_HEX as AES_DEFAULT_MASTER_KEY_HEX,
    DEFAULT_ROUNDS as AES_DEFAULT_ROUNDS,
    TRAIL_DELTA_IN as AES_TRAIL_DELTA_IN,
    TRAIL_DELTA_PENULTIMATE as AES_TRAIL_DELTA_PENULTIMATE,
    generate_right_pairs_from_penultimate_delta as generate_aes_right_pairs,
    recover_last_round_subkey_from_right_pairs as recover_aes_last_round_subkey,
)
from differential_cryptoanalysis.dc_key_recovery import (
    build_oracle,
    recover_last_whitening_subkey,
)
from differential_cryptoanalysis.klein_dc_key_recovery import (
    DEFAULT_BLOCK_BITS as KLEIN_DEFAULT_BLOCK_BITS,
    DEFAULT_KEY_BITS as KLEIN_DEFAULT_KEY_BITS,
    DEFAULT_MASTER_KEY_HEX as KLEIN_DEFAULT_MASTER_KEY_HEX,
    DEFAULT_ROUNDS as KLEIN_DEFAULT_ROUNDS,
    TRAIL_DELTA_IN as KLEIN_TRAIL_DELTA_IN,
    TRAIL_DELTA_PENULTIMATE as KLEIN_TRAIL_DELTA_PENULTIMATE,
    enumerate_final_whitening_candidates,
    generate_right_pairs_from_penultimate_delta as generate_klein_right_pairs,
    recover_transformed_final_whitening_from_right_pairs,
    transform_final_whitening_key,
)


SPN16_DEFAULT_MASTER_KEY_HEX = "00112233445566778899AABB"
SPN16_DEFAULT_ROUNDS = 5
SPN16_DEFAULT_DELTA_IN = 0x0B00
SPN16_DEFAULT_EXPECTED_DELTA_U = {2: 0x5}


def parse_hex_int(text: str) -> int:
    value = text.strip().replace("_", "")
    if value.lower().startswith("0x"):
        value = value[2:]
    if not value:
        raise argparse.ArgumentTypeError("empty hex value")
    try:
        return int(value, 16)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid hex value: {text!r}") from exc


def parse_expected_delta_u(text: str) -> Dict[int, int]:
    """
    Parses strings such as "2:5" or "1:6,3:6".

    Nibble positions use MSB order: 0, 1, 2, 3.
    """
    result: Dict[int, int] = {}
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        if ":" not in item:
            raise argparse.ArgumentTypeError(
                "expected format is pos:delta, for example 2:5 or 1:6,3:6"
            )
        pos_text, delta_text = item.split(":", 1)
        try:
            pos = int(pos_text.strip(), 0)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"invalid nibble position: {pos_text!r}") from exc
        delta = parse_hex_int(delta_text)
        result[pos] = delta

    if not result:
        raise argparse.ArgumentTypeError("at least one pos:delta entry is required")
    return result


def fmt_block(value: int, block_bits: int) -> str:
    width = (block_bits + 3) // 4
    return f"0x{value & ((1 << block_bits) - 1):0{width}X}"


def fmt_partial_nibbles(values: Sequence[int | None]) -> str:
    return "0x" + "".join("?" if value is None else f"{int(value) & 0xF:X}" for value in values)


def score_preview(scores: Sequence[Tuple[int, int]], *, digits: int, top: int) -> str:
    return ", ".join(f"{guess:0{digits}X}:{score}" for guess, score in scores[:top])


def recover_spn16_from_differential(
    *,
    master_key_hex: str = SPN16_DEFAULT_MASTER_KEY_HEX,
    rounds: int = SPN16_DEFAULT_ROUNDS,
    delta_in: int = SPN16_DEFAULT_DELTA_IN,
    expected_delta_u_by_nibble: Dict[int, int] | None = None,
    n_pairs: int = 4000,
    seed: int = 2026,
) -> Dict[str, Any]:
    """
    Recover targeted nibbles of SPN16 final whitening key K_(r+1).

    expected_delta_u_by_nibble is the already-known differential at the input of
    the last S-box layer, indexed by nibble position 0..3, MSB first.
    """
    expected = expected_delta_u_by_nibble or dict(SPN16_DEFAULT_EXPECTED_DELTA_U)
    oracle = build_oracle(master_key_hex=master_key_hex, rounds=rounds)
    partial_key, scores = recover_last_whitening_subkey(
        oracle_encrypt=oracle,
        delta_in=delta_in,
        expected_delta_u_by_nibble=expected,
        n_pairs=n_pairs,
        seed=seed,
        return_scores=True,
    )
    true_subkeys = spn16_cipher.expand_key_from_hex(master_key_hex, rounds)
    true_final_key = true_subkeys[-1]

    recovered_by_pos: Dict[int, Dict[str, int]] = {}
    for pos in sorted(expected):
        shift = 4 * (3 - pos)
        recovered_by_pos[pos] = {
            "expected_delta_u": expected[pos],
            "recovered": (partial_key >> shift) & 0xF,
            "true": (true_final_key >> shift) & 0xF,
        }

    return {
        "cipher": "SPN16",
        "rounds": rounds,
        "master_key_hex": master_key_hex,
        "delta_in": delta_in,
        "expected_delta_u_by_nibble": expected,
        "n_pairs": n_pairs,
        "seed": seed,
        "partial_key": partial_key,
        "true_final_key": true_final_key,
        "recovered_by_pos": recovered_by_pos,
        "scores": scores,
    }


def recover_reduced_aes_from_differential(
    *,
    master_key_hex: str = AES_DEFAULT_MASTER_KEY_HEX,
    rounds: int = AES_DEFAULT_ROUNDS,
    block_bits: int = AES_DEFAULT_BLOCK_BITS,
    key_bits: int = AES_DEFAULT_KEY_BITS,
    delta_in: int = AES_TRAIL_DELTA_IN,
    delta_penultimate: int = AES_TRAIL_DELTA_PENULTIMATE,
    n_pairs: int = 64,
    seed: int = 2026,
) -> Dict[str, Any]:
    """
    Recover the last round subkey of ReducedAES from known right pairs.

    This demo synthesizes right pairs at the input of the last round from the
    already-known penultimate-round differential.
    """
    cipher = ReducedAES(rounds=rounds, block_bits=block_bits, key_bits=key_bits)
    round_keys = cipher.expand_key_from_hex(master_key_hex)
    true_last_round_key = round_keys[-1]

    pairs = generate_aes_right_pairs(
        cipher=cipher,
        last_round_key=true_last_round_key,
        delta_penultimate=delta_penultimate,
        n_pairs=n_pairs,
        seed=seed,
    )
    recovered_key, scores = recover_aes_last_round_subkey(
        cipher=cipher,
        ciphertext_pairs=pairs,
        delta_penultimate=delta_penultimate,
        return_scores=True,
    )

    return {
        "cipher": "ReducedAES",
        "rounds": rounds,
        "block_bits": block_bits,
        "key_bits": key_bits,
        "master_key_hex": master_key_hex,
        "delta_in": delta_in,
        "delta_penultimate": delta_penultimate,
        "n_pairs": n_pairs,
        "seed": seed,
        "true_last_round_key": true_last_round_key,
        "recovered_key": recovered_key,
        "matches": recovered_key == true_last_round_key,
        "scores": scores,
    }


def recover_reduced_klein_from_differential(
    *,
    master_key_hex: str = KLEIN_DEFAULT_MASTER_KEY_HEX,
    rounds: int = KLEIN_DEFAULT_ROUNDS,
    block_bits: int = KLEIN_DEFAULT_BLOCK_BITS,
    key_bits: int = KLEIN_DEFAULT_KEY_BITS,
    delta_in: int = KLEIN_TRAIL_DELTA_IN,
    delta_penultimate: int = KLEIN_TRAIL_DELTA_PENULTIMATE,
    n_pairs: int = 128,
    seed: int = 2026,
    max_candidates_to_enumerate: int = 100_000,
) -> Dict[str, Any]:
    """
    Recover active nibbles of KLEIN final whitening key.

    The recovered object is T = InvRotate(InvMix(K_(r+1))). Unknown nibbles are
    left as None. If the unknown space is small enough, final whitening key
    candidates are enumerated.
    """
    cipher = ReducedKLEIN(rounds=rounds, block_bits=block_bits, key_bits=key_bits)
    round_keys = cipher.expand_round_keys_from_hex(master_key_hex)
    true_last_round_key = round_keys[cipher.rounds - 1]
    true_final_whitening_key = round_keys[cipher.rounds]
    true_transformed_key = transform_final_whitening_key(cipher, true_final_whitening_key)

    pairs = generate_klein_right_pairs(
        cipher=cipher,
        last_round_key=true_last_round_key,
        final_whitening_key=true_final_whitening_key,
        delta_penultimate=delta_penultimate,
        n_pairs=n_pairs,
        seed=seed,
    )
    partial_transformed_key, scores = recover_transformed_final_whitening_from_right_pairs(
        cipher=cipher,
        ciphertext_pairs=pairs,
        delta_penultimate=delta_penultimate,
        return_scores=True,
    )

    unknown_count = sum(value is None for value in partial_transformed_key)
    candidate_count_estimate = 16**unknown_count
    candidates: List[int] | None = None
    true_key_in_candidates: bool | None = None
    if candidate_count_estimate <= max_candidates_to_enumerate:
        candidates = enumerate_final_whitening_candidates(cipher, partial_transformed_key)
        true_key_in_candidates = true_final_whitening_key in candidates

    return {
        "cipher": "ReducedKLEIN",
        "rounds": rounds,
        "block_bits": block_bits,
        "key_bits": key_bits,
        "master_key_hex": master_key_hex,
        "delta_in": delta_in,
        "delta_penultimate": delta_penultimate,
        "n_pairs": n_pairs,
        "seed": seed,
        "true_last_round_key": true_last_round_key,
        "true_final_whitening_key": true_final_whitening_key,
        "true_transformed_key": true_transformed_key,
        "partial_transformed_key": partial_transformed_key,
        "candidate_count_estimate": candidate_count_estimate,
        "candidates": candidates,
        "true_key_in_candidates": true_key_in_candidates,
        "scores": scores,
    }


def print_spn16_result(result: Dict[str, Any], *, top: int = 5) -> None:
    print("=== SPN16 key recovery ===")
    print(f"Rondas:                  {result['rounds']}")
    print(f"Delta entrada:           {fmt_block(result['delta_in'], 16)}")
    print(f"Pares elegidos:          {result['n_pairs']} (seed={result['seed']})")
    print(f"K_(r+1) real:            {fmt_block(result['true_final_key'], 16)}")
    print(f"K_(r+1) parcial:         {fmt_block(result['partial_key'], 16)}")
    print("Nibbles atacados:        pos 0 = nibble mas significativo")
    for pos, info in result["recovered_by_pos"].items():
        ok = "OK" if info["recovered"] == info["true"] else "NO"
        print(
            f"  pos {pos}: DeltaU={info['expected_delta_u']:X}, "
            f"rec={info['recovered']:X}, real={info['true']:X} [{ok}]"
        )
    for pos in sorted(result["scores"]):
        print(f"  scores pos {pos}: {score_preview(result['scores'][pos], digits=1, top=top)}")


def print_aes_result(result: Dict[str, Any], *, top: int = 5) -> None:
    block_bits = result["block_bits"]
    print("=== ReducedAES key recovery ===")
    print(f"Rondas/bloque/clave:     {result['rounds']}/{block_bits}/{result['key_bits']}")
    print(f"Delta entrada trail:     {fmt_block(result['delta_in'], block_bits)}")
    print(f"Delta penultima ronda:   {fmt_block(result['delta_penultimate'], block_bits)}")
    print(f"Pares usados:            {result['n_pairs']} correctos sinteticos (seed={result['seed']})")
    print(f"K_r real:                {fmt_block(result['true_last_round_key'], block_bits)}")
    print(f"K_r recuperada:          {fmt_block(result['recovered_key'], block_bits)}")
    print(f"Coincide:                {result['matches']}")
    for pos in sorted(result["scores"]):
        print(f"  byte {pos}: {score_preview(result['scores'][pos], digits=2, top=top)}")


def print_klein_result(result: Dict[str, Any], *, top: int = 5) -> None:
    block_bits = result["block_bits"]
    print("=== ReducedKLEIN key recovery ===")
    print(f"Rondas/bloque/clave:     {result['rounds']}/{block_bits}/{result['key_bits']}")
    print(f"Delta entrada trail:     {fmt_block(result['delta_in'], block_bits)}")
    print(f"Delta penultima ronda:   {fmt_block(result['delta_penultimate'], block_bits)}")
    print(f"Pares usados:            {result['n_pairs']} correctos sinteticos (seed={result['seed']})")
    print(f"K_(r+1) real:            {fmt_block(result['true_final_whitening_key'], block_bits)}")
    print(f"T real:                  {fmt_block(result['true_transformed_key'], block_bits)}")
    print(f"T parcial recuperada:    {fmt_partial_nibbles(result['partial_transformed_key'])}")
    print(f"Candidatos estimados:    {result['candidate_count_estimate']}")
    if result["true_key_in_candidates"] is None:
        print("K real en candidatos:    no enumerado")
    else:
        print(f"K real en candidatos:    {result['true_key_in_candidates']}")
    for pos in sorted(result["scores"]):
        print(f"  nibble {pos}: {score_preview(result['scores'][pos], digits=1, top=top)}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Recuperacion de clave usando diferenciales ya calculados. "
            "SPN16 usa pares elegidos; AES/KLEIN reducido usan right pairs "
            "sinteticos en la ultima ronda."
        )
    )
    parser.add_argument("--top", type=int, default=5, help="Cantidad de candidatos por posicion a imprimir.")

    subparsers = parser.add_subparsers(dest="cipher", required=True)

    spn = subparsers.add_parser("spn16", help="Recuperar nibbles de K_(r+1) en SPN16.")
    spn.add_argument("--master-key-hex", default=SPN16_DEFAULT_MASTER_KEY_HEX)
    spn.add_argument("--rounds", type=int, default=SPN16_DEFAULT_ROUNDS)
    spn.add_argument("--delta-in", type=parse_hex_int, default=SPN16_DEFAULT_DELTA_IN)
    spn.add_argument(
        "--expected-delta-u",
        type=parse_expected_delta_u,
        default=SPN16_DEFAULT_EXPECTED_DELTA_U,
        help="Formato pos:delta, por ejemplo 2:5 o 1:6,3:6. Pos 0 es el nibble MSB.",
    )
    spn.add_argument("--n-pairs", type=int, default=4000)
    spn.add_argument("--seed", type=int, default=2026)
    spn.add_argument(
        "--top",
        type=int,
        default=argparse.SUPPRESS,
        help="Cantidad de candidatos por posicion a imprimir.",
    )

    aes = subparsers.add_parser("aes", help="Recuperar K_r en AES reducido desde right pairs.")
    aes.add_argument("--master-key-hex", default=AES_DEFAULT_MASTER_KEY_HEX)
    aes.add_argument("--rounds", type=int, default=AES_DEFAULT_ROUNDS)
    aes.add_argument("--block-bits", type=int, default=AES_DEFAULT_BLOCK_BITS)
    aes.add_argument("--key-bits", type=int, default=AES_DEFAULT_KEY_BITS)
    aes.add_argument("--delta-in", type=parse_hex_int, default=AES_TRAIL_DELTA_IN)
    aes.add_argument("--delta-penultimate", type=parse_hex_int, default=AES_TRAIL_DELTA_PENULTIMATE)
    aes.add_argument("--n-pairs", type=int, default=64)
    aes.add_argument("--seed", type=int, default=2026)
    aes.add_argument(
        "--top",
        type=int,
        default=argparse.SUPPRESS,
        help="Cantidad de candidatos por posicion a imprimir.",
    )

    klein = subparsers.add_parser("klein", help="Recuperar K_(r+1) en KLEIN reducido desde right pairs.")
    klein.add_argument("--master-key-hex", default=KLEIN_DEFAULT_MASTER_KEY_HEX)
    klein.add_argument("--rounds", type=int, default=KLEIN_DEFAULT_ROUNDS)
    klein.add_argument("--block-bits", type=int, default=KLEIN_DEFAULT_BLOCK_BITS)
    klein.add_argument("--key-bits", type=int, default=KLEIN_DEFAULT_KEY_BITS)
    klein.add_argument("--delta-in", type=parse_hex_int, default=KLEIN_TRAIL_DELTA_IN)
    klein.add_argument("--delta-penultimate", type=parse_hex_int, default=KLEIN_TRAIL_DELTA_PENULTIMATE)
    klein.add_argument("--n-pairs", type=int, default=128)
    klein.add_argument("--seed", type=int, default=2026)
    klein.add_argument("--max-candidates-to-enumerate", type=int, default=100_000)
    klein.add_argument(
        "--top",
        type=int,
        default=argparse.SUPPRESS,
        help="Cantidad de candidatos por posicion a imprimir.",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cipher == "spn16":
        result = recover_spn16_from_differential(
            master_key_hex=args.master_key_hex,
            rounds=args.rounds,
            delta_in=args.delta_in,
            expected_delta_u_by_nibble=args.expected_delta_u,
            n_pairs=args.n_pairs,
            seed=args.seed,
        )
        print_spn16_result(result, top=args.top)
    elif args.cipher == "aes":
        result = recover_reduced_aes_from_differential(
            master_key_hex=args.master_key_hex,
            rounds=args.rounds,
            block_bits=args.block_bits,
            key_bits=args.key_bits,
            delta_in=args.delta_in,
            delta_penultimate=args.delta_penultimate,
            n_pairs=args.n_pairs,
            seed=args.seed,
        )
        print_aes_result(result, top=args.top)
    elif args.cipher == "klein":
        result = recover_reduced_klein_from_differential(
            master_key_hex=args.master_key_hex,
            rounds=args.rounds,
            block_bits=args.block_bits,
            key_bits=args.key_bits,
            delta_in=args.delta_in,
            delta_penultimate=args.delta_penultimate,
            n_pairs=args.n_pairs,
            seed=args.seed,
            max_candidates_to_enumerate=args.max_candidates_to_enumerate,
        )
        print_klein_result(result, top=args.top)
    else:
        parser.error(f"unknown cipher: {args.cipher}")


if __name__ == "__main__":
    main()
