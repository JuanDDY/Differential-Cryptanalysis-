from __future__ import annotations

import os
import sys


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from find_characteristics.reduced_characteristic_search import (
    print_characteristics as print_reduced_characteristics,
    search_best_characteristics_to_penultimate as search_best_reduced_characteristics_to_penultimate,
    search_high_probability_characteristics_to_penultimate as search_reduced_characteristics_to_penultimate,
)
from find_characteristics.spn16_characteristic_search import (
    build_ddt,
    build_perm_lut,
    ddt_probabilities,
    print_characteristics as print_spn16_characteristics,
    search_best_characteristics_to_penultimate as search_best_spn16_characteristics_to_penultimate,
    search_high_probability_characteristics_to_penultimate as search_spn16_characteristics_to_penultimate,
)
from cryptosystems import spn16


def _read_int(prompt: str, *, default: int | None = None) -> int:
    while True:
        raw = input(prompt).strip()
        if raw == "" and default is not None:
            return default
        try:
            return int(raw)
        except ValueError:
            print("Valor invalido. Ingresa un entero.")


def _read_hex(prompt: str, *, bits: int, default: int | None = None) -> int:
    while True:
        raw = input(prompt).strip()
        if raw == "" and default is not None:
            return default
        if raw.startswith("0x") or raw.startswith("0X"):
            raw = raw[2:]
        try:
            value = int(raw, 16)
        except ValueError:
            print("Valor invalido. Ingresa un hexadecimal.")
            continue
        if not (0 <= value < (1 << bits)):
            print(f"El valor debe caber en {bits} bits.")
            continue
        return value


def _read_yes_no(prompt: str, *, default: bool) -> bool:
    suffix = "[S/n]" if default else "[s/N]"
    while True:
        raw = input(f"{prompt} {suffix}: ").strip().lower()
        if raw == "":
            return default
        if raw in ("s", "si", "y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("Responde s o n.")


def _run_spn16_menu() -> None:
    rounds = _read_int("Rondas totales SPN16 [4]: ", default=4)
    top_k = _read_int("Cantidad de resultados [10]: ", default=10)
    beam_width = _read_int("Beam width [200]: ", default=200)
    max_outputs = _read_int("Max salidas por nibble activo [4]: ", default=4)
    search_best = _read_yes_no("Buscar Delta_in automaticamente?", default=True)

    ddt = build_ddt(spn16.S_BOX)
    trans = ddt_probabilities(ddt)
    perm_lut = build_perm_lut()

    if search_best:
        max_initial_deltas = _read_int("Max Delta_in candidatos [32]: ", default=32)
        items = search_best_spn16_characteristics_to_penultimate(
            total_rounds=rounds,
            top_k=top_k,
            trans=trans,
            perm_lut=perm_lut,
            beam_width=beam_width,
            max_outputs_per_active_nibble=max_outputs,
            max_initial_deltas=max_initial_deltas,
        )
    else:
        delta_in = _read_hex("Delta_in (hex, 16 bits) [0x0B00]: ", bits=16, default=0x0B00)
        items = search_spn16_characteristics_to_penultimate(
            delta_in=delta_in,
            total_rounds=rounds,
            top_k=top_k,
            trans=trans,
            perm_lut=perm_lut,
            beam_width=beam_width,
            max_outputs_per_active_nibble=max_outputs,
        )

    print()
    print("SPN16 - caracteristicas hasta la penultima ronda")
    print_spn16_characteristics(items)


def _run_reduced_menu(*, cipher_name: str) -> None:
    block_default = 32 if cipher_name == "klein" else 64
    key_default = 64
    rounds_default = 6 if cipher_name == "klein" else 4
    delta_default = 0x0000000F if cipher_name == "klein" else 0x0100000000000000

    rounds = _read_int(f"Rondas totales {cipher_name.upper()} [{rounds_default}]: ", default=rounds_default)
    block_bits = _read_int(f"Tamano de bloque [{block_default}]: ", default=block_default)
    key_bits = _read_int(f"Tamano de clave [{key_default}]: ", default=key_default)
    top_k = _read_int("Cantidad de resultados [10]: ", default=10)
    beam_width = _read_int("Beam width [120]: ", default=120)
    max_outputs = _read_int("Max salidas por chunk activo [4]: ", default=4)
    max_candidates = _read_int("Max candidatos por estado [128]: ", default=128)
    search_best = _read_yes_no("Buscar Delta_in automaticamente?", default=True)

    if search_best:
        max_initial_deltas = _read_int("Max Delta_in candidatos [24]: ", default=24)
        items = search_best_reduced_characteristics_to_penultimate(
            cipher_name=cipher_name,
            total_rounds=rounds,
            block_bits=block_bits,
            key_bits=key_bits,
            top_k=top_k,
            beam_width=beam_width,
            max_outputs_per_active_chunk=max_outputs,
            max_candidates_per_state=max_candidates,
            max_initial_deltas=max_initial_deltas,
        )
    else:
        delta_in = _read_hex(
            f"Delta_in (hex, {block_bits} bits) [{hex(delta_default)}]: ",
            bits=block_bits,
            default=delta_default,
        )
        items = search_reduced_characteristics_to_penultimate(
            cipher_name=cipher_name,
            total_rounds=rounds,
            block_bits=block_bits,
            key_bits=key_bits,
            delta_in=delta_in,
            top_k=top_k,
            beam_width=beam_width,
            max_outputs_per_active_chunk=max_outputs,
            max_candidates_per_state=max_candidates,
        )

    print()
    print(f"{cipher_name.upper()} reducido - caracteristicas hasta la penultima ronda")
    print_reduced_characteristics(items, block_bits)


def main() -> None:
    while True:
        print()
        print("Menu de busqueda de caracteristicas hasta la penultima ronda")
        print("1. SPN16")
        print("2. KLEIN reducido")
        print("3. AES reducido")
        print("4. Salir")
        choice = input("Selecciona una opcion: ").strip()

        if choice == "1":
            _run_spn16_menu()
        elif choice == "2":
            _run_reduced_menu(cipher_name="klein")
        elif choice == "3":
            _run_reduced_menu(cipher_name="aes")
        elif choice == "4":
            print("Saliendo.")
            return
        else:
            print("Opcion invalida.")


if __name__ == "__main__":
    main()
