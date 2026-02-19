#!/usr/bin/env python3
"""
Herramienta ligera para calcular y mostrar la DDT (Differential Distribution Table)
de una S-box.

Soporta dos formas de entrada:
1) Archivo JSON:
   - Formato objeto: {"name": "...", "input_size": n, "output_size": m, "table": [...]}
   - Formato lista:  [ ... valores de la S-box ... ]
2) Lista directa por CLI con --sbox.

Ejemplos:
  python ddt_ligero.py --file sboxes/data/ascon.json
  python ddt_ligero.py --sbox "[0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]"
  python ddt_ligero.py --sbox "12,5,6,11,9,0,10,13,3,14,15,8,4,7,1,2" --format csv --out ddt.csv
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]  # sube de DDTs/ a repo root
sys.path.insert(0, str(ROOT))

DDTS_DIR = Path(__file__).resolve().parent      # .../Differential-Cryptanalysis-/DDTs
ROOT_DIR = DDTS_DIR.parent


import argparse
import ast
import csv
import json
import math
from pathlib import Path
from typing import Iterable, Sequence


def _parse_int(value: object) -> int:
    if isinstance(value, bool):
        raise ValueError("Los valores booleanos no son validos en la S-box")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("Valor vacio en la S-box")
        return int(text, 0)
    raise ValueError(f"No se pudo convertir a entero: {value!r}")


def _parse_list_from_text(raw: str) -> list[int]:
    text = raw.strip()
    if not text:
        raise ValueError("La lista de --sbox esta vacia")

    # 1) Intentar JSON (admite [1,2,3] y strings hex dentro del JSON)
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return [_parse_int(v) for v in data]
    except json.JSONDecodeError:
        pass

    # 2) Intentar literal Python (admite [0x1, 0x2, ...])
    try:
        data = ast.literal_eval(text)
        if isinstance(data, (list, tuple)):
            return [_parse_int(v) for v in data]
    except (ValueError, SyntaxError):
        pass

    # 3) Intentar "v1,v2,v3"
    if "," in text:
        return [_parse_int(chunk) for chunk in text.split(",")]

    raise ValueError(
        "No se pudo parsear --sbox. Usa una lista JSON/Python o una lista separada por comas."
    )


def _load_sbox_from_file(path: Path) -> tuple[list[int], int | None, int | None, str]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return ([_parse_int(v) for v in data], None, None, path.stem)

    if not isinstance(data, dict):
        raise ValueError("El JSON debe ser una lista o un objeto con clave 'table'")

    if "table" not in data:
        raise ValueError("Falta la clave 'table' en el JSON")

    table = [_parse_int(v) for v in data["table"]]
    input_size = data.get("input_size")
    output_size = data.get("output_size")
    name = str(data.get("name", path.stem))

    input_size = int(input_size) if input_size is not None else None
    output_size = int(output_size) if output_size is not None else None
    return table, input_size, output_size, name


def _is_power_of_two(value: int) -> bool:
    return value > 0 and (value & (value - 1)) == 0


def _infer_input_size(table_len: int) -> int:
    if not _is_power_of_two(table_len):
        raise ValueError(
            f"La longitud de la S-box ({table_len}) no es potencia de 2; no se puede inferir input_size."
        )
    return int(math.log2(table_len))


def _infer_output_size(table: Sequence[int]) -> int:
    max_value = max(table) if table else 0
    return max(1, max_value.bit_length())


def _validate_table(table: Sequence[int], input_size: int, output_size: int) -> None:
    expected = 1 << input_size
    if len(table) != expected:
        raise ValueError(
            f"Tamano de tabla invalido: se esperaban {expected} entradas para input_size={input_size}, pero hay {len(table)}."
        )

    upper = 1 << output_size
    for idx, value in enumerate(table):
        if value < 0 or value >= upper:
            raise ValueError(
                f"Valor fuera de rango en tabla[{idx}]={value}. Debe estar en [0, {upper - 1}] para output_size={output_size}."
            )


def compute_ddt(table: Sequence[int], input_size: int, output_size: int) -> list[list[int]]:
    n_in = 1 << input_size
    n_out = 1 << output_size
    ddt = [[0 for _ in range(n_out)] for _ in range(n_in)]

    for dx in range(n_in):
        for x in range(n_in):
            dy = table[x] ^ table[x ^ dx]
            ddt[dx][dy] += 1
    return ddt


def print_ddt(ddt: Sequence[Sequence[int]]) -> None:
    if not ddt:
        print("(DDT vacia)")
        return

    rows = len(ddt)
    cols = len(ddt[0])
    cell_width = max(len(str(value)) for row in ddt for value in row)
    row_header = max(2, len(str(rows - 1)))

    header = " " * (row_header + 1)
    header += " ".join(f"{j:>{cell_width}}" for j in range(cols))
    print(header)

    for i, row in enumerate(ddt):
        values = " ".join(f"{value:>{cell_width}}" for value in row)
        print(f"{i:>{row_header}} {values}")


def save_ddt_csv(ddt: Sequence[Sequence[int]], out_path: Path) -> None:
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(ddt)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Calcula la tabla diferencial (DDT) de una S-box."
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--file",
        type=str,
        help="Ruta a JSON con la S-box (objeto con table/input_size/output_size o lista).",
    )
    src.add_argument(
        "--sbox",
        type=str,
        help="Lista directa de la S-box: JSON/Python ([...]) o coma-separada.",
    )
    parser.add_argument(
        "--input-size",
        type=int,
        default=None,
        help="Bits de entrada. Si no se da, se infiere por longitud de tabla.",
    )
    parser.add_argument(
        "--output-size",
        type=int,
        default=None,
        help="Bits de salida. Si no se da, se infiere por valor maximo de tabla.",
    )
    parser.add_argument(
        "--format",
        choices=("table", "csv"),
        default="table",
        help="Formato de salida en consola. 'csv' imprime CSV en stdout.",
    )
    parser.add_argument(
        "--out",
        type=str,
        default=None,
        help="Si se indica, guarda la DDT en CSV en esta ruta.",
    )
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.file:
        table, file_input_size, file_output_size, name = _load_sbox_from_file(Path(args.file))
    else:
        table = _parse_list_from_text(args.sbox)
        file_input_size = None
        file_output_size = None
        name = "sbox_cli"

    input_size = args.input_size
    output_size = args.output_size

    if input_size is None:
        input_size = file_input_size if file_input_size is not None else _infer_input_size(len(table))
    if output_size is None:
        output_size = file_output_size if file_output_size is not None else _infer_output_size(table)

    _validate_table(table, input_size, output_size)
    ddt = compute_ddt(table, input_size, output_size)

    print(f"S-box: {name}")
    print(f"input_size={input_size}, output_size={output_size}, entradas={len(table)}")

    if args.format == "table":
        print_ddt(ddt)
    else:
        writer = csv.writer(__import__("sys").stdout)
        writer.writerows(ddt)

    if args.out:
        out_path = Path(args.out)
        save_ddt_csv(ddt, out_path)
        print(f"DDT guardada en: {out_path}")


if __name__ == "__main__":
    main()
