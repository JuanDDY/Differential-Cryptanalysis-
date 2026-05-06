from __future__ import annotations

import os
import sys
from typing import Callable, Dict, Tuple


CURRENT_DIR = os.path.dirname(__file__)
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from aes_impossible_dc import main as aes_demo
from klein_impossible_dc import main as klein_demo
from spn16_impossible_dc import main as spn16_demo


MenuAction = Tuple[str, Callable[[], None]]


OPTIONS: Dict[str, MenuAction] = {
    "1": ("Ataque diferencial imposible a SPN16", spn16_demo),
    "2": ("Ataque diferencial imposible a AES", aes_demo),
    "3": ("Ataque diferencial imposible a KLEIN", klein_demo),
}


def print_menu() -> None:
    print("=== Impossible Differential Cryptanalysis ===")
    for key, (label, _) in OPTIONS.items():
        print(f"{key}. {label}")
    print("0. Salir")


def main() -> None:
    while True:
        print_menu()
        choice = input("Selecciona una opcion: ").strip()

        if choice == "0":
            print("Saliendo.")
            return

        selected = OPTIONS.get(choice)
        if selected is None:
            print("Opcion invalida.\n")
            continue

        label, action = selected
        print(f"\n{label}\n")
        try:
            action()
        except Exception as exc:
            print(f"Error durante la ejecucion: {exc}")

        print("")
        input("Presiona Enter para volver al menu...")
        print("")


if __name__ == "__main__":
    main()
