from __future__ import annotations

import os
import sys
from typing import Callable, Dict, Tuple


CURRENT_DIR = os.path.dirname(__file__)
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from aes_dc_key_recovery import main as aes_demo
from dc_key_recovery import demo as spn16_demo
from klein_dc_key_recovery import main as klein_demo


MenuAction = Tuple[str, Callable[[], None]]


OPTIONS: Dict[str, MenuAction] = {
    "1": ("Ataque diferencial a SPN16", spn16_demo),
    "2": ("Ataque diferencial a AES reducido", aes_demo),
    "3": ("Ataque diferencial a KLEIN reducido", klein_demo),
}


def print_menu() -> None:
    print("=== Differential Cryptanalysis ===")
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
