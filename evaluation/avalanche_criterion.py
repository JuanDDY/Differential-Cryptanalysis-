import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import numpy as np
import matplotlib.pyplot as plt
from tabulate import tabulate
from sboxes.loader import load as load_sbox
from sboxes.sbox import SBox  # Para anotaciones de tipo


def avalanche_criterion(sbox: SBox, detail: bool = False):
    """
    Calcula el Strict Avalanche Criterion (SAC) de una S-box usando su atributo .table.

    Parameters
    ----------
    sbox : SBox
        Instancia de SBox que contiene la tabla en "table".
    detail : bool
        Si True devuelve la matriz completa (input_bits x output_bits).

    Returns
    -------
    If detail=False:
        avg_sac : float        SAC promedio de todos los bits de entrada
        sac_per_input : np.ndarray  Vector de SAC por bit de entrada
        std_per_input : np.ndarray  Desviación estándar por bit de entrada
        max_std : float       Desviación estándar máxima
    If detail=True:
        sac_matrix : np.ndarray (n x m) SAC para cada par (input_bit, output_bit)
    """
    n, m = int(sbox.input_size), int(sbox.output_size)
    sac_counts = np.zeros((n, m), dtype=int)
    N = 1 << n

    def _parse(v):
        # Interpreta strings hexadecimales o decimales, o convierte ints directamente
        if isinstance(v, (str, np.str_)):
            return int(v, 0)
        else:
            return int(v)

    for i in range(n):
        mask = 1 << i
        for x in range(N):
            y      = _parse(sbox.table[x])
            y_flip = _parse(sbox.table[x ^ mask])
            diff   = y ^ y_flip
            for j in range(m):
                sac_counts[i, j] += (diff >> j) & 1

    sac_matrix = sac_counts / N
    if detail:
        return sac_matrix

    sac_per_input = sac_matrix.mean(axis=1)
    avg_sac       = sac_per_input.mean()
    std_per_input = sac_matrix.std(axis=1)
    max_std       = std_per_input.max()

    return avg_sac, sac_per_input, std_per_input, max_std


def print_avalanche_summary(sbox: SBox):
    """
    Imprime en consola un resumen tabulado del SAC para cada bit de entrada.
    """
    avg_sac, sac_per_input, std_per_input, max_std = avalanche_criterion(sbox)
    headers = ['Avg SAC', 'Std SAC']
    rows = [[f"{s:.3f}", f"{st:.3f}"] for s, st in zip(sac_per_input, std_per_input)]
    print(f"SAC promedio general: {avg_sac:.3f}")
    print(f"Desviación estándar máxima: {max_std:.3f}")
    print(tabulate(rows, headers=headers, showindex=[f'In{i}' for i in range(sbox.input_size)], tablefmt="fancy_grid"))


def plot_avalanche_matrix(sbox: SBox):
    """
    Muestra un heatmap de la matriz SAC (input_bits × output_bits).
    """
    sac_mat = avalanche_criterion(sbox, detail=True)
    fig, ax = plt.subplots()
    cax = ax.matshow(sac_mat, aspect='auto')
    fig.colorbar(cax, label='Probabilidad de cambio')
    ax.set_xlabel('Bits de salida')
    ax.set_ylabel('Bits de entrada')
    ax.set_title(f'Heatmap SAC: {type(sbox).__name__}')
    ax.set_xticks(range(sbox.output_size))
    ax.set_yticks(range(sbox.input_size))
    plt.show()


def test_avalanche(sbox, name: str):
    print(f"\n=== Avalanche Criterion: {name} ===")
    print_avalanche_summary(sbox)
    try:
        plot_avalanche_matrix(sbox)
    except Exception:
        pass  # en entorno CLI, omitimos el plot
    

class IdentitySBox:
    """
    S-Box identidad de tamaño n × n, implementa table e apply().
    """
    def __init__(self, n: int):
        self.input_size = n
        self.output_size = n
        self.table = list(range(1 << n))

    def apply(self, value: int) -> int:
        return value


if __name__ == "__main__":
    # Ejemplo con ASCON S-Box
    print("=== Avalanche Criterion con ASCON S-Box ===")
    sbox_demo = load_sbox("sboxes/data/ascon.json")
    print_avalanche_summary(sbox_demo)
    print("\nMatriz SAC completa:")
    plot_avalanche_matrix(sbox_demo)

    # Ejemplo con identidad 4×4
    print("\n=== Avalanche Criterion con Identity 4x4 ===")
    sbox_id = IdentitySBox(4)
    print_avalanche_summary(sbox_id)
    plot_avalanche_matrix(sbox_id)