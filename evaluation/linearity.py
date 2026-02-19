# evaluation/linearity.py
import numpy as np

def dot(u: int, v: int) -> int:
    # computa el producto bit a bit (paridad) entre dos enteros
    c = 0
    x = u & v
    while x > 0:
        x &= x - 1
        c += 1
    return c % 2

def fwht_inplace(a: np.ndarray):
    n = a.shape[0]
    h = 1
    while h < n:
        for i in range(0, n, h * 2):
            for j in range(i, i + h):
                x = a[j]
                y = a[j + h]
                a[j] = x + y
                a[j + h] = x - y
        h *= 2

def evaluate_table(table, input_size: int) -> float:
    # 1) Normalizamos la tabla a una lista de enteros puros
    table_int = []
    for v in table:
        if isinstance(v, str):
            # acepta cadenas como '0x1' o '17'
            table_int.append(int(v, 0))
        else:
            table_int.append(int(v))

    size = 1 << input_size
    maximum = 0.0

    # 2) Para cada máscara b construimos la transformada de Walsh–Hadamard
    for b in range(1, size):
        h = np.empty(size, dtype=np.float64)
        for x in range(size):
            h[x] = 1.0 - 2.0 * dot(b, table_int[x])
        fwht_inplace(h)

        current_max = np.max(np.abs(h))
        if current_max > maximum:
            maximum = current_max

    # 3) No–linealidad estándar
    nonlinearity = (2 ** (input_size - 1)) - (maximum / 2.0)
    return nonlinearity

def evaluate(sbox) -> float:
    # Llama a evaluate_table sobre la tabla interna
    return evaluate_table(sbox.table, int(sbox.input_size))
