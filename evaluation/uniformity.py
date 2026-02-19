import numpy as np
from sboxes import SBox

def ddt(table, input_size: int, output_size: int):
    """
    Construye la diferencia-distribución (DDT) corrigiendo
    valores hexadecimales representados como strings.
    """
    # 1) Convertimos cada entry a int, interpretando "0x.." si es str
    N = 1 << input_size
    arr = np.empty(N, dtype=np.int64)
    for i, v in enumerate(table):
        # v puede ser int, np.integer, str, np.str_
        if isinstance(v, (str, np.str_)):
            arr[i] = int(v, 0)      # int("0x1", 0) -> 1
        else:
            arr[i] = int(v)

    # 2) Ahora sí construimos la DDT
    ddt = np.zeros((N, 1 << output_size), dtype=np.uint32)
    for dx in range(N):
        for x in range(N):
            x_prime = x ^ dx
            # arr[x] y arr[x_prime] son int de verdad
            assert 0 <= arr[x] < (1 << output_size)
            assert 0 <= arr[x_prime] < (1 << output_size)
            dy = arr[x] ^ arr[x_prime]
            ddt[dx, dy] += 1

    return ddt

def get_ddt(sbox: SBox) -> np.ndarray:
    # Invertimos input/output porque DDT usa input bits como filas
    return ddt(sbox.table, sbox.input_size, sbox.output_size)
