import numpy as np
#from numba import jit
from evaluation import uniformity
from sboxes import SBox

#@jit(nopython=True)
def evaluate(table: np.ndarray = None, sbox: SBox = None, input_size: int = None, output_size: int = None) -> np.floating:
    if table is None and sbox is None:
        raise ValueError("Either table or sbox must be provided")
    if table is not None and sbox is not None:
        raise ValueError("Either table or sbox must be provided")
    if table is not None and (input_size is None or output_size is None):
        raise ValueError("Table must be provided with input_size and output_size")

    multiplier = 1
    if sbox is not None:
        table = uniformity.get_ddt(sbox)
        if sbox.input_size == sbox.output_size:
            multiplier = 100
    if table is not None:
        if input_size == output_size:
            multiplier = 100

    ddt_std_value = np.std(table[1:, 1:])
    nonzero = np.count_nonzero(table[1:, 0])

    return ddt_std_value + np.max(table[1:, :]) + multiplier * nonzero