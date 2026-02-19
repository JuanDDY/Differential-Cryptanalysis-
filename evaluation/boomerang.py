import numpy as np
from sboxes import SBox

# Boomerang Conectivity Table (BCT)
from typing import List

def bct(S: List[int]) -> List[List[int]]:
    """
    Calcula la Boomerang Connectivity Table (BCT) de una permutación S sobre F_2^n.

    Parametros
    S : list[int] s-box.

    Retorna
    beta : list[list[int]] Matriz de tamaño N x N donde beta[a][b] = β_S(a,b).
    """
    N = len(S)
    # Verificación: N debe ser potencia de 2
    if N & (N - 1) != 0:
        raise ValueError("La longitud de S debe ser una potencia de 2.")
    # Verificación: S debe ser permutación
    if sorted(S) != list(range(N)):
        raise ValueError("S debe ser una permutación de 0..N-1.")

    # Inversa de S
    S_inv = [0]*N
    for x, y in enumerate(S):
        S_inv[y] = x

    # Construir la BCT
    beta = [[0]*N for _ in range(N)]
    for a in range(N):
        for b in range(N):
            cnt = 0
            for x in range(N):
                lhs = S_inv[S[x] ^ b] ^ S_inv[S[x ^ a] ^ b]
                if lhs == a:
                    cnt += 1
            beta[a][b] = cnt
    return beta


def get_bct(sbox: SBox) -> np.ndarray:
    if sbox.input_size != sbox.output_size:
        raise ValueError("El sbox dee ser biyectivo.")
    return bct(sbox.table)
