#!/usr/bin/env python3
"""
Pruebas de cadenas de Markov para S-Boxes.
Ubicado en evaluation/markov_chains/test_markov_chain.py
"""

import matplotlib.pyplot as plt
from tabulate import tabulate

from sboxes.loader import load as load_sbox
from evaluation.markov_chains.basic_markov_chain import DifferentialMarkovChain, create_transition_matrix_from_sbox
from evaluation.identity_sbox import IdentitySBox


def test_sbox_markov(sbox, epsilon=1e-4, r_values=None):
    if r_values is None:
        r_values = [1,2,5,10]
    print(f"\n--- Pruebas MarkovChain: {type(sbox).__name__} ---")
    P = create_transition_matrix_from_sbox(sbox)
    chain = DifferentialMarkovChain(P)

    # Propiedades
    print("Doble estocástica:", chain.is_doubly_stochastic())
    print("Irreducible:", chain.is_irreducible())
    print("Aperiodic:", chain.is_aperiodic())
    print("Ergódica:", chain.is_ergodic())

    # Mixing times
    print(f"Mixing time iterativo (ε={epsilon}): {chain.mixing_time_iterative(epsilon)}")
    print(f"Mixing time espectral  (ε={epsilon}): {chain.mixing_time_spectral(epsilon)}")

    # TV distance y max_probability
    tbl = []
    for r in r_values:
        tv = chain.tv_distance(r)
        mp = chain.max_probability(r)
        tbl.append([r, f"{tv:.6f}", f"{mp:.6f}"])
    print(tabulate(tbl, headers=['r','TV distance','Max probability'], tablefmt='github'))

    # Gráfica de TV distance
    rs = list(range(1, max(r_values)+1))
    tvs = [chain.tv_distance(r) for r in rs]
    plt.figure(figsize=(5,3))
    plt.plot(rs, tvs, 'o-')
    plt.title(f"TV distance vs r: {type(sbox).__name__}")
    plt.xlabel("r")
    plt.ylabel("TV distance")
    plt.grid(True)
    plt.show()


def main():
    # ASCON
    print("=== Testing ASCON S-Box ===")
    ascon = load_sbox("sboxes/data/ascon.json")
    test_sbox_markov(ascon)

    # Identity 4x4
    print("=== Testing Identity 4x4 S-Box ===")
    ident = IdentitySBox(4)
    test_sbox_markov(ident)


if __name__ == "__main__":
    main()
