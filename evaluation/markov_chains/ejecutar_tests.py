#!/usr/bin/env python3
"""
tests_markov_metrics.py

Ejecuta pruebas específicas de TV Distance y Max Probability
para diferentes S-Boxes usando tu implementación de cadenas de Markov.
"""

import matplotlib.pyplot as plt
from tabulate import tabulate

from sboxes.loader import load as load_sbox
from evaluation.markov_chains.basic_markov_chain import create_transition_matrix, DifferentialMarkovChain
from evaluation.graphics.all_test_markov_chains import test_tv_distance, test_max_probability
from evaluation.avalanche_criterion import IdentitySBox


def run_metrics_for_sbox(sbox, name, r_max=20):
    """
    Ejecuta y muestra pruebas de TV Distance y Max Probability
    para una S-Box dada.
    """
    print(f"\n=== Pruebas de métricas: {name} ===")
    # TV Distance
    test_tv_distance(sbox, r_max=r_max)
    # Max Probability
    test_max_probability(sbox, r_max=r_max)


def main():
    # Listado de S-Boxes a probar
    specs = [
        {"name": "ASCON", "sbox": load_sbox("sboxes/ascon.json")},
        {"name": "Identity 4x4", "sbox": IdentitySBox(4)},
    ]

    for spec in specs:
        run_metrics_for_sbox(spec["sbox"], spec["name"], r_max=20)

if __name__ == "__main__":
    main()
