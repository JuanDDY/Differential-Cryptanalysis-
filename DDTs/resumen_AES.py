from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]  # sube de DDTs/ a repo root
sys.path.insert(0, str(ROOT))

import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

from sboxes.loader import load as load_sbox
from evaluation.uniformity import get_ddt
from evaluation.fixed_points import fixed_ponts
from evaluation.linearity import evaluate
from evaluation.avalanche_criterion import avalanche_criterion
from evaluation.markov_chains.basic_markov_chain import (
    DifferentialMarkovChain,
    create_transition_matrix,
)

DDTS_DIR = Path(__file__).resolve().parent      # .../Differential-Cryptanalysis-/DDTs
ROOT_DIR = DDTS_DIR.parent

def _to_hex_table(values) -> list[str]:
    return [hex(int(v)) for v in values]


def summarize_aes(
    json_path: str = "data/clasics/aes.json",
    metrics_csv: str = "./aes_metrics_summary.csv",
    ddt_csv: str = "./aes_ddt.csv",
    show_plot: bool = True,
):
    json_path = (ROOT_DIR / json_path).resolve()
    metrics_csv = (DDTS_DIR / metrics_csv).resolve()
    ddt_csv = (DDTS_DIR / ddt_csv).resolve()
    
    sbox = load_sbox(json_path)
    table_hex = _to_hex_table(sbox.table)

    print("=== Datos de AES ===")
    print(f"Nombre: {sbox.name}")
    print(f"Dimension: {sbox.input_size}x{sbox.output_size}")
    print(f"Tabla ({len(table_hex)} entradas):")
    print(table_hex)

    ddt = get_ddt(sbox)
    ddt_df = pd.DataFrame(
        ddt,
        index=[f"dx={i}" for i in range(ddt.shape[0])],
        columns=[f"dy={j}" for j in range(ddt.shape[1])],
    )

    print("\n=== DDT ===")
    print(ddt_df.to_markdown())

    avg_sac, sac_per_input, std_per_input, max_std = avalanche_criterion(sbox)
    fixed_points = int(fixed_ponts(sbox, detail=True)[1])
    max_ddt = int(ddt.max())
    uniformity = int(ddt[1:].max()) if ddt.shape[0] > 1 else max_ddt

    transition_matrix = create_transition_matrix(
        np.asarray(sbox.table, dtype=np.int64),
        int(sbox.input_size),
        int(sbox.output_size),
        skip_zero=True,
    )
    chain = DifferentialMarkovChain(transition_matrix)

    metrics_df = pd.DataFrame(
        [
            {
                "name": sbox.name,
                "input_size": int(sbox.input_size),
                "output_size": int(sbox.output_size),
                "uniformity": uniformity,
                "max_ddt": max_ddt,
                "fixed_points": fixed_points,
                "non_linearity": float(evaluate(sbox)),
                "avg_sac": float(avg_sac),
                "max_std_sac": float(max_std),
                "sac_per_input": [float(x) for x in np.round(sac_per_input, 6)],
                "std_sac_per_input": [float(x) for x in np.round(std_per_input, 6)],
                "spectral_gap": float(chain.spectral_gap()),
                "tv_distance_r4": float(chain.tv_distance(4)),
                "max_probability_r4": float(chain.max_probability(4)),
                "mixing_time_eps_1e-3": int(
                    chain.mixing_time_iterative(epsilon=1e-3, max_steps=10_000)
                ),
                "mixing_time_spectral_eps_1e-3": float(
                    chain.mixing_time_spectral(eps=1e-3)
                ),
            }
        ]
    )

    print("\n=== Metricas de AES ===")
    print(metrics_df.to_markdown(index=False))

    metrics_df.to_csv(metrics_csv, index=False)
    ddt_df.to_csv(ddt_csv, index=True)
    print(f"\nMetricas guardadas en: {metrics_csv}")
    print(f"DDT guardada en: {ddt_csv}")

    if show_plot:
        plt.figure(figsize=(8, 6))
        sns.heatmap(ddt_df, annot=True, fmt="d", cmap="Blues", cbar=True)
        plt.title("AES 8x8 - Difference Distribution Table (DDT)")
        plt.xlabel("Delta y")
        plt.ylabel("Delta x")
        plt.tight_layout()
        plt.show()

    return metrics_df, ddt_df


if __name__ == "__main__":
    summarize_aes()
