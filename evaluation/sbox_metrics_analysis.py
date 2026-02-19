import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import matplotlib.colors as mcolors

from evaluation.avalanche_criterion import avalanche_criterion
from evaluation.fixed_points      import fixed_ponts
from evaluation.uniformity         import get_ddt
from evaluation.linearity         import evaluate
from sboxes.loader                import load as load_sbox


def get_metrics(specs: list[dict]) -> pd.DataFrame:
    """
    Calcula métricas básicas para un conjunto de S-Boxes.
    """
    metrics = []
    for i, spec in enumerate(specs):
        sbox = spec['sbox']
        ddt_matrix       = get_ddt(sbox)
        max_ddt_ex0      = np.max(ddt_matrix[1:])      # ignoramos dx=0
        uniformity       = max_ddt_ex0
        fixed_points     = fixed_ponts(sbox, detail=True)[1]
        non_lin          = evaluate(sbox)
        avg_sac,_,stds,max_std = avalanche_criterion(sbox)

        metrics.append({
            'name':           spec['name'],
            'uniformity':     uniformity,
            'max_ddt':        np.max(ddt_matrix),
            'fixed_points':   fixed_points,
            'non_linearity':  non_lin,
            'avg_sac':        avg_sac,
            'max_std_sac':    max_std
        })

    return pd.DataFrame(metrics)


def plot_metric_bars(df: pd.DataFrame,
                     metric: str,
                     specs: list[dict],
                     title: str = None):
    """
    Crea un gráfico de barras para una métrica específica,
    usando los colores definidos en cada spec.
    """
    # 1) Extraer el orden y la paleta de colores de specs
    order  = [spec['name']  for spec in specs]
    rawc   = [spec['color'] for spec in specs]
    # Convertir tuplas RGB a HEX si hace falta
    palette = [mcolors.to_hex(c) if not isinstance(c, str) else c
               for c in rawc]

    # 2) Dibujar
    plt.figure(figsize=(8, 4))
    sns.barplot(
        data=df,
        x='name',
        y=metric,
        order=order,
        palette=palette,
        dodge=False
    )
    plt.title(title or metric.replace('_',' ').title())
    plt.xlabel('S-Box')
    plt.ylabel(metric.replace('_',' ').title())
    plt.xticks(rotation=30, ha='right')
    plt.tight_layout()
    plt.show()


def run_all_metrics(specs: list[dict],
                    filename: str ="sbox_metrics_summary") -> pd.DataFrame:
    df = get_metrics(specs)

    # 1) Tabla en consola
    print("\n=== Métricas de S-Boxes ===")
    print(df.to_string(index=False))

    # 2) Gráficos de barras
    for col in ['uniformity',
                'max_ddt',
                'fixed_points',
                'non_linearity',
                'avg_sac',
                'max_std_sac']:
        plot_metric_bars(
            df,
            metric=col,
            specs=specs,
            title=col.replace('_',' ').title()
        )

    # 3) Guardar CSV
    df.to_csv(f"{filename}.csv", index=False)
    return df

if __name__ == "__main__":
    # Carga ejemplo
    specs = []
    to_proof = ["ascon", "nuestro 5.v1", "nuestro 5.v2", "nuestro 5.v3"]
    for sbox_link in to_proof:
        sbox = load_sbox(f"sboxes/data/{sbox_link}.json")
        specs.append({
            'name': sbox_link,
            'table': sbox.table.tolist(),
            'n_in': sbox.input_size,
            'n_out': sbox.output_size,
            'color': None,
            'sbox': sbox
        })
        
    run_all_metrics(specs)
