#!/usr/bin/env python3
"""
Script de pruebas para S-Boxes.
Ejecuta:
  - Pruebas de Cadena de Markov (propiedades, mixing times, TV distance, max probability)
para un conjunto de S-Boxes definido en la lista `sboxes_to_test`.
"""
import matplotlib.pyplot as plt
from tabulate import tabulate

from sboxes.loader import load as load_sbox
from evaluation.markov_chains.basic_markov_chain import DifferentialMarkovChain, create_transition_matrix, create_transition_matrix_from_sbox
from evaluation.identity_sbox import IdentitySBox

def test_markov(sbox, name: str, epsilon: float = 1e-4, r_values=None):
    print(f"\n=== Markov Chain Tests: {name} ===")
    P = create_transition_matrix_from_sbox(sbox)
    chain = DifferentialMarkovChain(P)
    # Propiedades
    props = chain.analyze_markov_chain()
    print(tabulate(props.items(), tablefmt='github'))

    # Mixing times
    tau_iter = chain.mixing_time_iterative(epsilon)
    tau_spec = chain.mixing_time_spectral(epsilon)
    print(f"Mixing time iterativo (ε={epsilon}): {tau_iter}")
    print(f"Mixing time espectral  (ε={epsilon}): {tau_spec}")

    # TV distance y max probability por paso
    if r_values is None:
        r_values = [1,2,5,10,20]
    table = []
    for r in r_values:
        tv = chain.tv_distance(r)
        mp = chain.max_probability(r)
        table.append([r, f"{tv:.4f}", f"{mp:.4f}"])
    print(tabulate(table, headers=['r','TV distance','Max probability'], tablefmt='github'))

    # Graficar comparativas (opcional)
    try:
        rs = r_values
        tvs = [chain.tv_distance(r) for r in rs]
        mps = [chain.max_probability(r) for r in rs]
        fig, ax1 = plt.subplots()
        ax1.plot(rs, tvs, 'o-', label='TV distance')
        ax1.set_xlabel('Steps r')
        ax1.set_ylabel('TV distance')
        ax2 = ax1.twinx()
        ax2.plot(rs, mps, 's--', color='red', label='Max probability')
        ax2.set_ylabel('Max probability')
        plt.title(f"TV & MaxProb vs r: {name}")
        fig.tight_layout()
        plt.show()
    except Exception:
        pass


def test_tv_distance(sbox, r_values=None):
    """
    Calcula y muestra la distancia de variación total (TV distance)
    para una lista de valores de pasos r sobre la cadena de Markov
    asociada a la DDT de la sbox.
    """
    if r_values is None:
        r_values = list(range(1, 21))  # por defecto r=1..20

    # Construir matriz de transición y cadena
    P = create_transition_matrix_from_sbox(sbox)
    chain = DifferentialMarkovChain(P)

    # Recoger resultados
    rows = []
    for r in r_values:
        tv = chain.tv_distance(r)
        rows.append([r, f"{tv:.6f}"])

    # Mostrar tabla
    print(f"\nTV Distance para {type(sbox).__name__}:")
    print(tabulate(rows, headers=["r", "TV distance"], tablefmt="github"))
    return {r: float(tv) for r, tv in rows}


def test_max_probability(sbox, r_values=None):
    """
    Calcula y muestra la probabilidad máxima (max probability)
    para una lista de valores de pasos r sobre la cadena de Markov
    asociada a la DDT de la sbox.
    """
    if r_values is None:
        r_values = list(range(1, 21))  # por defecto r=1..20

    # Construir matriz de transición y cadena
    P = create_transition_matrix_from_sbox(sbox)
    chain = DifferentialMarkovChain(P)

    # Recoger resultados
    rows = []
    for r in r_values:
        mp = chain.max_probability(r)
        rows.append([r, f"{mp:.6f}"])

    # Mostrar tabla
    print(f"\nMax Probability para {type(sbox).__name__}:")
    print(tabulate(rows, headers=["r", "Max probability"], tablefmt="github"))
    return {r: float(mp) for r, mp in rows}


def test_mixing_times(sbox, name: str, epsilons=None, max_steps: int = 10_000):
    """
    Contrasta los mixing times (iterativo vs espectral) para distintos ε.
    - sbox: objeto con .table, .input_size, .output_size
    - name: nombre para los prints
    - epsilons: lista de ε a probar (si None, usa [1e-1,1e-2,1e-3,1e-4])
    """
    if epsilons is None:
        epsilons = [1e-1, 1e-2, 1e-3, 1e-4]
    # Construir cadena
    P = create_transition_matrix_from_sbox(sbox)
    chain = DifferentialMarkovChain(P)

    rows = []
    for eps in epsilons:
        tau_iter = chain.mixing_time_iterative(epsilon=eps, max_steps=max_steps)
        tau_spec = chain.mixing_time_spectral(eps=eps)
        rows.append([f"{eps:.0e}", tau_iter, f"{tau_spec:.1f}"])
    print(f"\n=== Mixing times para {name} ===")
    print(tabulate(rows,
                   headers=["ε", "τ_iterativo (pasos)", "τ_espectral (cota)"],
                   tablefmt="github"))
    return {eps: (tau_iter, tau_spec) for (eps, tau_iter, tau_spec) in rows}


#######################################
# Comparaciones entre S-Boxes
#######################################

import numpy as np
import matplotlib.pyplot as plt
from tabulate import tabulate
from evaluation.markov_chains.basic_markov_chain import create_transition_matrix, DifferentialMarkovChain

def compare_tv_distance(specs, detail: bool = False, graphic: bool = False, log_scale: bool = False, r_values=None, ):
    """
    Compara TV distance para varias S-Boxes.
    specs: lista de dicts {'name', 'table', 'n_in', 'n_out', 'color'}
    """
    if r_values is None:
        r_values = list(range(1, 21))
    # Crear cadenas
    chains = {
        spec['name']: (DifferentialMarkovChain(
                          create_transition_matrix(
                            np.array(spec['table']),
                            spec['n_in'], spec['n_out']
                          )),
                        spec['color'])
        for spec in specs
    }

    # Mostrar tabla
    headers = ['r'] + list(chains.keys())
    rows = []
    for r in r_values:
        row = [r] + [f"{chains[name][0].tv_distance(r):.6f}" for name in chains]
        rows.append(row)
    if detail:
        print(tabulate(rows, headers=headers, tablefmt="github"))

    # Graficar
    if graphic:
        plt.figure()
        for name, (chain, color) in chains.items():
            tvs = [chain.tv_distance(r) for r in r_values]
            plt.plot(r_values, tvs, 'o-', label=name, color=color)
        plt.xlabel('r')
        plt.ylabel('TV distance')
        if log_scale == 1:
            plt.yscale('log')
        elif log_scale == 2:
            plt.yscale('logit')
        plt.title('TV distance vs Steps')
        plt.legend()
        plt.grid(True)
        plt.show()
    return {name: [chain.tv_distance(r) for r in r_values] for name, (chain, _) in chains.items()}


def compare_max_probability(specs, detail: bool = False, graphic: bool = False, log_scale: bool = False, r_values=None, ):
    """
    Compara Max probability para varias S-Boxes.
    specs: lista de dicts {'name', 'table', 'n_in', 'n_out', 'color'}
    """
    if r_values is None:
        r_values = list(range(1, 21))
    chains = {
        spec['name']: (DifferentialMarkovChain(
                          create_transition_matrix(
                            np.array(spec['table']),
                            spec['n_in'], spec['n_out']
                          )),
                        spec['color'])
        for spec in specs
    }

    headers = ['r'] + list(chains.keys())
    rows = []
    for r in r_values:
        row = [r] + [f"{chains[name][0].max_probability(r):.6f}" for name in chains]
        rows.append(row)
    if detail:
        print(tabulate(rows, headers=headers, tablefmt="github"))

    if graphic:
        plt.figure()
        for name, (chain, color) in chains.items():
            mps = [chain.max_probability(r) for r in r_values]
            plt.plot(r_values, mps, 's--', label=name, color=color)
        plt.xlabel('r')
        plt.ylabel('Max probability')
        if log_scale:
                plt.yscale('log')
        plt.title('Max probability vs Steps')
        plt.legend()
        plt.grid(True)
        plt.show()
    return {name: [chain.max_probability(r) for r in r_values] for name, (chain, _) in chains.items()}


def compare_mixing_times(specs, epsilons=None, max_steps=10000, detail: bool = False, graphic: bool = False, log_scale: bool = False):
    """
    Compara mixing times (iterativo vs espectral) para varias S-Boxes.
    specs: lista de dicts {'name', 'table', 'n_in', 'n_out', 'color'}
    """
    if epsilons is None:
        epsilons = [1e-1, 1e-2, 1e-3, 1e-4, 1e-5, 1e-6, 1e-7, 1e-8, 1e-9, 1e-10]
    chains = {
        spec['name']: (DifferentialMarkovChain(
                          create_transition_matrix(
                            np.array(spec['table']),
                            spec['n_in'], spec['n_out']
                          )),
                        spec['color'])
        for spec in specs
    }

    headers = ['ε'] + [f"{name} iter" for name in chains] + [f"{name} spec" for name in chains]
    rows = []
    for eps in epsilons:
        row = [f"{eps:.0e}"]
        row += [chains[name][0].mixing_time_iterative(epsilon=eps, max_steps=max_steps) for name in chains]
        row += [f"{chains[name][0].mixing_time_spectral(eps=eps):.1f}" for name in chains]
        rows.append(row)
    
    if detail: 
        print(tabulate(rows, headers=headers, tablefmt="github"))

    if graphic:
        plt.figure()
        for name, (chain, color) in chains.items():
            tau_iter = [chain.mixing_time_iterative(epsilon=eps, max_steps=max_steps) for eps in epsilons]
            tau_spec = [chain.mixing_time_spectral(eps=eps) for eps in epsilons]
            plt.plot(epsilons, tau_iter, 'o-', label=f"{name} iter", color=color)
            plt.plot(epsilons, tau_spec, 'x--', label=f"{name} spec", color=color)
        plt.xscale('log')
        plt.xlabel('ε')
        plt.ylabel('Mixing time')
        plt.title('Mixing time vs ε')
        plt.legend()
        plt.grid(True)
        plt.show()
        return {name: (chain.mixing_time_iterative(epsilon=eps, max_steps=max_steps), chain.mixing_time_spectral(eps=eps)) for name, (chain, _) in chains.items()}
    
    
def compare_mixing_times_spectrals(specs, epsilons=None, max_steps=10000, detail: bool = False, graphic: bool = False, log_scale: bool = False):
    """
    Compara mixing times (iterativo vs espectral) para varias S-Boxes.
    specs: lista de dicts {'name', 'table', 'n_in', 'n_out', 'color'}
    """
    if epsilons is None:
        epsilons = [1e-1, 1e-2, 1e-3, 1e-4, 1e-5, 1e-6, 1e-7, 1e-8, 1e-9, 1e-10]
    chains = {
        spec['name']: (DifferentialMarkovChain(
                          create_transition_matrix(
                            np.array(spec['table']),
                            spec['n_in'], spec['n_out']
                          )),
                        spec['color'])
        for spec in specs
    }

    headers = ['ε'] + [f"{name} iter" for name in chains] + [f"{name} spec" for name in chains]
    rows = []
    for eps in epsilons:
        row = [f"{eps:.0e}"]
        row += [chains[name][0].mixing_time_iterative(epsilon=eps, max_steps=max_steps) for name in chains]
        row += [f"{chains[name][0].mixing_time_spectral(eps=eps):.1f}" for name in chains]
        rows.append(row)
    
    if detail: 
        print(tabulate(rows, headers=headers, tablefmt="github"))

    if graphic:
        plt.figure()
        for name, (chain, color) in chains.items():
            tau_iter = [chain.mixing_time_iterative(epsilon=eps, max_steps=max_steps) for eps in epsilons]
            tau_spec = [chain.mixing_time_spectral(eps=eps) for eps in epsilons]
            plt.plot(epsilons, tau_iter, 'o-', label=f"{name} iter", color=color)
            plt.plot(epsilons, tau_spec, 'x--', label=f"{name} spec", color=color)
        plt.xscale('log')
        plt.xlabel('ε')
        plt.ylabel('Mixing time')
        plt.title('Mixing time vs ε')
        plt.legend()
        plt.grid(True)
        plt.show()
        return {name: (chain.mixing_time_iterative(epsilon=eps, max_steps=max_steps), chain.mixing_time_spectral(eps=eps)) for name, (chain, _) in chains.items()}

    
#
# Intento con otras librerias
#
import pandas as pd

def get_tv_distance_dataframe(specs, r_values=None):
    if r_values is None:
        r_values = list(range(1, 21))  # o el rango que uses normalmente
    data = []
    for spec in specs:
        name = spec['name']
        chain = DifferentialMarkovChain(
            create_transition_matrix(np.array(spec['table']), spec['n_in'], spec['n_out'])
        )
        for r in r_values:
            data.append({'SBox': name, 'r': r, 'TV distance': chain.tv_distance(r)})
    return pd.DataFrame(data)


import seaborn as sns
def compare_with_seaborn(specs, r_values=None, log_scale: bool = False):
    df = get_tv_distance_dataframe(specs, r_values)
    sns.set_theme(style="whitegrid")
    plt.figure(figsize=(6, 4))
    sns.lineplot(data=df, x='r', y='TV distance', hue='SBox', marker='o')
    plt.title("TV distance vs Steps")
    plt.xlabel("r")
    plt.ylabel("TV distance")
    if log_scale == 1:
        plt.yscale('log')
    elif log_scale == 2:
        plt.yscale('logit')
    plt.tight_layout()
    plt.savefig("tv_seaborn.pdf")
    plt.show()

from plotnine import ggplot, aes, geom_line, geom_point, theme_minimal, labs, theme, element_text, scale_y_log10, scale_y_sqrt
from IPython.display import display
def compare_with_plotnine(specs, r_values=None, log_scale: bool = False):
    df = get_tv_distance_dataframe(specs, r_values)
    if log_scale ==1:
        plot = (ggplot(df, aes(x='r', y='TV distance', color='SBox'))
            + geom_line()
            + geom_point()
            + scale_y_log10()  # Escala log
            + labs(title='TV distance vs Steps (log scale)', x='r', y='TV distance (log)')
            + theme_minimal()
            + theme(
                legend_title=element_text(size=10),
                axis_title=element_text(size=12),
                axis_text=element_text(size=10)))
        display(plot)
    elif log_scale == 2:
        plot = (ggplot(df, aes(x='r', y='TV distance', color='SBox'))
                + geom_line()
                + geom_point()
                + scale_y_sqrt() 
                + labs(title='TV distance vs Steps', x='r', y='TV distance')
                + theme_minimal()
                + theme(
                    legend_title=element_text(size=10),
                    axis_title=element_text(size=12),
                    axis_text=element_text(size=10)))
        display(plot)
    else:
        plot = (ggplot(df, aes(x='r', y='TV distance', color='SBox'))
                + geom_line()
                + geom_point()
                + labs(title='TV distance vs Steps', x='r', y='TV distance')
                + theme_minimal()
                + theme(
                    legend_title=element_text(size=10),
                    axis_title=element_text(size=12),
                    axis_text=element_text(size=10)))
        display(plot)


import altair as alt
def compare_with_altair(specs, r_values=None, log_scale: bool = False):
    df = get_tv_distance_dataframe(specs, r_values)
    if log_scale == 1:
        chart = alt.Chart(df).mark_line(point=True).encode(
            x=alt.X('r:O', title='r'),
            y=alt.Y('TV distance:Q', scale=alt.Scale(type='log'), title='TV distance (log)'),  # log scale
            color='SBox:N'
        ).properties(
            title='TV distance vs Steps',
            width=400,
            height=300
        ).configure_axis(
            labelFontSize=11,
            titleFontSize=12
        ).configure_title(
            fontSize=13
        )
        chart.save('tv_altair.html')
        chart.display()
    elif log_scale == 2: 
        chart = alt.Chart(df).mark_line(point=True).encode(
            x=alt.X('r:O', title='r'),
            y=alt.Y('value:Q', scale=alt.Scale(type='sqrt')) ,
            color='SBox:N'
        ).properties(
            title='TV distance vs Steps',
            width=400,
            height=300
        ).configure_axis(
            labelFontSize=11,
            titleFontSize=12
        ).configure_title(
            fontSize=13
        )
        chart.save('tv_altair.html')
        chart.display()
    else: 
        chart = alt.Chart(df).mark_line(point=True).encode(
            x=alt.X('r:O', title='r'),
            y=alt.Y('TV distance:Q', title='TV distance'),
            color='SBox:N'
        ).properties(
            title='TV distance vs Steps',
            width=400,
            height=300
        ).configure_axis(
            labelFontSize=11,
            titleFontSize=12
        ).configure_title(
            fontSize=13
        )
        chart.save('tv_altair.html')
        chart.display()

    
def main():
    # Lista de S-Boxes a probar
    sboxes_to_test = [
        ('ASCON', load_sbox('sboxes/data/ascon.json')),
        ('Identity 4x4', IdentitySBox(4)),
        ('5x5-A', load_sbox('sboxes/data/nuestro 5.json')),
        #('5x5-B', load_sbox('sboxes/custom_sbox_b.json'))
    ]

    for name, sbox in sboxes_to_test:
        test_markov(sbox, name)


if __name__ == "__main__":
    from sboxes.loader import load as load_sbox
    from evaluation.identity_sbox import IdentitySBox

    # Prueba con ASCON
    ascon = load_sbox("sboxes/ascon.json")
    test_tv_distance(ascon)
    test_max_probability(ascon)

    # Prueba con Identity 4×4
    id4 = IdentitySBox(4)
    test_tv_distance(id4)
    test_max_probability(id4)

