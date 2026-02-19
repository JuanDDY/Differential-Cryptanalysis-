import numpy as np
import pandas as pd
import altair as alt
import matplotlib.colors as mcolors
from evaluation.markov_chains.basic_markov_chain import create_transition_matrix, DifferentialMarkovChain

def compare_tv_distance_altair(
    specs,
    r_values=None,
    log_scale: bool = False,
    detail: bool = False
) -> alt.Chart:
    if r_values is None:
        r_values = list(range(1, 21))

    records = []
    for spec in specs:
        name  = spec['name']
        table = np.array(spec['table'], dtype=int)
        P     = create_transition_matrix(table,
                                         spec['n_in'],
                                         spec['n_out'],
                                         skip_zero=True)
        chain = DifferentialMarkovChain(P)
        for r in r_values:
            records.append({
                'r': r,
                'S-Box': name,
                'TV distance': chain.tv_distance(r)
            })
    df = pd.DataFrame(records)

    if detail:
        print(df.pivot(index='r',
                       columns='S-Box',
                       values='TV distance').to_markdown())

    domain       = [spec['name']  for spec in specs]
    raw_colors   = [spec['color'] for spec in specs]
    range_colors = [mcolors.to_hex(c) for c in raw_colors]

    chart = (
        alt.Chart(df)
        .mark_line(point=True)
        .encode(
            x=alt.X('r:Q', title='Steps (r)'),
            y=alt.Y('TV distance:Q',
                    title='TV distance',
                    scale=alt.Scale(type='log') if log_scale else alt.Scale()),
            color=alt.Color('S-Box:N',
                            scale=alt.Scale(domain=domain, range=range_colors),
                            legend=alt.Legend(title='S-Box')),
            tooltip=['r', 'S-Box', 'TV distance']
        )
        .properties(
            width=600,
            height=400,
            title='TV distance vs Steps'
        )
        .interactive()
    )
    return chart


def compare_max_probability_altair(
    specs,
    r_values=None,
    log_scale: bool = False,
    detail: bool = False
) -> alt.Chart:
    if r_values is None:
        r_values = list(range(1, 21))

    records = []
    for spec in specs:
        name  = spec['name']
        table = np.array(spec['table'], dtype=int)
        P     = create_transition_matrix(table,
                                         spec['n_in'],
                                         spec['n_out'],
                                         skip_zero=True)
        chain = DifferentialMarkovChain(P)
        for r in r_values:
            records.append({
                'r': r,
                'S-Box': name,
                'Max probability': chain.max_probability(r)
            })
    df = pd.DataFrame(records)

    if detail:
        print(df.pivot(index='r',
                       columns='S-Box',
                       values='Max probability').to_markdown())

    domain       = [spec['name']  for spec in specs]
    raw_colors   = [spec['color'] for spec in specs]
    range_colors = [mcolors.to_hex(c) for c in raw_colors]

    chart = (
        alt.Chart(df)
        .mark_line(point=True)
        .encode(
            x=alt.X('r:Q', title='Steps (r)'),
            y=alt.Y('Max probability:Q',
                    title='Max probability',
                    scale=alt.Scale(type='log') if log_scale else alt.Scale()),
            color=alt.Color('S-Box:N',
                            scale=alt.Scale(domain=domain, range=range_colors),
                            legend=alt.Legend(title='S-Box')),
            tooltip=['r', 'S-Box', 'Max probability']
        )
        .properties(
            width=600,
            height=400,
            title='Max probability vs Steps'
        )
        .interactive()
    )
    return chart


def compare_mixing_times_altair(
    specs,
    epsilons=None,
    max_steps: int = 10_000,
    log_scale: bool = False
) -> alt.Chart:
    if epsilons is None:
        epsilons = [10**(-i) for i in range(1, 11)]
    print(epsilons)
    # 1) Armar DataFrame “long”
    records = []
    for spec in specs:
        name  = spec['name']
        table = np.array(spec['table'], dtype=int)
        P     = create_transition_matrix(table, spec['n_in'], spec['n_out'], skip_zero=True)
        chain = DifferentialMarkovChain(P)

        for eps in epsilons:
            records.append({
                'ε':           eps,
                'S-Box':       name,
                'Método':      'iterative',
                'Mixing time': chain.mixing_time_iterative(epsilon=eps, max_steps=max_steps)
            })
            print(f"{name} with ε={eps}: {chain.mixing_time_iterative(epsilon=eps, max_steps=max_steps)}")
            """
            records.append({
                'ε':           eps,
                'S-Box':       name,
                'Método':      'espectral',
                'Mixing time': chain.mixing_time_spectral(epsilon=eps, max_steps=max_steps)
            })
            """

    df = pd.DataFrame.from_records(records)

    # 2) Dominio y paleta (en el mismo orden que specs)
    
    domain       = [spec['name']  for spec in specs]
    range_colors = [spec['color'] for spec in specs]

    # 3) Gráfico Altair
    chart = (
        alt.Chart(df)
        .mark_line(point=True)
        .encode(
            x=alt.X('ε:Q',
                    title='ε',
                    scale=alt.Scale(type='log') if log_scale else alt.Scale()),
            y=alt.Y('Mixing time:Q', title='Mixing time (steps)'),
            color=alt.Color('S-Box:N',
                            scale=alt.Scale(domain=domain, range=range_colors),
                            legend=alt.Legend(title='S-Box')),
            strokeDash=alt.StrokeDash('Método:N',
                                     scale=alt.Scale(
                                       domain=['iterativo','espectral'],
                                       range=[[],[4,4]]
                                     ),
                                     legend=alt.Legend(title='Método')),
            tooltip=['S-Box','Método','ε','Mixing time']
        )
        .properties(
            width=600,
            height=400,
            title='Mixing time vs bound'
        )
        .interactive()
    )

    return chart



def compare_mixing_times_spectrals_altair(
    specs,
    epsilons=None,
    max_steps: int = 10_000,
    log_scale: bool = False
) -> alt.Chart:
    if epsilons is None:
        epsilons = [10**(-i) for i in range(1, 11)]

    # 1) DataFrame “long”
    records = []
    for spec in specs:
        name  = spec['name']
        table = np.array(spec['table'], dtype=int)
        P     = create_transition_matrix(table, spec['n_in'], spec['n_out'], skip_zero=True)
        chain = DifferentialMarkovChain(P)

        for eps in epsilons:
            records.append({
                'ε':           eps,
                'S-Box':       name,
                'Método':      'iterativo',
                'Mixing time': chain.mixing_time_iterative(epsilon=eps, max_steps=max_steps)
            })
            records.append({
                'ε':           eps,
                'S-Box':       name,
                'Método':      'espectral',
                'Mixing time': chain.mixing_time_spectral(eps=eps)
            })

    df = pd.DataFrame.from_records(records)

    # 2) Misma paleta
    domain       = [spec['name']  for spec in specs]
    range_colors = [spec['color'] for spec in specs]

    # 3) Gráfico
    chart = (
        alt.Chart(df)
        .mark_line(point=True)
        .encode(
            x=alt.X('ε:Q',
                    title='ε',
                    scale=alt.Scale(type='log') if log_scale else alt.Scale()),
            y=alt.Y('Mixing time:Q', title='Mixing time (steps)'),
            color=alt.Color('S-Box:N',
                            scale=alt.Scale(domain=domain, range=range_colors),
                            legend=alt.Legend(title='S-Box')),
            strokeDash=alt.StrokeDash('Método:N',
                                     scale=alt.Scale(
                                       domain=['iterativo','espectral'],
                                       range=[[],[4,4]]
                                     ),
                                     legend=alt.Legend(title='Método')),
            tooltip=['S-Box','Método','ε','Mixing time']
        )
        .properties(
            width=600,
            height=400,
            title='Mixing times iterativo vs espectral (todo junto)'
        )
        .interactive()
    )

    return chart