import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '....')))

import numpy as np
from numpy.linalg import eigvals, matrix_power
from typing import Tuple
from math import gcd

class DifferentialMarkovChain:
    """
    Cadena de Markov basada en la tabla diferencial de un S-box.
    """

    def __init__(self, P: np.ndarray, init: str | np.ndarray = "uniform"):
        """
        Parameters
        ----------
        P : np.ndarray
            Matriz de transición (float64, filas que suman 1).
        init : "uniform", "stationary" o np.ndarray
            Distribución inicial de estados.
        """
        self.P = P.copy()
        self.k = P.shape[0]

        if isinstance(init, str):
            if init == "uniform":
                self.pi0 = np.full(self.k, 1 / self.k)
            elif init == "stationary":
                self.pi0 = self.stationary_distribution()
            else:
                raise ValueError("init debe ser 'uniform', 'stationary' o un vector numpy.")
        else:
            init = np.asarray(init, dtype=np.float64)
            assert init.shape == (self.k,) and np.isclose(init.sum(), 1.0)
            self.pi0 = init

    # ------------------------------------------------------------------
    #  Propiedades teóricas
    # ------------------------------------------------------------------
    def stationary_distribution(self, tol: float = 1e-12, max_iter: int = 10_000, print_stop_with: bool = False, initial: str ="uniform") -> np.ndarray:
        """Devuelve el vector estacionario π tal que πP = π."""
        if initial == "uniform": 
            pi = np.full(self.k, 1 / self.k)
        else: 
            pi = np.zeros(self.k)
            pi[0] = 1.0
        for _ in range(max_iter):
            new_pi = pi @ self.P
            if np.linalg.norm(new_pi - pi, 1) < tol:
                if print_stop_with: print(f"Converged with norm {np.linalg.norm(new_pi - pi, 1)}, in {_+1} iterations.")
                return new_pi
            if print_stop_with: print(f"Iteration {_+1}: norm {np.linalg.norm(new_pi - pi, 1)}")
            pi = new_pi
        raise RuntimeError("No converge; quizá la cadena no sea ergódica.")
    
    def spectral_gap(self) -> float:
        """γ = 1 − |λ₂| (λ₂ second largest eigenvalue)."""
        lams = np.sort(np.abs(eigvals(self.P)))
        return 1.0 - lams[-2].real

    def P_power(self, r: int) -> np.ndarray:
        """P^r."""
        return matrix_power(self.P, r)

    def max_probability(self, r: int) -> float:
        """Máxima entrada de P^r."""
        return self.P_power(r).max()

    # -------- distancia total a la estación (peor estado inicial) a r pasos
    def tv_distance(self, r: int):
        pi = self.stationary_distribution()
        diff = 0.5 * np.abs(self.P_power(r) - pi).sum(axis=1)
        return diff.max()

    # -------- “tiempo de mezcla” aproximado para ε dado
    def mixing_time_spectral(self, eps: float = 2**-20):
        gap = self.spectral_gap()
        if gap == 0:
            return np.inf
        from math import log, ceil
        return ceil(log(1 / (2 * eps)) / gap)
    
    def mixing_time_iterative(self, epsilon=1e-3, max_steps=10_000):
        for r in range(1, max_steps+1):
            if self.tv_distance(r) <= epsilon:
                return r
        return -1

    # ------------------------------------------------------------------
    # Verificaciones
    # ------------------------------------------------------------------
    def is_doubly_stochastic(self, tol: float = 1e-8) -> bool:
        """sum of rows and columns is 1."""
        rows = np.allclose(self.P.sum(axis=1), 1.0, atol=tol)
        cols = np.allclose(self.P.sum(axis=0), 1.0, atol=tol)
        return bool(rows and cols)

    def is_irreducible(self) -> bool:
        """
        Irreducible: grafo conexo. Construye adyacencia P>0 y chequea
        que desde un estado se pueda alcanzar a todos con DFS/BFS.
        """
        adj = (self.P > 0).astype(int)
        visited = set()
        stack = [0]
        while stack:
            u = stack.pop()
            if u in visited: continue
            visited.add(u)
            neighbors = np.where(adj[u])[0]
            stack.extend(n for n in neighbors if n not in visited)
        return len(visited) == self.k
    
    
    def compute_periods(self, tol: float = 1e-12, max_t: int = None) -> tuple[np.ndarray, int]:
        """
        Calcula el período di de cada estado i y el período global d.
        Retorna (periods, d).
        """
        k = self.k
        if max_t is None:
            max_t = 2 * k

        periods = np.zeros(k, dtype=int)
        for i in range(k):
            hits = [t for t in range(1, max_t + 1)
                    if self.P_power(t)[i, i] > tol]
            if not hits:
                periods[i] = 0
            else:
                di = hits[0]
                for t in hits[1:]:
                    di = gcd(di, t)
                periods[i] = di

        nonzero = periods[periods > 0]
        if len(nonzero) == 0:
            d = 0
        else:
            d = nonzero[0]
            for di in nonzero[1:]:
                d = gcd(d, di)
        return periods, d

    def is_aperiodic(self, tol: float = 1e-12, max_t: int = None) -> bool:
        """
        Devuelve True si el período global d = 1.
        """
        _, d = self.compute_periods(tol, max_t)
        return d == 1

    """
    def is_aperiodic(self, tol: float = 1e-12) -> bool:
        
        #Aperiodic: gcd{ t : (P^t)_{ii} > 0 } = 1 para algún i.
        #Chequea para i=0 (si irreducible, basta).
        
        powers = [self.P_power(t)[0, 0] for t in range(1, 2*self.k+1)]
        
        hits = [t for t, val in enumerate(powers, 1) if val > tol]
        if not hits:
            return False
        from math import gcd
        d = hits[0]
        for t in hits[1:]:
            d = gcd(d, t)
            if d == 1:
                return True
        return False
    """
    
    def is_ergodic(self) -> bool:
        """Ergodicidad = irreducible + aperiodic."""
        return self.is_irreducible() and self.is_aperiodic()
    
    # ------------------------------------------------------------------
    #  Simulación
    # ------------------------------------------------------------------
    def simulate(self, steps: int, random_state: int | None = None) -> np.ndarray:
        """
        Devuelve una trayectoria (array de ints) de longitud `steps`
        siguiendo las probabilidades de transición.
        """
        rng = np.random.default_rng(random_state)
        traj = np.empty(steps, dtype=np.int32)

        traj[0] = rng.choice(self.k, p=self.pi0)
        for t in range(1, steps):
            traj[t] = rng.choice(self.k, p=self.P[traj[t-1]])
        return traj
    
    
    def analyze_markov_chain(self):
        # Analiza las propiedades de una cadena de Markov
        # Verificar si es doblemente estocástica
        is_doubly_stochastic = (np.allclose(np.sum(self.P, axis=0), 1) and 
                            np.allclose(np.sum(self.P, axis=1), 1))
        
        # Verificar ergodicidad de manera simple
        is_ergodic = np.all(np.linalg.matrix_power(self.P, self.P.shape[0]) > 0)
        
        # Analizar valores propios para tasa de convergencia
        eigenvalues = np.linalg.eigvals(self.P)
        sorted_eigs = sorted(abs(eigenvalues), reverse=True)
        
        convergence_rate = sorted_eigs[1] if len(sorted_eigs) > 1 else 0
        
        return {
            "is_doubly_stochastic": is_doubly_stochastic,
            "is_ergodic": is_ergodic,
            "convergence_rate": convergence_rate,
            "eigenvalues": sorted_eigs
    }

    
from evaluation.uniformity import ddt  

def create_transition_matrix_from_sbox(sbox):
    """
    Crea la matriz de transición P para la DDT de la sbox.
    """
    table_list = list(sbox.table)
    # ddt espera (table, input_size, output_size)
    counts = ddt(table_list, int(sbox.input_size), int(sbox.output_size))
    # descartar dx = 0
    P = counts[1:,1:].astype(np.float64)
    # normalizar filas
    P /= P.sum(axis=1, keepdims=True)
    return P


def create_transition_matrix(discrete_vector: np.ndarray,
                      n_in: int, n_out: int,
                      skip_zero: bool = True) -> np.ndarray:
    """
    Devuelve la matriz de transición P (float64) a partir del S-box
    en forma de vector discreto (lookup table), usando directamente ddt.

    Parameters
    ----------
    discrete_vector : np.ndarray  (len = 2**n_in)
        Tabla del S-box.
    n_in, n_out : int
        Tamaños en bits de entrada y salida.
    skip_zero : bool
        Si True descarta la fila Δx = 0 porque no se usa en cripto-ataques.
    """
    # Llamar a ddt con tipos nativos para Numba
    counts = ddt(discrete_vector, int(n_in), int(n_out))

    # Omitir la fila/columna dx=0 si corresponde
    if skip_zero:
        counts = counts[1:, 1:]

    # Normalizar cada fila para obtener probabilidades
    row_sums = counts.sum(axis=1, keepdims=True)  

    # Devolver matriz de transición
    return counts / row_sums.astype(np.float64)
