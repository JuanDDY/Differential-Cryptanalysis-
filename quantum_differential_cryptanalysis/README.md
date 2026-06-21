# Criptoanálisis diferencial cuántico experimental sobre SPN16

Este directorio implementa, con tamaños simulables, el flujo del capítulo 6:

\[
R(y_r)=\sum_i \mathrm{RP}(y_r,i),
\qquad
\widetilde R(y_r)\approx R(y_r),
\]

seguido por una búsqueda iterativa de máximo tipo Dürr--Høyer.

## Modelo y alcance

La implementación usa el modelo Q1:

1. Los pares \((P_i,P_i^*)\), con diferencia fija
   \(\alpha=\mathtt{0B00}\), se generan clásicamente.
2. Los cifrados \((E_K(P_i),E_K(P_i^*))\) también se obtienen clásicamente.
3. La parte cuántica procesa únicamente esa tabla de pares y el espacio
   explícito de candidatas \(\mathcal K_r\).

El caso de estudio es el SPN16 de Heys con cuatro rondas, S-boxes de 4 bits y
la trayectoria:

```text
0B00 -> 0040 -> 0220 -> 0606
```

La clave de ejemplo es `00112233445566778899` y produce:

```text
K1..K5 = 0011, 2233, 4455, 6677, 8899
```

La candidata \(y_r\) corresponde a la subclave final `K5`. El descifrado
parcial es:

```text
SBOX_INV(C XOR y_r)
```

Como `alpha_expected = 0606` solo activa los nibbles 1 y 3, una única
característica recupera la clase parcial `?8?9`, representada de forma
canónica como `0809`. No permite deducir por sí sola los nibbles inactivos.

## Simplificación explícita de los oráculos

`O_2` no contiene una implementación reversible completa de `E_K`. Primero se
calcula clásicamente la lista de bits `RP(candidate, i)` y después se construye
un oráculo de fase que marca los índices correspondientes:

\[
O_2|j\rangle=(-1)^{e(x,j)}|j\rangle.
\]

`O_1` se construye de forma análoga sobre índices de una lista explícita
`K_cand`. Puede usar:

- `mode="exact"`: conteos clásicos `R(x)`;
- `mode="estimated"`: estimaciones de conteo cuántico.

Esta decisión reproduce el comportamiento lógico de los oráculos y hace
viable la simulación. No es una síntesis reversible optimizada ni una
implementación destinada a romper AES, KLEIN u otro cifrador real.

## Módulos

- `src/spn16.py`: `E_K`, calendario simple, S-box, permutación y última ronda.
- `src/classical_attack.py`: pares Q1, `RP(y_r,i)`, `R(y_r)` y búsqueda clásica.
- `src/oracles.py`: oráculos simulados `O_2` y `O_1`.
- `src/quantum_counting.py`: QPE sobre la iteración de Grover.
- `src/grover_search.py`: búsqueda de índices marcados.
- `src/durr_hoyer_max.py`: actualización iterativa de la subclave umbral `y`.
- `notebooks/qdiff_spn16_demo.ipynb`: demostración completa.

## Convención de conteo

Si hay `L` pares, el registro de índices usa un dominio acolchado
`N = 2^m >= L`; los índices añadidos no están marcados. Para `M=R(x)`:

\[
\sin^2(\theta)=M/N,
\qquad
\widetilde M=N\sin^2(\pi\widetilde\phi),
\]

donde la iteración de Grover tiene autofases
\(\exp(\pm 2i\theta)\) y QPE estima
\(\widetilde\phi\approx\theta/\pi\).

## Instalación

Desde la raíz del repositorio:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r quantum_differential_cryptanalysis\requirements.txt
```

## Pruebas

```powershell
python -m pytest quantum_differential_cryptanalysis\tests
```

## Notebook

```powershell
python -m jupyter lab quantum_differential_cryptanalysis\notebooks\qdiff_spn16_demo.ipynb
```

También puede abrirse con Jupyter Notebook o VS Code. El notebook usa
`Statevector`, por lo que no requiere hardware cuántico ni credenciales.

## Limitaciones

- La complejidad de construcción de los oráculos sigue siendo clásica.
- El simulador almacena el vector de estado completo.
- La lista `K_cand` se mantiene pequeña y puede codificar solo los nibbles
  activos.
- La rutina Dürr--Høyer es una demostración estructural con presupuesto fijo o
  `ceil(c*sqrt(|K_cand|))`, no una prueba de ventaja cuántica.
- La clave real se conoce únicamente para construir el experimento controlado
  y comparar el resultado final.

