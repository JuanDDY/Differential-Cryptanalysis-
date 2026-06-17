# Estructura del repositorio y guia para una version reducida

Este repositorio implementa cifradores de juguete/reducidos y herramientas de
criptoanalisis diferencial. La arquitectura se puede leer en capas:

1. `sboxes/`: modelo y carga de S-boxes.
2. `data/clasics/`: tablas de S-boxes en JSON o listas experimentales.
3. `cryptosystems/`: cifradores y variantes reducidas.
4. `evaluation/`: metricas de S-boxes, DDT, BCT, SAC, linealidad y Markov.
5. `find_characteristics/`: busqueda de caracteristicas diferenciales.
6. `differential_cryptoanalysis/`: ataques diferenciales y recuperacion de clave.
7. `DDTs/`: scripts/notebooks/resultados para tablas diferenciales.
8. `impossible_differential_cryptanalysis/`: stubs para diferencial imposible.

No copiar en una version reducida: `.venv/`, `.tmp/`, `__pycache__/`, archivos
CSV generados y notebooks grandes si no se necesitan para reproducir resultados.

## Raiz

| Archivo | Rol |
| --- | --- |
| `README.md` | Setup rapido, comandos de test y ejemplo de busqueda SPN16. |
| `requirements.txt` | Dependencias Python: `numpy`, `pandas`, `matplotlib`, `seaborn`, `tabulate`, `altair`, `plotnine`, `ipython`, `galois`. |
| `.gitignore` | Reglas de exclusion de git. |

Setup recomendado desde la raiz:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Comandos de humo:

```powershell
python -m unittest discover -s cryptosystems -p "test*.py" -v
python find_characteristics\spn16_characteristic_search.py --delta-in 0x0B00 --rounds 5 --top-k 10
python differential_cryptoanalysis\dc_key_recovery.py
python DDTs\ddt_ligero.py --sbox "[0xC,0x5,0x6,0xB,0x9,0x0,0xA,0xD,0x3,0xE,0xF,0x8,0x4,0x7,0x1,0x2]"
```

## `sboxes/`

Base comun para cargar y representar S-boxes.

| Archivo | Rol |
| --- | --- |
| `sbox.py` | Define `SBox(input_size, output_size, table, name)`. Es un contenedor simple. |
| `loader.py` | Carga JSON con esquema `{name,input_size,output_size,table}` y devuelve `SBox`. Convierte strings hexadecimales a enteros. |
| `__init__.py` | Exporta `SBox` para `from sboxes import SBox`. |

Notas para version reducida:

- Esencial si se usan `evaluation/*`, `DDTs/resumen_*.py` o JSON de `data/clasics`.
- `loader.py` espera una tabla plana de longitud `2^input_size`.

## `data/clasics/`

Datos de S-boxes. Los archivos validos para `sboxes.loader.load` deben tener
`name`, `input_size`, `output_size` y `table` plana.

| Archivo | Contenido/uso |
| --- | --- |
| `02_elefant.json` | S-box ELEFANT 4x4. |
| `03_GIFT-COFB.json` | S-box Grain/GIFT-COFB 4x4 segun metadata del archivo. |
| `06_PHOTON-Beetle.json` | S-box PHOTON-Beetle 4x4. |
| `07_Romulus.json` | S-box Romulus/SKINNY 8x8. |
| `aes.json` | S-box AES 8x8. Usada por resumenes y metricas. |
| `APN5.json` | S-box APN 5x5. |
| `ascon.json` | S-box ASCON 5x5. |
| `des.json` | S-box DES-S1 declarada 6x4, pero la tabla esta como matriz 4x16; no carga directamente con `loader.py` sin aplanarla/adaptarla. |
| `fides_5_AB.json` | S-box FIDES 5x5. |
| `fides_6_APN.json` | S-box FIDES 6x6. |
| `KLEIN.json` | S-box KLEIN 4x4. |
| `present.json` | S-box PRESENT 4x4. |
| `proof.json` | S-box PROOF 2x2. |
| `wage_SB.json` | S-box WAGE SB 7x7. |
| `wage_WGP.json` | S-box WAGE WGP 7x7. |
| `apn_5.json` | Lista de muchas S-boxes/candidatas 5-bit; no usa el esquema del loader. |
| `apn_6.json` | Lista de muchas S-boxes/candidatas 6-bit; no usa el esquema del loader. |

Para una version reducida de metricas, conservar solo `aes.json`,
`KLEIN.json`, `present.json` y `ascon.json`.

## `cryptosystems/`

Implementaciones de cifrado y pruebas. Es la capa que usan los ataques y la
busqueda de caracteristicas.

| Archivo | Rol |
| --- | --- |
| `spn16.py` | SPN de 16 bits con S-box 4x4, permutacion de bits, key schedule por trozos hex, cifrado/descifrado. Es el cifrador principal de juguete. |
| `spn_modular.py` | Clase `ModularSPN`: SPN parametrizable por S-box, permutacion, rondas y tamano de bloque. Se usa para ataques genericos. |
| `aes.py` | AES-128 clasico: S-box, inversa, key expansion, SubBytes, ShiftRows, MixColumns, cifrado/descifrado. |
| `klein.py` | KLEIN de bloque 64-bit con S-box nibble, rotacion, MixNibbles, key schedule y cifrado/descifrado. |
| `reduced_aes.py` | `ReducedAES(rounds, block_bits, key_bits)`: AES/Rijndael reducido con bloques 32..128 y claves 32..256. |
| `reduced_klein.py` | `ReducedKLEIN(rounds, block_bits, key_bits)`: KLEIN reducido de 32 o 64 bits. |
| `dc_key_recovery.py` | Recuperacion generica de subclave final para `ModularSPN`; genera pares elegidos y puntua candidatos con DDT. |
| `README_reduced.md` | Guia de uso de `ReducedAES` y `ReducedKLEIN`. |
| `test_aes.py` | Tests de AES. |
| `test_klein.py` | Tests de KLEIN. |
| `test_reduced_ciphers.py` | Tests de cifrado/descifrado de AES/KLEIN reducidos. |
| `test_spn_modular.py` | Tests de `ModularSPN`. |

Minimo para SPN16:

```text
cryptosystems/spn16.py
```

Minimo para ataques genericos:

```text
cryptosystems/spn16.py
cryptosystems/spn_modular.py
cryptosystems/dc_key_recovery.py
```

Minimo para AES/KLEIN reducidos:

```text
cryptosystems/aes.py
cryptosystems/klein.py
cryptosystems/reduced_aes.py
cryptosystems/reduced_klein.py
```

## `evaluation/`

Metricas y analisis de S-boxes.

| Archivo | Rol |
| --- | --- |
| `uniformity.py` | Construye DDT con `ddt(table,input_size,output_size)` y `get_ddt(sbox)`. |
| `linearity.py` | Calcula no linealidad con Walsh-Hadamard. |
| `avalanche_criterion.py` | Calcula SAC, matriz SAC y funciones de impresion/grafica. |
| `fixed_points.py` | Cuenta puntos fijos `S(x)=x`. La funcion se llama `fixed_ponts`. |
| `cost_function.py` | Funcion objetivo experimental basada en DDT, desviacion y uniformidad. |
| `boomerang.py` | Calcula BCT en Python para S-boxes biyectivas. |
| `boomerang.rs` | Version Rust experimental de BCT. No es necesaria para correr Python. |
| `identity_sbox.py` | S-box identidad para comparar metricas. |
| `sbox_metrics_analysis.py` | Orquesta metricas basicas y graficas de barras para varias S-boxes. |
| `markov.py` | Archivo vacio/placeholder. |
| `__init__.py` | Inicializador del paquete. |

### `evaluation/markov_chains/`

| Archivo | Rol |
| --- | --- |
| `basic_markov_chain.py` | `DifferentialMarkovChain`, matriz de transicion desde DDT, distancia TV, probabilidad maxima, mezcla, propiedades de cadena. |
| `ejecutar_tests.py` | Script de pruebas/metricas Markov para S-boxes. Tiene rutas antiguas a revisar antes de usar. |
| `delete.py` | Utilidades experimentales para traducir/generar S-boxes; no esencial. |
| `results.txt` | Resultado o notas generadas. |
| `__init__.py` | Inicializador. |

### `evaluation/graphics/`

| Archivo | Rol |
| --- | --- |
| `all_test_markov_chains.py` | Comparaciones Markov completas entre S-boxes; tablas y graficas. |
| `graphics_with_altair.py` | Graficas interactivas Altair para TV distance, max probability y mixing time. |
| `test_markov_chain.py` | Script de prueba Markov para una S-box. |

Minimo para calcular metricas en notebooks:

```text
evaluation/uniformity.py
evaluation/linearity.py
evaluation/avalanche_criterion.py
evaluation/fixed_points.py
evaluation/markov_chains/basic_markov_chain.py
sboxes/
```

## `DDTs/`

Herramientas y resultados de tablas diferenciales.

| Archivo | Rol |
| --- | --- |
| `ddt_ligero.py` | CLI simple para calcular DDT desde JSON o lista `--sbox`; puede imprimir tabla o CSV. |
| `calcular_ddt_sbox.ipynb` | Notebook simple para escribir una S-box como array, calcular DDT y metricas importando `evaluation/`. |
| `resumen_AES.py` | Script que carga `data/clasics/aes.json`, calcula DDT, SAC, puntos fijos, no linealidad y Markov, y guarda CSV. |
| `resumen_AES.ipynb` | Notebook equivalente para AES. |
| `resumen_KLEIN.py` | Script equivalente para `data/clasics/KLEIN.json`. |
| `resumen_KLEIN.ipynb` | Notebook equivalente para KLEIN. |
| `aes_ddt.csv`, `ddtAES.csv` | DDT de AES generada. Parecen duplicados. |
| `aes_metrics_summary.csv` | Resumen de metricas AES generado. |
| `klein_ddt.csv` | DDT de KLEIN generada. |
| `klein_metrics_summary.csv` | Resumen de metricas KLEIN generado. |
| `__init__.py` | Inicializador vacio. |

Para version reducida, conservar `ddt_ligero.py` y, si se quieren notebooks,
`calcular_ddt_sbox.ipynb`. Los CSV se regeneran.

Nota de imports en notebooks: si el notebook esta dentro de `DDTs/`, agregar la
raiz del repo a `sys.path` antes de importar `evaluation` o `sboxes`:

```python
from pathlib import Path
import sys

for path in [Path.cwd().resolve(), *Path.cwd().resolve().parents]:
    if (path / "evaluation").is_dir() and (path / "sboxes").is_dir():
        sys.path.insert(0, str(path))
        break
```

## `find_characteristics/`

Busqueda de diferenciales y caracteristicas de alta probabilidad.

| Archivo | Rol |
| --- | --- |
| `spn16_characteristic_search.py` | Script principal para SPN16: DDT, distribucion diferencial exacta, beam search de caracteristicas, busqueda hasta penultima ronda. |
| `reduced_characteristic_search.py` | Beam search para `ReducedAES` y `ReducedKLEIN` hasta penultima ronda. |
| `menu_penultimate_characteristics.py` | Menu interactivo para correr busquedas sobre SPN16, AES reducido o KLEIN reducido. |
| `test_spn16_characteristic_search.py` | Tests de la busqueda SPN16. |
| `test_reduced_characteristic_search.py` | Tests de la busqueda en cifradores reducidos. |
| `README.md` | Guia de parametros y comandos. |

Minimo para SPN16:

```text
find_characteristics/spn16_characteristic_search.py
cryptosystems/spn16.py
```

Minimo para AES/KLEIN reducidos:

```text
find_characteristics/reduced_characteristic_search.py
cryptosystems/aes.py
cryptosystems/klein.py
cryptosystems/reduced_aes.py
cryptosystems/reduced_klein.py
```

## `differential_cryptoanalysis/`

Ataques diferenciales y demos de recuperacion de subclaves.

| Archivo | Rol |
| --- | --- |
| `dc_key_recovery.py` | Ataque diferencial funcional a SPN16: genera pares elegidos, cifra con oraculo y recupera nibbles de la subclave final por conteo. |
| `aes_dc_key_recovery.py` | Recuperacion de ultima subclave en AES reducido usando pares correctos sinteticos en la entrada de la ultima ronda. |
| `klein_dc_key_recovery.py` | Recuperacion parcial de whitening final transformado para KLEIN reducido usando pares correctos sinteticos. |
| `menu.py` | Menu para ejecutar demos SPN16, AES reducido y KLEIN reducido. |
| `spn16.py` | Copia local antigua de SPN16. El README indica que la version activa para ataques es `cryptosystems/spn16.py`, pero notebooks locales pueden importar esta copia. |
| `spn16_pair_last_round_demo.ipynb` | Notebook para trazar pares SPN16, ver diferencias por fase y deshacer la ultima ronda con subclaves candidatas. |
| `table.md` | DDT en Markdown para la S-box 4x4 usada en SPN16. |
| `test_dc_key_recovery.py` | Test del ataque SPN16. |
| `test_reduced_key_recovery.py` | Tests de recuperacion en AES/KLEIN reducidos. |
| `README.md` | Descripcion del flujo de ataques y comandos. |

Minimo para ataque SPN16:

```text
differential_cryptoanalysis/dc_key_recovery.py
cryptosystems/spn16.py
```

Minimo para menu completo:

```text
differential_cryptoanalysis/menu.py
differential_cryptoanalysis/dc_key_recovery.py
differential_cryptoanalysis/aes_dc_key_recovery.py
differential_cryptoanalysis/klein_dc_key_recovery.py
cryptosystems/
```

## `impossible_differential_cryptanalysis/`

Estructura preparada para criptoanalisis diferencial imposible. Actualmente son
stubs, no implementaciones completas.

| Archivo | Rol |
| --- | --- |
| `spn16_impossible_dc.py` | Punto de entrada pendiente para SPN16. |
| `aes_impossible_dc.py` | Punto de entrada pendiente para AES. |
| `klein_impossible_dc.py` | Punto de entrada pendiente para KLEIN. |
| `menu.py` | Menu que llama a los stubs. |
| `README.md` | Explica el objetivo y estado pendiente. |

Para una version reducida ejecutable, esta carpeta puede omitirse sin romper el
flujo diferencial clasico.

## Perfiles de version reducida recomendados

### Perfil A: SPN16 minimo para busqueda y ataque

Conserva:

```text
requirements.txt
README.md
cryptosystems/spn16.py
find_characteristics/spn16_characteristic_search.py
differential_cryptoanalysis/dc_key_recovery.py
differential_cryptoanalysis/table.md
```

Opcional:

```text
cryptosystems/test_aes.py              # no necesario para SPN16
find_characteristics/test_spn16_characteristic_search.py
differential_cryptoanalysis/test_dc_key_recovery.py
differential_cryptoanalysis/spn16_pair_last_round_demo.ipynb
```

Comandos:

```powershell
python find_characteristics\spn16_characteristic_search.py --delta-in 0x0B00 --rounds 5 --top-k 10
python differential_cryptoanalysis\dc_key_recovery.py
```

### Perfil B: S-box metrics + DDT

Conserva:

```text
requirements.txt
sboxes/
data/clasics/aes.json
data/clasics/KLEIN.json
data/clasics/present.json
data/clasics/ascon.json
evaluation/uniformity.py
evaluation/linearity.py
evaluation/avalanche_criterion.py
evaluation/fixed_points.py
evaluation/sbox_metrics_analysis.py
evaluation/markov_chains/basic_markov_chain.py
DDTs/ddt_ligero.py
DDTs/calcular_ddt_sbox.ipynb
```

Comandos:

```powershell
python DDTs\ddt_ligero.py --file data\clasics\KLEIN.json
```

### Perfil C: AES/KLEIN reducidos + ataques

Conserva:

```text
requirements.txt
cryptosystems/aes.py
cryptosystems/klein.py
cryptosystems/reduced_aes.py
cryptosystems/reduced_klein.py
find_characteristics/reduced_characteristic_search.py
differential_cryptoanalysis/aes_dc_key_recovery.py
differential_cryptoanalysis/klein_dc_key_recovery.py
```

Comandos:

```powershell
python find_characteristics\reduced_characteristic_search.py --cipher klein --rounds 6 --block-bits 32 --key-bits 64 --delta-in 0x0000000F --top-k 10
python differential_cryptoanalysis\aes_dc_key_recovery.py
python differential_cryptoanalysis\klein_dc_key_recovery.py
```

### Perfil D: repo reducido pero completo para Codex

Conserva:

```text
requirements.txt
README.md
REPO_STRUCTURE_REDUCED.md
sboxes/
data/clasics/aes.json
data/clasics/KLEIN.json
data/clasics/present.json
data/clasics/ascon.json
cryptosystems/
evaluation/uniformity.py
evaluation/linearity.py
evaluation/avalanche_criterion.py
evaluation/fixed_points.py
evaluation/cost_function.py
evaluation/boomerang.py
evaluation/sbox_metrics_analysis.py
evaluation/markov_chains/basic_markov_chain.py
find_characteristics/
differential_cryptoanalysis/
DDTs/ddt_ligero.py
DDTs/calcular_ddt_sbox.ipynb
```

Omite:

```text
.venv/
.tmp/
**/__pycache__/
DDTs/*.csv
DDTs/resumen_AES.ipynb
DDTs/resumen_KLEIN.ipynb
evaluation/graphics/
evaluation/boomerang.rs
evaluation/markov.py
evaluation/markov_chains/delete.py
evaluation/markov_chains/results.txt
impossible_differential_cryptanalysis/
data/clasics/apn_5.json
data/clasics/apn_6.json
data/clasics/des.json
```

## Dependencias internas importantes

- `sboxes.loader` depende de `sboxes.SBox` y `numpy`.
- `evaluation.uniformity`, `linearity`, `avalanche_criterion`,
  `fixed_points` esperan objetos tipo `SBox`.
- `evaluation.markov_chains.basic_markov_chain` depende de
  `evaluation.uniformity`.
- `DDTs/resumen_*.py` dependen de `sboxes`, `evaluation`, `numpy`, `pandas`,
  `seaborn`, `matplotlib`.
- `find_characteristics/spn16_characteristic_search.py` depende de
  `cryptosystems.spn16`.
- `find_characteristics/reduced_characteristic_search.py` depende de
  `cryptosystems.reduced_aes` y `cryptosystems.reduced_klein`.
- `differential_cryptoanalysis/dc_key_recovery.py` usa `cryptosystems.spn16`.
- `differential_cryptoanalysis/aes_dc_key_recovery.py` usa
  `cryptosystems.reduced_aes` y `cryptosystems.aes.INV_S_BOX`.
- `differential_cryptoanalysis/klein_dc_key_recovery.py` usa
  `cryptosystems.reduced_klein` y `cryptosystems.klein.S_BOX_INV`.

## Reglas practicas para otra instancia de Codex

1. Ejecutar comandos desde la raiz del repo para que los imports funcionen.
2. Si se trabaja desde notebooks dentro de subcarpetas, insertar la raiz del repo
   en `sys.path`.
3. No asumir que todo JSON en `data/clasics/` carga con `sboxes.loader`; validar
   primero el esquema.
4. Tratar `differential_cryptoanalysis/spn16.py` como copia legacy; preferir
   `cryptosystems/spn16.py` en scripts nuevos.
5. Los CSV y notebooks de resumen son resultados/demos, no fuente canonica.
6. Los ataques AES/KLEIN reducidos usan pares correctos sinteticos para aislar la
   recuperacion de clave; no prueban encontrar esos pares desde texto plano.
