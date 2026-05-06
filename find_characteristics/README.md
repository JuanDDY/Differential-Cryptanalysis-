# find_characteristics

Busqueda de diferenciales y caracteristicas diferenciales de alta probabilidad
para el SPN de 16 bits en `cryptosystems/spn16.py`.

## Script principal

- `spn16_characteristic_search.py`
- `menu_penultimate_characteristics.py`

## Que calcula

1. **Diferencial de probabilidad** `(DeltaX, DeltaY)`:
   probabilidad total de obtener `DeltaY` al cifrar pares con diferencia `DeltaX`.
2. **Caracteristica diferencial**:
   camino `Delta0 -> Delta1 -> ... -> Deltar` con probabilidad acumulada alta.

## Uso rapido

Desde la raiz del repo:

```powershell
python find_characteristics\spn16_characteristic_search.py --delta-in 0x0B00 --rounds 5 --top-k 10
```

Menu sencillo para elegir `SPN16`, `KLEIN` reducido o `AES` reducido y correr la busqueda hasta la penultima ronda:

```powershell
python find_characteristics\menu_penultimate_characteristics.py
```

Forzando una diferencia final:

```powershell
python find_characteristics\spn16_characteristic_search.py --delta-in 0x0B00 --rounds 5 --target-out 0x00A0 --top-k 10
```

Buscando hasta la penultima ronda (`r-1`), sin aplicar la ultima ronda corta:

```powershell
python find_characteristics\spn16_characteristic_search.py --delta-in 0x0B00 --rounds 5 --to-penultimate --top-k 10
```

Buscando automaticamente un `Delta_in` y `Delta_out` con caracteristica de alta probabilidad en `r-1` rondas:

```powershell
python find_characteristics\spn16_characteristic_search.py --rounds 5 --search-best --top-k 10 --max-initial-deltas 40
```

## Parametros utiles

### Parametros comunes

- `--rounds`: rondas totales del cifrador.
- `--top-k`: cantidad de caracteristicas a mostrar.
- `--beam-width`: ancho del beam search; si sube, explora mas caminos pero tarda mas.
- `--delta-in`: diferencia de entrada en hex. Si usas `--search-best`, no hace falta.
- `--target-out`: obliga a que la ultima diferencia buscada sea ese valor.
- `--search-best`: busca automaticamente un `Delta_in -> Delta_out` con probabilidad alta.

### Parametros de poda

- `--min-step-prob`: descarta transiciones con probabilidad demasiado baja.
- `--max-initial-deltas`: al usar `--search-best`, limita cuantos `Delta_in` candidatos se prueban.

### Solo SPN16

- `--to-penultimate`: busca sobre `r-1` rondas regulares, sin aplicar la ultima ronda corta.
- `--max-outputs-per-active-nibble`: limita salidas por nibble activo segun la DDT.

---

## AES/KLEIN reducidos (hasta penultima ronda)

Script:

- `reduced_characteristic_search.py`

Busca caracteristicas diferenciales de alta probabilidad desde `Delta_0`
hasta `Delta_(r-1)` (penultima ronda), para:

- `cryptosystems/reduced_aes.py`
- `cryptosystems/reduced_klein.py`

### Ejemplo KLEIN reducido

```powershell
python find_characteristics\reduced_characteristic_search.py `
  --cipher klein --rounds 6 --block-bits 32 --key-bits 64 `
  --delta-in 0x0000000F --top-k 10 --beam-width 1000
```

Busqueda automatica del mejor `Delta_in -> Delta_out` en `r-1` rondas:

```powershell
python find_characteristics\reduced_characteristic_search.py `
  --cipher klein --rounds 6 --block-bits 32 --key-bits 64 `
  --search-best --top-k 10 --max-initial-deltas 24
```

### Ejemplo AES reducido

```powershell
python find_characteristics\reduced_characteristic_search.py `
  --cipher aes --rounds 4 --block-bits 64 --key-bits 64 `
  --delta-in 0x0100000000000000 --top-k 10 --beam-width 1000 `
  --max-outputs-per-active-chunk 6
```

## Parametros de AES/KLEIN reducidos

- `--cipher`: elige `aes` o `klein`.
- `--block-bits`: tamano del bloque del cifrador reducido.
- `--key-bits`: tamano de la clave del cifrador reducido.
- `--max-outputs-per-active-chunk`: limita salidas por S-box activa; en AES el chunk es un byte, en KLEIN es un nibble.
- `--max-candidates-per-state`: limita cuantos candidatos intermedios se conservan por estado y ronda.
- `--max-initial-active-chunks`: al usar `--search-best`, limita cuantos chunks activos puede tener el `Delta_in` propuesto.
