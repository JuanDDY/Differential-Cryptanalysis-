# differential_cryptoanalysis

Codigo para experimentos de criptoanalisis diferencial y recuperacion de subclaves.

## Estado actual

- `dc_key_recovery.py`: version simple y funcional para `cryptosystems/spn16.py`
- `aes_dc_key_recovery.py`: recuperacion de la ultima subclave para `ReducedAES`
- `klein_dc_key_recovery.py`: recuperacion parcial de la subclave final para `ReducedKLEIN`
- `test_dc_key_recovery.py`: test del ataque sobre `SPN16`
- `test_reduced_key_recovery.py`: tests de `AES reducido` y `KLEIN reducido`
- `spn16.py`: copia local antigua; la version activa usada por el ataque es `cryptosystems/spn16.py`

## Que hace `dc_key_recovery.py`

Recupera nibbles de la subclave final `K_(r+1)` del `SPN16` por conteo diferencial.

Flujo:

1. Se fija un `Delta_in`.
2. Se generan pares elegidos `(P, P ^ Delta_in)`.
3. Se cifran con un oraculo.
4. Se prueban candidatos de nibble de la subclave final.
5. Se puntua cada candidato comparando la diferencia esperada `Delta_u` a la entrada de la ultima S-box.

## Uso rapido

Ejecutar la demo:

```powershell
python differential_cryptoanalysis\dc_key_recovery.py
```

Ejecutar la demo de `AES reducido`:

```powershell
python differential_cryptoanalysis\aes_dc_key_recovery.py
```

Ejecutar la demo de `KLEIN reducido`:

```powershell
python differential_cryptoanalysis\klein_dc_key_recovery.py
```

Abrir el menu:

```powershell
python differential_cryptoanalysis\menu.py
```

Ejecutar el test:

```powershell
python -m unittest differential_cryptoanalysis\test_dc_key_recovery.py -v
python -m unittest differential_cryptoanalysis\test_reduced_key_recovery.py -v
```

## Uso desde codigo

```python
from differential_cryptoanalysis.dc_key_recovery import build_oracle, recover_last_whitening_subkey

oracle = build_oracle("00112233445566778899AABB", rounds=5)

partial_key, scores = recover_last_whitening_subkey(
    oracle_encrypt=oracle,
    delta_in=0x0B00,
    expected_delta_u_by_nibble={2: 0x5},
    n_pairs=4000,
    seed=2026,
    return_scores=True,
)

print(hex(partial_key))
print(scores[2][:5])
```

## Parametros importantes

- `delta_in`: diferencia de entrada elegida.
- `expected_delta_u_by_nibble`: diferencias esperadas a la entrada de la ultima S-box, por posicion de nibble.
- `n_pairs`: cantidad de pares elegidos; mas pares suele dar mejor senal.
- `seed`: semilla para reproducibilidad.

## Nota

`AES reducido` y `KLEIN reducido` usan demos con pares correctos sinteticos en la entrada de la ultima ronda.
Eso es intencional: con los trails usados aqui no es razonable obtener suficientes pares correctos desde texto plano por fuerza bruta.

Por ahora, el menu ejecuta:

- `SPN16`: demo funcional del ataque diferencial usual.
- `AES reducido`: demo funcional de recuperacion de `K_r`.
- `KLEIN reducido`: demo funcional de recuperacion parcial de `K_(r+1)`.
