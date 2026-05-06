# Cifradores Reducidos (AES y KLEIN)

Este directorio incluye dos clases para experimentar con versiones reducidas:

- `ReducedAES` en `reduced_aes.py`
- `ReducedKLEIN` en `reduced_klein.py`

> Uso academico/experimental. No usar en produccion.

## 1) ReducedAES

Clase: `ReducedAES(rounds, block_bits, key_bits)`

- `rounds`: numero de rondas (>= 1).
- `block_bits`: tamano de bloque (multiplo de 32, entre 32 y 128).
- `key_bits`: tamano de clave (multiplo de 32, entre 32 y 256).

### Cifrar y descifrar (caso AES-128 clasico)

```python
from cryptosystems.reduced_aes import ReducedAES

cipher = ReducedAES(rounds=10, block_bits=128, key_bits=128)
key = "000102030405060708090A0B0C0D0E0F"
pt = "00112233445566778899AABBCCDDEEFF"

ct = cipher.encrypt_hex(pt, key)
pt_back = cipher.decrypt_hex(ct, key)
print(ct, pt_back)
```

### Cifrar y descifrar (caso reducido)

```python
from cryptosystems.reduced_aes import ReducedAES

cipher = ReducedAES(rounds=4, block_bits=64, key_bits=64)
key = "0011223344556677"
pt = "89ABCDEF01234567"

ct = cipher.encrypt_hex(pt, key)
pt_back = cipher.decrypt_hex(ct, key)
print(ct, pt_back)
```

## 2) ReducedKLEIN

Clase: `ReducedKLEIN(rounds, block_bits, key_bits)`

- `rounds`: numero de rondas (>= 1).
- `block_bits`: tamano de bloque (32 o 64).
- `key_bits`: tamano de clave (multiplo de 16, >= 48 y >= `block_bits`).

### Cifrar y descifrar (caso KLEIN-64 clasico)

```python
from cryptosystems.reduced_klein import ReducedKLEIN

cipher = ReducedKLEIN(rounds=12, block_bits=64, key_bits=64)
key = "0000000000000000"
pt = "FFFFFFFFFFFFFFFF"

ct = cipher.encrypt_hex(pt, key)
pt_back = cipher.decrypt_hex(ct, key)
print(ct, pt_back)
```

### Cifrar y descifrar (caso reducido)

```python
from cryptosystems.reduced_klein import ReducedKLEIN

cipher = ReducedKLEIN(rounds=6, block_bits=32, key_bits=64)
key = "0011223344556677"
pt = "89ABCDEF"

ct = cipher.encrypt_hex(pt, key)
pt_back = cipher.decrypt_hex(ct, key)
print(ct, pt_back)
```

## Tests

```powershell
python -m unittest cryptosystems\test_reduced_ciphers.py -v
```
