from typing import List

# --- Parámetros del cifrador (SPN 16-bit) ---

# S-box (nibbles) dada: input -> output (hex)
S_BOX = [
    0xE, 0x4, 0xD, 0x1,
    0x2, 0xF, 0xB, 0x8,
    0x3, 0xA, 0x6, 0xC,
    0x5, 0x9, 0x0, 0x7
]

# Inversa de la S-box
S_BOX_INV = [0]*16
for i, v in enumerate(S_BOX):
    S_BOX_INV[v] = i

# Permutación de bits (1..16 -> 1..16). Índice 0 sin uso para comodidad 1-based.
PERM = [0,  1,5,9,13,  2,6,10,14,  3,7,11,15,  4,8,12,16]

# Utilidades de bits -----------------------------------------------------------

def _permute16(x: int) -> int:
    """Aplica la permutación PERM a un entero de 16 bits."""
    y = 0
    for i in range(1, 17):  # 1..16
        src_bit = (x >> (16 - i)) & 1
        dst_pos = PERM[i]            # 1..16
        y |= (src_bit << (16 - dst_pos))
    return y

def _sub_bytes16(x: int) -> int:
    """Aplica S_BOX nibble a nibble (4 nibbles en 16 bits)."""
    y = 0
    for shift in (12, 8, 4, 0):
        nib = (x >> shift) & 0xF
        y |= (S_BOX[nib] << shift)
    return y

def _inv_sub_bytes16(x: int) -> int:
    """Aplica S_BOX_INV nibble a nibble."""
    y = 0
    for shift in (12, 8, 4, 0):
        nib = (x >> shift) & 0xF
        y |= (S_BOX_INV[nib] << shift)
    return y

# Key schedule ----------------------------------------------------------------

def expand_key_from_hex(master_key_hex: str, r: int) -> List[int]:
    """
    Genera r+1 subclaves de 16 bits a partir de un master key en hex.
    Requisitos:
      - master_key_hex debe tener al menos 4*(r+1) hex chars.
    """
    need = (r + 1) * 4
    if len(master_key_hex) < need:
        raise ValueError(f"Se requieren al menos {need} hex chars para {r+1} subclaves de 16 bits.")
    subkeys = []
    for i in range(r + 1):
        k_hex = master_key_hex[4*i:4*(i+1)]
        subkeys.append(int(k_hex, 16))
    return subkeys  # [K1, K2, ..., K_{r+1}]

# Cifrado / Descifrado ---------------------------------------------------------

def spn_encrypt_block(plain16: int, subkeys: List[int], r: int) -> int:
    """
    Cifra un bloque de 16 bits con r rondas y r+1 subclaves (última es blanqueo final).
    Rondas 1..r-1: XOR K -> S-box -> Permutación
    Ronda r:       XOR K -> S-box -> XOR K_final
    """
    if len(subkeys) != r + 1:
        raise ValueError("Debe haber r+1 subclaves de 16 bits.")

    x = plain16 & 0xFFFF
    for i in range(r - 1):
        x ^= subkeys[i]
        x = _sub_bytes16(x)
        x = _permute16(x)

    x ^= subkeys[r - 1]
    x = _sub_bytes16(x)
    x ^= subkeys[r]  # whitening final
    return x & 0xFFFF

def spn_decrypt_block(cipher16: int, subkeys: List[int], r: int) -> int:
    """Descifra un bloque de 16 bits (inverso del de arriba)."""
    if len(subkeys) != r + 1:
        raise ValueError("Debe haber r+1 subclaves de 16 bits.")

    x = cipher16 & 0xFFFF
    x ^= subkeys[r]
    x = _inv_sub_bytes16(x)
    x ^= subkeys[r - 1]

    # Esta PERM es involutiva (su propia inversa), así que aplicamos _permute16 de nuevo
    for i in range(r - 2, -1, -1):
        x = _permute16(x)
        x = _inv_sub_bytes16(x)
        x ^= subkeys[i]

    return x & 0xFFFF

# Helpers cómodos --------------------------------------------------------------

def encrypt_hex(plain_hex: str, master_key_hex: str, r: int = 5) -> str:
    if len(plain_hex) != 4:
        raise ValueError("El bloque debe ser 16 bits (exactamente 4 hex chars).")
    Ks = expand_key_from_hex(master_key_hex, r)
    c = spn_encrypt_block(int(plain_hex, 16), Ks, r)
    return f"{c:04X}"

def decrypt_hex(cipher_hex: str, master_key_hex: str, r: int = 5) -> str:
    if len(cipher_hex) != 4:
        raise ValueError("El bloque debe ser 16 bits (exactamente 4 hex chars).")
    Ks = expand_key_from_hex(master_key_hex, r)
    p = spn_decrypt_block(int(cipher_hex, 16), Ks, r)
    return f"{p:04X}"

# --- Demo rápida ---
if __name__ == "__main__":
    r = 5
    master_key_hex = "00112233445566778899AABB"  # 6 subclaves de 16 bits
    PT = "1234"
    C = encrypt_hex(PT, master_key_hex, r=r)
    PT2 = decrypt_hex(C, master_key_hex, r=r)
    print(f"P = {PT}  ->  C = {C}  ->  P' = {PT2}")
