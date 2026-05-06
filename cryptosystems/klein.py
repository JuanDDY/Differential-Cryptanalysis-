from typing import List, Tuple

# --- KLEIN (family): KLEIN-64, KLEIN-80, KLEIN-96 ----------------------------
# Block size fixed: 64 bits.
# Rounds: 12 / 16 / 20 for key sizes 64 / 80 / 96.

BLOCK_BITS = 64
BLOCK_BYTES = 8

S_BOX = [
    0x7, 0x4, 0xA, 0x9,
    0x1, 0xF, 0xB, 0x0,
    0xC, 0x3, 0x2, 0x6,
    0x8, 0xE, 0xD, 0x5,
]

# Involutive S-box (its own inverse), but keep explicit for readability.
S_BOX_INV = [0] * 16
for i, v in enumerate(S_BOX):
    S_BOX_INV[v] = i

ROUNDS_BY_KEY_BITS = {
    64: 12,
    80: 16,
    96: 20,
}


def _mul(a: int, b: int) -> int:
    """GF(2^8) multiply with AES polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)."""
    p = 0
    x = a & 0xFF
    y = b & 0xFF
    for _ in range(8):
        if y & 1:
            p ^= x
        hi = x & 0x80
        x = (x << 1) & 0xFF
        if hi:
            x ^= 0x1B
        y >>= 1
    return p


def _xor_bytes(a: List[int], b: List[int]) -> List[int]:
    return [x ^ y for x, y in zip(a, b)]


def _sub_nibbles(state: List[int]) -> None:
    for i, byte in enumerate(state):
        hi = (byte >> 4) & 0xF
        lo = byte & 0xF
        state[i] = (S_BOX[hi] << 4) | S_BOX[lo]


def _inv_sub_nibbles(state: List[int]) -> None:
    for i, byte in enumerate(state):
        hi = (byte >> 4) & 0xF
        lo = byte & 0xF
        state[i] = (S_BOX_INV[hi] << 4) | S_BOX_INV[lo]


def _rotate_nibbles(state: List[int]) -> List[int]:
    # Rotate left by 2 bytes (4 nibbles).
    return state[2:] + state[:2]


def _inv_rotate_nibbles(state: List[int]) -> List[int]:
    return state[-2:] + state[:-2]


def _mix_columns_4bytes(col: List[int]) -> List[int]:
    a0, a1, a2, a3 = col
    return [
        _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3,
        a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3,
        a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3),
        _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2),
    ]


def _inv_mix_columns_4bytes(col: List[int]) -> List[int]:
    a0, a1, a2, a3 = col
    return [
        _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9),
        _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13),
        _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11),
        _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14),
    ]


def _mix_nibbles(state: List[int]) -> List[int]:
    # MixColumns-like operation applied to two 4-byte tuples.
    left = _mix_columns_4bytes(state[:4])
    right = _mix_columns_4bytes(state[4:])
    return left + right


def _inv_mix_nibbles(state: List[int]) -> List[int]:
    left = _inv_mix_columns_4bytes(state[:4])
    right = _inv_mix_columns_4bytes(state[4:])
    return left + right


def _substitute_byte_with_nibble_sbox(x: int) -> int:
    hi = (x >> 4) & 0xF
    lo = x & 0xF
    return ((S_BOX[hi] << 4) | S_BOX[lo]) & 0xFF


def _key_schedule_step(current_key: List[int], round_counter: int) -> List[int]:
    """
    KeySchedule for one step, valid for key sizes 64/80/96.
    Based on KLEIN paper, Section 3.2.4.
    """
    m = len(current_key)
    half = (m + 1) // 2  # ceil(m/2)
    a = current_key[:half]
    b = current_key[half:]

    # (b) cyclic left shift one byte in each tuple.
    a0 = a[1:] + a[:1]
    b0 = b[1:] + b[:1]

    # (c) Feistel-like swap.
    a1 = b0[:]  # left tuple
    b1 = _xor_bytes(a0, b0)  # right tuple

    # (d) XOR round counter with 3rd byte in left tuple.
    a1[2] ^= (round_counter & 0xFF)

    # Substitute 2nd and 3rd bytes in right tuple with KLEIN S-box (nibble-wise).
    b1[1] = _substitute_byte_with_nibble_sbox(b1[1])
    b1[2] = _substitute_byte_with_nibble_sbox(b1[2])

    return a1 + b1


def _normalize_key_hex(master_key_hex: str) -> str:
    text = master_key_hex.strip()
    if text.startswith("0x") or text.startswith("0X"):
        text = text[2:]
    return text.upper()


def _get_rounds_for_key_bits(key_bits: int) -> int:
    if key_bits not in ROUNDS_BY_KEY_BITS:
        raise ValueError("KLEIN supports only key sizes 64, 80, or 96 bits.")
    return ROUNDS_BY_KEY_BITS[key_bits]


def expand_round_keys_from_hex(master_key_hex: str) -> Tuple[List[int], int]:
    """
    Expand master key into round keys (64-bit each) and returns (round_keys, rounds).
    round_keys length is rounds + 1 (final whitening key included).
    """
    key_hex = _normalize_key_hex(master_key_hex)
    if len(key_hex) not in (16, 20, 24):
        raise ValueError("KLEIN key must be 16, 20, or 24 hex chars (64/80/96 bits).")

    key_bits = len(key_hex) * 4
    rounds = _get_rounds_for_key_bits(key_bits)
    key_state = list(bytes.fromhex(key_hex))

    round_keys: List[int] = []
    for i in range(1, rounds + 2):
        # Truncate leftmost 64 bits.
        rk_bytes = key_state[:BLOCK_BYTES]
        round_keys.append(int.from_bytes(bytes(rk_bytes), "big"))
        if i <= rounds:
            key_state = _key_schedule_step(key_state, i)

    return round_keys, rounds


def klein_encrypt_block(plain64: int, master_key_hex: str) -> int:
    round_keys, rounds = expand_round_keys_from_hex(master_key_hex)

    state = list((plain64 & ((1 << 64) - 1)).to_bytes(8, "big"))
    for i in range(rounds):
        rk = list(round_keys[i].to_bytes(8, "big"))
        state = _xor_bytes(state, rk)
        _sub_nibbles(state)
        state = _rotate_nibbles(state)
        state = _mix_nibbles(state)

    state = _xor_bytes(state, list(round_keys[rounds].to_bytes(8, "big")))
    return int.from_bytes(bytes(state), "big")


def klein_decrypt_block(cipher64: int, master_key_hex: str) -> int:
    round_keys, rounds = expand_round_keys_from_hex(master_key_hex)

    state = list((cipher64 & ((1 << 64) - 1)).to_bytes(8, "big"))
    state = _xor_bytes(state, list(round_keys[rounds].to_bytes(8, "big")))

    for i in range(rounds - 1, -1, -1):
        state = _inv_mix_nibbles(state)
        state = _inv_rotate_nibbles(state)
        _inv_sub_nibbles(state)
        rk = list(round_keys[i].to_bytes(8, "big"))
        state = _xor_bytes(state, rk)

    return int.from_bytes(bytes(state), "big")


def encrypt_hex(plain_hex: str, master_key_hex: str) -> str:
    if len(plain_hex) != 16:
        raise ValueError("KLEIN block size is exactly 16 hex chars (64 bits).")
    c = klein_encrypt_block(int(plain_hex, 16), master_key_hex)
    return f"{c:016X}"


def decrypt_hex(cipher_hex: str, master_key_hex: str) -> str:
    if len(cipher_hex) != 16:
        raise ValueError("KLEIN block size is exactly 16 hex chars (64 bits).")
    p = klein_decrypt_block(int(cipher_hex, 16), master_key_hex)
    return f"{p:016X}"


if __name__ == "__main__":
    # Vector from KLEIN paper (Appendix A, KLEIN-64)
    key = "0000000000000000"
    pt = "FFFFFFFFFFFFFFFF"
    ct = encrypt_hex(pt, key)
    pt_back = decrypt_hex(ct, key)

    print(f"K = {key}")
    print(f"P = {pt}")
    print(f"C = {ct}")
    print(f"P' = {pt_back}")
