from __future__ import annotations

from math import ceil
from typing import List, Sequence

from cryptosystems.klein import S_BOX, S_BOX_INV


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


def _mix_columns_4bytes(col: Sequence[int]) -> List[int]:
    a0, a1, a2, a3 = [int(x) & 0xFF for x in col]
    return [
        _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3,
        a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3,
        a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3),
        _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2),
    ]


def _inv_mix_columns_4bytes(col: Sequence[int]) -> List[int]:
    a0, a1, a2, a3 = [int(x) & 0xFF for x in col]
    return [
        _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9),
        _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13),
        _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11),
        _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14),
    ]


class ReducedKLEIN:
    """
    Variante reducida de KLEIN para analisis experimental.

    Parametros:
      - rounds: numero de rondas
      - block_bits: tamano de bloque (32 o 64 bits)
      - key_bits: tamano de clave (multiplo de 16, >= block_bits y >= 48)

    Nota:
      - Para block_bits=64 y key_bits en {64,80,96}, con rounds clasicos
        (12,16,20), se comporta como KLEIN estandar.
      - Para block_bits=32, se aplica la misma estructura en una sola mitad.
    """

    def __init__(self, rounds: int, block_bits: int, key_bits: int) -> None:
        if rounds < 1:
            raise ValueError("rounds must be >= 1")
        if block_bits not in (32, 64):
            raise ValueError("block_bits must be 32 or 64")
        if key_bits % 16 != 0:
            raise ValueError("key_bits must be a multiple of 16")
        if key_bits < 48:
            raise ValueError("key_bits must be >= 48")
        if key_bits < block_bits:
            raise ValueError("key_bits must be >= block_bits")

        self.rounds = int(rounds)
        self.block_bits = int(block_bits)
        self.key_bits = int(key_bits)

        self.block_bytes = self.block_bits // 8
        self.key_bytes = self.key_bits // 8
        self.block_mask = (1 << self.block_bits) - 1
        self.hex_digits = ceil(self.block_bits / 4)

        self.rotate_bytes = max(1, self.block_bytes // 4)
        self.mix_groups = self.block_bytes // 4

    def required_round_keys(self) -> int:
        return self.rounds + 1

    def _int_to_state(self, x: int) -> List[int]:
        return list((x & self.block_mask).to_bytes(self.block_bytes, "big"))

    def _state_to_int(self, state: Sequence[int]) -> int:
        return int.from_bytes(bytes(state), "big")

    def _xor_state(self, a: Sequence[int], b: Sequence[int]) -> List[int]:
        return [(int(x) ^ int(y)) & 0xFF for x, y in zip(a, b)]

    def _sub_nibbles(self, state: List[int]) -> None:
        for i, byte in enumerate(state):
            hi = (byte >> 4) & 0xF
            lo = byte & 0xF
            state[i] = (S_BOX[hi] << 4) | S_BOX[lo]

    def _inv_sub_nibbles(self, state: List[int]) -> None:
        for i, byte in enumerate(state):
            hi = (byte >> 4) & 0xF
            lo = byte & 0xF
            state[i] = (S_BOX_INV[hi] << 4) | S_BOX_INV[lo]

    def _rotate(self, state: Sequence[int]) -> List[int]:
        return list(state[self.rotate_bytes:] + state[:self.rotate_bytes])

    def _inv_rotate(self, state: Sequence[int]) -> List[int]:
        return list(state[-self.rotate_bytes:] + state[:-self.rotate_bytes])

    def _mix(self, state: Sequence[int]) -> List[int]:
        out: List[int] = []
        for g in range(self.mix_groups):
            base = 4 * g
            out.extend(_mix_columns_4bytes(state[base:base + 4]))
        return out

    def _inv_mix(self, state: Sequence[int]) -> List[int]:
        out: List[int] = []
        for g in range(self.mix_groups):
            base = 4 * g
            out.extend(_inv_mix_columns_4bytes(state[base:base + 4]))
        return out

    def _substitute_byte_with_nibble_sbox(self, x: int) -> int:
        hi = (x >> 4) & 0xF
        lo = x & 0xF
        return ((S_BOX[hi] << 4) | S_BOX[lo]) & 0xFF

    def _key_schedule_step(self, current_key: Sequence[int], round_counter: int) -> List[int]:
        m = len(current_key)
        half = (m + 1) // 2
        left = list(current_key[:half])
        right = list(current_key[half:])

        if len(left) < 3 or len(right) < 3:
            raise ValueError("key_bits too small for this KLEIN-like schedule")

        left0 = left[1:] + left[:1]
        right0 = right[1:] + right[:1]

        left1 = right0[:]
        right1 = self._xor_state(left0, right0)

        left1[2] ^= (round_counter & 0xFF)
        right1[1] = self._substitute_byte_with_nibble_sbox(right1[1])
        right1[2] = self._substitute_byte_with_nibble_sbox(right1[2])
        return left1 + right1

    def expand_round_keys_from_hex(self, master_key_hex: str) -> List[int]:
        key_hex = master_key_hex.strip()
        if key_hex.startswith("0x") or key_hex.startswith("0X"):
            key_hex = key_hex[2:]
        expected_chars = self.key_bytes * 2
        if len(key_hex) != expected_chars:
            raise ValueError(f"master_key_hex must have exactly {expected_chars} hex chars")

        key_state = list(bytes.fromhex(key_hex))
        round_keys: List[int] = []
        for i in range(1, self.rounds + 2):
            rk_bytes = key_state[:self.block_bytes]
            round_keys.append(int.from_bytes(bytes(rk_bytes), "big"))
            if i <= self.rounds:
                key_state = self._key_schedule_step(key_state, i)
        return round_keys

    def _check_round_keys(self, round_keys: Sequence[int]) -> None:
        if len(round_keys) != self.required_round_keys():
            raise ValueError(f"expected {self.required_round_keys()} round keys")

    def encrypt_block(self, plaintext: int, round_keys: Sequence[int]) -> int:
        self._check_round_keys(round_keys)

        state = self._int_to_state(plaintext)
        for i in range(self.rounds):
            rk = self._int_to_state(round_keys[i])
            state = self._xor_state(state, rk)
            self._sub_nibbles(state)
            state = self._rotate(state)
            state = self._mix(state)

        state = self._xor_state(state, self._int_to_state(round_keys[self.rounds]))
        return self._state_to_int(state) & self.block_mask

    def decrypt_block(self, ciphertext: int, round_keys: Sequence[int]) -> int:
        self._check_round_keys(round_keys)

        state = self._int_to_state(ciphertext)
        state = self._xor_state(state, self._int_to_state(round_keys[self.rounds]))

        for i in range(self.rounds - 1, -1, -1):
            state = self._inv_mix(state)
            state = self._inv_rotate(state)
            self._inv_sub_nibbles(state)
            rk = self._int_to_state(round_keys[i])
            state = self._xor_state(state, rk)

        return self._state_to_int(state) & self.block_mask

    def encrypt_hex(self, plaintext_hex: str, master_key_hex: str) -> str:
        expected_chars = self.hex_digits
        text = plaintext_hex.strip()
        if text.startswith("0x") or text.startswith("0X"):
            text = text[2:]
        if len(text) != expected_chars:
            raise ValueError(f"plaintext_hex must have exactly {expected_chars} hex chars")

        round_keys = self.expand_round_keys_from_hex(master_key_hex)
        c = self.encrypt_block(int(text, 16), round_keys)
        return f"{c:0{self.hex_digits}X}"

    def decrypt_hex(self, ciphertext_hex: str, master_key_hex: str) -> str:
        expected_chars = self.hex_digits
        text = ciphertext_hex.strip()
        if text.startswith("0x") or text.startswith("0X"):
            text = text[2:]
        if len(text) != expected_chars:
            raise ValueError(f"ciphertext_hex must have exactly {expected_chars} hex chars")

        round_keys = self.expand_round_keys_from_hex(master_key_hex)
        p = self.decrypt_block(int(text, 16), round_keys)
        return f"{p:0{self.hex_digits}X}"


if __name__ == "__main__":
    # Caso KLEIN-64 clasico (12 rondas)
    k_std = ReducedKLEIN(rounds=12, block_bits=64, key_bits=64)
    key_std = "0000000000000000"
    pt_std = "FFFFFFFFFFFFFFFF"
    ct_std = k_std.encrypt_hex(pt_std, key_std)
    pt_std_back = k_std.decrypt_hex(ct_std, key_std)
    print(f"[KLEIN-64] P={pt_std} -> C={ct_std} -> P'={pt_std_back}")

    # Caso reducido (32 bits, menos rondas)
    k_red = ReducedKLEIN(rounds=6, block_bits=32, key_bits=64)
    key_red = "0011223344556677"
    pt_red = "89ABCDEF"
    ct_red = k_red.encrypt_hex(pt_red, key_red)
    pt_red_back = k_red.decrypt_hex(ct_red, key_red)
    print(f"[KLEIN reducido] P={pt_red} -> C={ct_red} -> P'={pt_red_back}")
