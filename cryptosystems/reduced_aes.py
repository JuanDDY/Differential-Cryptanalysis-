from __future__ import annotations

from math import ceil
from typing import List, Sequence

from cryptosystems.aes import INV_S_BOX, S_BOX


def _mul(a: int, b: int) -> int:
    """Multiplicacion en GF(2^8) con polinomio irreducible 0x11B."""
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


def _xtime(x: int) -> int:
    x &= 0xFF
    return ((x << 1) ^ 0x1B) & 0xFF if (x & 0x80) else (x << 1) & 0xFF


class ReducedAES:
    """
    Variante reducida de AES/Rijndael para fines academicos.

    Parametros configurables:
      - rounds: numero de rondas
      - block_bits: tamano de bloque en bits (multiplo de 32, entre 32 y 128)
      - key_bits: tamano de clave en bits (multiplo de 32, entre 32 y 256)
    """

    def __init__(self, rounds: int, block_bits: int, key_bits: int) -> None:
        if rounds < 1:
            raise ValueError("rounds must be >= 1")
        if block_bits % 32 != 0 or not (32 <= block_bits <= 128):
            raise ValueError("block_bits must be a multiple of 32 and in [32, 128]")
        if key_bits % 32 != 0 or not (32 <= key_bits <= 256):
            raise ValueError("key_bits must be a multiple of 32 and in [32, 256]")

        self.rounds = int(rounds)
        self.block_bits = int(block_bits)
        self.key_bits = int(key_bits)

        self.nb = self.block_bits // 32  # columnas del estado
        self.nk = self.key_bits // 32  # palabras de clave
        self.block_bytes = self.block_bits // 8
        self.key_bytes = self.key_bits // 8
        self.block_mask = (1 << self.block_bits) - 1
        self.hex_digits = ceil(self.block_bits / 4)
        self.recommended_rounds = max(self.nb, self.nk) + 6

    def required_round_keys(self) -> int:
        return self.rounds + 1

    def _int_to_state(self, x: int) -> List[int]:
        return list((x & self.block_mask).to_bytes(self.block_bytes, "big"))

    def _state_to_int(self, state: Sequence[int]) -> int:
        return int.from_bytes(bytes(state), "big")

    def _add_round_key(self, state: List[int], round_key: Sequence[int]) -> None:
        for i in range(self.block_bytes):
            state[i] ^= int(round_key[i]) & 0xFF

    def _sub_bytes(self, state: List[int]) -> None:
        for i in range(self.block_bytes):
            state[i] = S_BOX[state[i]]

    def _inv_sub_bytes(self, state: List[int]) -> None:
        for i in range(self.block_bytes):
            state[i] = INV_S_BOX[state[i]]

    def _shift_rows(self, state: List[int]) -> None:
        tmp = state.copy()
        for r in range(4):
            row = [tmp[4 * c + r] for c in range(self.nb)]
            shift = r % self.nb
            row = row[shift:] + row[:shift]
            for c in range(self.nb):
                state[4 * c + r] = row[c]

    def _inv_shift_rows(self, state: List[int]) -> None:
        tmp = state.copy()
        for r in range(4):
            row = [tmp[4 * c + r] for c in range(self.nb)]
            shift = r % self.nb
            row = row[-shift:] + row[:-shift] if shift else row
            for c in range(self.nb):
                state[4 * c + r] = row[c]

    def _mix_columns(self, state: List[int]) -> None:
        for c in range(self.nb):
            i = 4 * c
            a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]
            state[i] = _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3
            state[i + 1] = a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3
            state[i + 2] = a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3)
            state[i + 3] = _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2)

    def _inv_mix_columns(self, state: List[int]) -> None:
        for c in range(self.nb):
            i = 4 * c
            a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]
            state[i] = _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9)
            state[i + 1] = _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13)
            state[i + 2] = _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11)
            state[i + 3] = _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14)

    def expand_key_from_hex(self, master_key_hex: str) -> List[int]:
        """
        Expande la clave a round keys del tamano del bloque.
        """
        key_hex = master_key_hex.strip()
        if key_hex.startswith("0x") or key_hex.startswith("0X"):
            key_hex = key_hex[2:]
        expected_chars = self.key_bytes * 2
        if len(key_hex) != expected_chars:
            raise ValueError(f"master_key_hex must have exactly {expected_chars} hex chars")

        key_bytes = list(bytes.fromhex(key_hex))
        words: List[List[int]] = [key_bytes[4 * i:4 * i + 4] for i in range(self.nk)]
        total_words = self.nb * (self.rounds + 1)

        rcon = 0x01
        for i in range(self.nk, total_words):
            temp = words[i - 1].copy()
            if i % self.nk == 0:
                temp = temp[1:] + temp[:1]
                temp = [S_BOX[x] for x in temp]
                temp[0] ^= rcon
                rcon = _xtime(rcon)
            elif self.nk > 6 and i % self.nk == 4:
                temp = [S_BOX[x] for x in temp]
            words.append([words[i - self.nk][j] ^ temp[j] for j in range(4)])

        round_keys: List[int] = []
        for r in range(self.rounds + 1):
            rk_bytes: List[int] = []
            for w in words[r * self.nb:(r + 1) * self.nb]:
                rk_bytes.extend(w)
            round_keys.append(int.from_bytes(bytes(rk_bytes), "big"))
        return round_keys

    def _check_round_keys(self, round_keys: Sequence[int]) -> None:
        if len(round_keys) != self.required_round_keys():
            raise ValueError(f"expected {self.required_round_keys()} round keys")

    def encrypt_block(self, plaintext: int, round_keys: Sequence[int]) -> int:
        self._check_round_keys(round_keys)

        state = self._int_to_state(plaintext)
        self._add_round_key(state, self._int_to_state(round_keys[0]))

        for r in range(1, self.rounds):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, self._int_to_state(round_keys[r]))

        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, self._int_to_state(round_keys[self.rounds]))
        return self._state_to_int(state) & self.block_mask

    def decrypt_block(self, ciphertext: int, round_keys: Sequence[int]) -> int:
        self._check_round_keys(round_keys)

        state = self._int_to_state(ciphertext)
        self._add_round_key(state, self._int_to_state(round_keys[self.rounds]))

        for r in range(self.rounds - 1, 0, -1):
            self._inv_shift_rows(state)
            self._inv_sub_bytes(state)
            self._add_round_key(state, self._int_to_state(round_keys[r]))
            self._inv_mix_columns(state)

        self._inv_shift_rows(state)
        self._inv_sub_bytes(state)
        self._add_round_key(state, self._int_to_state(round_keys[0]))
        return self._state_to_int(state) & self.block_mask

    def encrypt_hex(self, plaintext_hex: str, master_key_hex: str) -> str:
        expected_chars = self.hex_digits
        text = plaintext_hex.strip()
        if text.startswith("0x") or text.startswith("0X"):
            text = text[2:]
        if len(text) != expected_chars:
            raise ValueError(f"plaintext_hex must have exactly {expected_chars} hex chars")

        round_keys = self.expand_key_from_hex(master_key_hex)
        c = self.encrypt_block(int(text, 16), round_keys)
        return f"{c:0{self.hex_digits}X}"

    def decrypt_hex(self, ciphertext_hex: str, master_key_hex: str) -> str:
        expected_chars = self.hex_digits
        text = ciphertext_hex.strip()
        if text.startswith("0x") or text.startswith("0X"):
            text = text[2:]
        if len(text) != expected_chars:
            raise ValueError(f"ciphertext_hex must have exactly {expected_chars} hex chars")

        round_keys = self.expand_key_from_hex(master_key_hex)
        p = self.decrypt_block(int(text, 16), round_keys)
        return f"{p:0{self.hex_digits}X}"


if __name__ == "__main__":
    # Caso clasico AES-128
    aes_std = ReducedAES(rounds=10, block_bits=128, key_bits=128)
    k_std = "000102030405060708090A0B0C0D0E0F"
    p_std = "00112233445566778899AABBCCDDEEFF"
    c_std = aes_std.encrypt_hex(p_std, k_std)
    p_std_back = aes_std.decrypt_hex(c_std, k_std)
    print(f"[AES-128] P={p_std} -> C={c_std} -> P'={p_std_back}")

    # Caso reducido
    aes_red = ReducedAES(rounds=4, block_bits=64, key_bits=64)
    k_red = "0011223344556677"
    p_red = "89ABCDEF01234567"
    c_red = aes_red.encrypt_hex(p_red, k_red)
    p_red_back = aes_red.decrypt_hex(c_red, k_red)
    print(f"[AES reducido] P={p_red} -> C={c_red} -> P'={p_red_back}")
