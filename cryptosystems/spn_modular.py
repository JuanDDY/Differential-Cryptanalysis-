from __future__ import annotations

from dataclasses import dataclass
from math import ceil
from typing import List, Sequence


def _is_power_of_two(x: int) -> bool:
    return x > 0 and (x & (x - 1)) == 0


def _ilog2_power_of_two(x: int) -> int:
    if not _is_power_of_two(x):
        raise ValueError("value must be a power of two")
    return x.bit_length() - 1


@dataclass(frozen=True)
class SPNConfig:
    sbox: Sequence[int]
    permutation: Sequence[int]
    rounds: int
    block_bits: int


class ModularSPN:
    """
    SPN completamente modular.

    Estructura de rondas (r = rounds):
      - Rondas 1..r-1: XOR K_i -> S -> P
      - Ronda r:       XOR K_r -> S -> XOR K_{r+1}
    """

    def __init__(
        self,
        sbox: Sequence[int],
        permutation: Sequence[int],
        rounds: int,
        block_bits: int,
    ) -> None:
        self.config = SPNConfig(
            sbox=list(sbox),
            permutation=list(permutation),
            rounds=int(rounds),
            block_bits=int(block_bits),
        )
        self._validate()

        self.sbox: List[int] = list(self.config.sbox)
        self.permutation: List[int] = list(self.config.permutation)
        self.rounds: int = self.config.rounds
        self.block_bits: int = self.config.block_bits

        self.sbox_bits: int = _ilog2_power_of_two(len(self.sbox))
        self.sbox_mask: int = (1 << self.sbox_bits) - 1
        self.num_sboxes: int = self.block_bits // self.sbox_bits
        self.block_mask: int = (1 << self.block_bits) - 1
        self.hex_digits: int = ceil(self.block_bits / 4)

        self.sbox_inv: List[int] = [0] * len(self.sbox)
        for i, y in enumerate(self.sbox):
            self.sbox_inv[y] = i

        self.perm_inv: List[int] = [0] * self.block_bits
        for src, dst in enumerate(self.permutation):
            self.perm_inv[dst] = src

    def _validate(self) -> None:
        sbox = list(self.config.sbox)
        perm = list(self.config.permutation)
        rounds = self.config.rounds
        block_bits = self.config.block_bits

        if rounds < 1:
            raise ValueError("rounds must be >= 1")
        if block_bits < 1:
            raise ValueError("block_bits must be >= 1")

        if not _is_power_of_two(len(sbox)):
            raise ValueError("len(sbox) must be a power of two")

        sbox_bits = _ilog2_power_of_two(len(sbox))
        if block_bits % sbox_bits != 0:
            raise ValueError("block_bits must be divisible by sbox input size in bits")

        value_limit = 1 << sbox_bits
        seen = set()
        for v in sbox:
            if not isinstance(v, int):
                raise ValueError("sbox values must be integers")
            if not (0 <= v < value_limit):
                raise ValueError("sbox values out of range")
            if v in seen:
                raise ValueError("sbox must be bijective for decryption")
            seen.add(v)

        if len(perm) != block_bits:
            raise ValueError("permutation length must be exactly block_bits")
        perm_set = set(perm)
        expected = set(range(block_bits))
        if perm_set != expected:
            raise ValueError("permutation must be a bijection over [0..block_bits-1]")

    def required_subkeys(self) -> int:
        return self.rounds + 1

    def expand_key_from_hex(self, master_key_hex: str) -> List[int]:
        """
        Parte el master key en (rounds+1) subclaves de block_bits.
        """
        if self.block_bits % 4 != 0:
            raise ValueError("hex key expansion requires block_bits multiple of 4")

        chars_per_subkey = self.block_bits // 4
        need = self.required_subkeys() * chars_per_subkey
        key_text = master_key_hex.strip()
        if key_text.startswith("0x") or key_text.startswith("0X"):
            key_text = key_text[2:]
        if len(key_text) < need:
            raise ValueError(f"master_key_hex needs at least {need} hex chars")

        subkeys: List[int] = []
        for i in range(self.required_subkeys()):
            start = i * chars_per_subkey
            end = start + chars_per_subkey
            subkeys.append(int(key_text[start:end], 16))
        return subkeys

    def _check_subkeys(self, subkeys: Sequence[int]) -> None:
        if len(subkeys) != self.required_subkeys():
            raise ValueError(f"expected {self.required_subkeys()} subkeys")

    def _permute(self, x: int) -> int:
        y = 0
        for src, dst in enumerate(self.permutation):
            bit = (x >> (self.block_bits - 1 - src)) & 1
            y |= bit << (self.block_bits - 1 - dst)
        return y & self.block_mask

    def _inv_permute(self, x: int) -> int:
        y = 0
        for src, dst in enumerate(self.perm_inv):
            bit = (x >> (self.block_bits - 1 - src)) & 1
            y |= bit << (self.block_bits - 1 - dst)
        return y & self.block_mask

    def _sub_layer(self, x: int) -> int:
        y = 0
        for i in range(self.num_sboxes):
            shift = self.sbox_bits * (self.num_sboxes - 1 - i)
            in_val = (x >> shift) & self.sbox_mask
            y |= self.sbox[in_val] << shift
        return y & self.block_mask

    def _inv_sub_layer(self, x: int) -> int:
        y = 0
        for i in range(self.num_sboxes):
            shift = self.sbox_bits * (self.num_sboxes - 1 - i)
            in_val = (x >> shift) & self.sbox_mask
            y |= self.sbox_inv[in_val] << shift
        return y & self.block_mask

    def encrypt_block(self, plaintext: int, subkeys: Sequence[int]) -> int:
        self._check_subkeys(subkeys)

        x = plaintext & self.block_mask
        for i in range(self.rounds - 1):
            x ^= subkeys[i]
            x = self._sub_layer(x)
            x = self._permute(x)

        x ^= subkeys[self.rounds - 1]
        x = self._sub_layer(x)
        x ^= subkeys[self.rounds]
        return x & self.block_mask

    def decrypt_block(self, ciphertext: int, subkeys: Sequence[int]) -> int:
        self._check_subkeys(subkeys)

        x = ciphertext & self.block_mask
        x ^= subkeys[self.rounds]
        x = self._inv_sub_layer(x)
        x ^= subkeys[self.rounds - 1]

        for i in range(self.rounds - 2, -1, -1):
            x = self._inv_permute(x)
            x = self._inv_sub_layer(x)
            x ^= subkeys[i]

        return x & self.block_mask

    def encrypt_hex(self, plaintext_hex: str, master_key_hex: str) -> str:
        p = int(plaintext_hex, 16)
        subkeys = self.expand_key_from_hex(master_key_hex)
        c = self.encrypt_block(p, subkeys)
        return f"{c:0{self.hex_digits}X}"

    def decrypt_hex(self, ciphertext_hex: str, master_key_hex: str) -> str:
        c = int(ciphertext_hex, 16)
        subkeys = self.expand_key_from_hex(master_key_hex)
        p = self.decrypt_block(c, subkeys)
        return f"{p:0{self.hex_digits}X}"


if __name__ == "__main__":
    # Configuracion pedida por el usuario:
    # - S-box 4x4
    # - Permutacion 0-based de 16 bits
    # - 5 rondas (ultima ronda corta)
    sbox = [
        0xE, 0x4, 0xD, 0x1,
        0x2, 0xF, 0xB, 0x8,
        0x3, 0xA, 0x6, 0xC,
        0x5, 0x9, 0x0, 0x7,
    ]
    permutation = [
        0, 4, 8, 12,
        1, 5, 9, 13,
        2, 6, 10, 14,
        3, 7, 11, 15,
    ]

    cipher = ModularSPN(sbox=sbox, permutation=permutation, rounds=5, block_bits=16)
    key = "00112233445566778899AABB"
    pt = "1234"
    ct = cipher.encrypt_hex(pt, key)
    pt_back = cipher.decrypt_hex(ct, key)
    print(f"P={pt} -> C={ct} -> P'={pt_back}")
