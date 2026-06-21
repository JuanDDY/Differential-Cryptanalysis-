"""Pruebas del cifrador SPN16 autocontenido."""

from quantum_differential_cryptanalysis.src.spn16 import (
    INV_SBOX,
    SBOX,
    decrypt_last_round_partial,
    encrypt_block,
    encryption_trace,
    inverse_permute_bits,
    permute_bits,
    split_master_key,
)


def test_sbox_inverse() -> None:
    assert all(INV_SBOX[SBOX[value]] == value for value in range(16))


def test_permutation_inverse() -> None:
    for value in (0x0000, 0x0001, 0x1234, 0xBEEF, 0xFFFF):
        assert inverse_permute_bits(permute_bits(value)) == value


def test_encryption_is_deterministic_and_matches_vector() -> None:
    subkeys = split_master_key("00112233445566778899")
    assert subkeys == [0x0011, 0x2233, 0x4455, 0x6677, 0x8899]
    assert encrypt_block(0x002B, subkeys) == 0x3CE1
    assert encrypt_block(0x002B, subkeys) == encrypt_block(0x002B, subkeys)


def test_partial_last_round_decryption() -> None:
    subkeys = split_master_key("00112233445566778899")
    ciphertext = encrypt_block(0x002B, subkeys)
    partial = decrypt_last_round_partial(ciphertext, subkeys[-1])
    trace = dict(encryption_trace(0x002B, subkeys))
    assert partial == 0x61F7
    assert partial == trace["round_4_before_sbox"]

