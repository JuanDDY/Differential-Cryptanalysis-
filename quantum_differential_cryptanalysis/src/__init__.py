"""API del prototipo Q1 de criptoanálisis diferencial cuántico."""

from .classical_attack import (
    CandidateScore,
    KnownPair,
    count_right_pairs,
    encrypt_pairs,
    exhaustive_key_search,
    generate_plaintext_pairs,
    right_pair,
)
from .durr_hoyer_max import DurrHoyerResult, durr_hoyer_max
from .quantum_counting import (
    QuantumCountingResult,
    quantum_count_marked,
    quantum_counting,
)
from .spn16 import (
    INV_SBOX,
    PBOX,
    PBOX_INV,
    SBOX,
    decrypt_last_round_partial,
    encrypt_block,
    split_master_key,
)
from .utils import format_partial_key

__all__ = [
    "CandidateScore",
    "DurrHoyerResult",
    "INV_SBOX",
    "KnownPair",
    "PBOX",
    "PBOX_INV",
    "QuantumCountingResult",
    "SBOX",
    "count_right_pairs",
    "decrypt_last_round_partial",
    "durr_hoyer_max",
    "encrypt_block",
    "encrypt_pairs",
    "exhaustive_key_search",
    "format_partial_key",
    "generate_plaintext_pairs",
    "quantum_count_marked",
    "quantum_counting",
    "right_pair",
    "split_master_key",
]
