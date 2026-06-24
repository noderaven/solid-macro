"""Tests for payload/aes.py. Pinned to NIST KAT vectors."""

import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from payload import aes  # noqa: E402


# NIST FIPS 197 Appendix C.3: AES-256 single-block KAT
FIPS197_KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
FIPS197_PT = bytes.fromhex("00112233445566778899aabbccddeeff")
FIPS197_CT = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")

# NIST SP 800-38A F.5.5: CTR-AES256 vectors (4 blocks)
SP38A_KEY = bytes.fromhex(
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
)
SP38A_NONCE = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
SP38A_PT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
SP38A_CT = bytes.fromhex(
    "601ec313775789a5b7a7f504bbf3d228"
    "f443e3ca4d62b59aca84e990cacaf5c5"
    "2b0930daa23de94ce87017ba2d84988d"
    "dfc9c58db67aada613c2dd08457941a6"
)


def test_fips197_block_kat():
    rks = aes.key_expansion_256(FIPS197_KEY)
    assert aes.encrypt_block(FIPS197_PT, rks) == FIPS197_CT


def test_sp800_38a_ctr_kat():
    assert aes.aes_256_ctr(SP38A_PT, SP38A_KEY, SP38A_NONCE) == SP38A_CT


def test_ctr_roundtrip_block_aligned():
    key, nonce = os.urandom(32), os.urandom(16)
    pt = os.urandom(48)
    ct = aes.aes_256_ctr(pt, key, nonce)
    assert ct != pt
    assert aes.aes_256_ctr(ct, key, nonce) == pt


def test_ctr_roundtrip_partial_final_block():
    key, nonce = os.urandom(32), os.urandom(16)
    pt = os.urandom(33)
    ct = aes.aes_256_ctr(pt, key, nonce)
    assert aes.aes_256_ctr(ct, key, nonce) == pt


def test_ctr_empty_input():
    key, nonce = os.urandom(32), os.urandom(16)
    assert aes.aes_256_ctr(b"", key, nonce) == b""


def test_key_length_validation():
    with pytest.raises(ValueError):
        aes.aes_256_ctr(b"data", b"\x00" * 16, b"\x00" * 16)


def test_nonce_length_validation():
    with pytest.raises(ValueError):
        aes.aes_256_ctr(b"data", b"\x00" * 32, b"\x00" * 8)


def test_counter_increments_correctly():
    """Encrypting one block at counter N should match the Nth slice of a long stream."""
    key = b"\x00" * 32
    base_nonce = bytes.fromhex("00000000000000000000000000000000")
    advanced_nonce = bytes.fromhex("00000000000000000000000000000003")
    block_at_3 = aes.aes_256_ctr(b"\x00" * 16, key, advanced_nonce)
    full_stream = aes.aes_256_ctr(b"\x00" * 64, key, base_nonce)
    assert block_at_3 == full_stream[48:64]
