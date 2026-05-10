"""
Tests for BIP-374: Discrete Logarithm Equality Proofs (DLEQ).

Tests cover:
  - generate_dleq_proof + verify_dleq_proof round-trip with random keys
  - Proof is deterministic given same aux randomness
  - Proof invalidation with wrong keys
  - Edge cases: invalid proof lengths, zero scalars
  - Message binding (m parameter)
"""

import os
from binascii import unhexlify
from unittest import TestCase

from embit.bip374 import generate_dleq_proof, verify_dleq_proof, DLEQError
from embit.util.secp256k1 import (
    ec_pubkey_create,
    ec_pubkey_serialize,
    ec_pubkey_parse,
    EC_COMPRESSED,
)
from embit.ec import PrivateKey


def _gen_key():
    """Generate a random valid private key as bytes."""
    while True:
        k = os.urandom(32)
        try:
            PrivateKey(k)
            return k
        except Exception:
            pass


def _pub_from_priv(priv_bytes: bytes) -> bytes:
    """Return 33-byte compressed pubkey for a private key."""
    internal = ec_pubkey_create(priv_bytes)
    return ec_pubkey_serialize(internal, EC_COMPRESSED)


def _ecdh(priv_bytes: bytes, pub_bytes: bytes) -> bytes:
    """Compute priv * pub, return 33-byte compressed result."""
    from embit.util.secp256k1 import ec_pubkey_tweak_mul

    internal = ec_pubkey_parse(pub_bytes)
    ec_pubkey_tweak_mul(internal, priv_bytes)
    return ec_pubkey_serialize(internal, EC_COMPRESSED)


class TestBIP374RoundTrip(TestCase):
    """Core property: generate then verify succeeds."""

    def test_basic_round_trip(self):
        a = _gen_key()
        B_priv = _gen_key()
        B = _pub_from_priv(B_priv)
        A = _pub_from_priv(a)
        C = _ecdh(a, B)

        proof = generate_dleq_proof(a, B)
        self.assertTrue(verify_dleq_proof(A, B, C, proof))

    def test_round_trip_multiple_keys(self):
        for _ in range(5):
            a = _gen_key()
            B_priv = _gen_key()
            B = _pub_from_priv(B_priv)
            A = _pub_from_priv(a)
            C = _ecdh(a, B)
            proof = generate_dleq_proof(a, B)
            self.assertTrue(verify_dleq_proof(A, B, C, proof))

    def test_deterministic_with_aux_rand(self):
        a = _gen_key()
        B = _pub_from_priv(_gen_key())
        r = os.urandom(32)
        proof1 = generate_dleq_proof(a, B, r=r)
        proof2 = generate_dleq_proof(a, B, r=r)
        self.assertEqual(proof1, proof2)

    def test_different_aux_rand_gives_different_proof(self):
        a = _gen_key()
        B = _pub_from_priv(_gen_key())
        proof1 = generate_dleq_proof(a, B, r=os.urandom(32))
        proof2 = generate_dleq_proof(a, B, r=os.urandom(32))
        # Proofs are almost certainly different (different r => different k)
        self.assertNotEqual(proof1, proof2)

    def test_with_message_binding(self):
        a = _gen_key()
        B = _pub_from_priv(_gen_key())
        A = _pub_from_priv(a)
        C = _ecdh(a, B)
        m = b"BIP-374 test message"
        proof = generate_dleq_proof(a, B, m=m)
        # Verify with correct m
        self.assertTrue(verify_dleq_proof(A, B, C, proof, m=m))
        # Verify fails with wrong m
        self.assertFalse(verify_dleq_proof(A, B, C, proof, m=b"wrong message"))
        # Verify fails with no m
        self.assertFalse(verify_dleq_proof(A, B, C, proof))

    def test_no_message_binding(self):
        a = _gen_key()
        B = _pub_from_priv(_gen_key())
        A = _pub_from_priv(a)
        C = _ecdh(a, B)
        proof = generate_dleq_proof(a, B)
        # Fails if m added during verification
        self.assertFalse(verify_dleq_proof(A, B, C, proof, m=b"extra"))


class TestBIP374Rejection(TestCase):
    """Verifier must reject tampered or invalid proofs."""

    def test_wrong_A_rejected(self):
        a = _gen_key()
        B = _pub_from_priv(_gen_key())
        C = _ecdh(a, B)
        proof = generate_dleq_proof(a, B)
        A_wrong = _pub_from_priv(_gen_key())
        self.assertFalse(verify_dleq_proof(A_wrong, B, C, proof))

    def test_wrong_B_rejected(self):
        a = _gen_key()
        B = _pub_from_priv(_gen_key())
        A = _pub_from_priv(a)
        C = _ecdh(a, B)
        proof = generate_dleq_proof(a, B)
        B_wrong = _pub_from_priv(_gen_key())
        self.assertFalse(verify_dleq_proof(A, B_wrong, C, proof))

    def test_wrong_C_rejected(self):
        a = _gen_key()
        B = _pub_from_priv(_gen_key())
        A = _pub_from_priv(a)
        proof = generate_dleq_proof(a, B)
        C_wrong = _pub_from_priv(_gen_key())
        self.assertFalse(verify_dleq_proof(A, B, C_wrong, proof))

    def test_flipped_bit_in_proof_rejected(self):
        a = _gen_key()
        B = _pub_from_priv(_gen_key())
        A = _pub_from_priv(a)
        C = _ecdh(a, B)
        proof = bytearray(generate_dleq_proof(a, B))
        proof[0] ^= 0x01  # flip a bit in e
        self.assertFalse(verify_dleq_proof(A, B, C, bytes(proof)))

    def test_wrong_proof_length_rejected(self):
        a = _gen_key()
        B = _pub_from_priv(_gen_key())
        A = _pub_from_priv(a)
        C = _ecdh(a, B)
        self.assertFalse(verify_dleq_proof(A, B, C, b"\x00" * 32))  # too short
        self.assertFalse(verify_dleq_proof(A, B, C, b"\x00" * 65))  # too long

    def test_swapped_A_C_rejected(self):
        """C = a*B ≠ B, so swapping A and C should fail."""
        a = _gen_key()
        B = _pub_from_priv(_gen_key())
        A = _pub_from_priv(a)
        C = _ecdh(a, B)
        proof = generate_dleq_proof(a, B)
        self.assertFalse(verify_dleq_proof(C, B, A, proof))

    def test_zero_proof_rejected(self):
        a = _gen_key()
        B = _pub_from_priv(_gen_key())
        A = _pub_from_priv(a)
        C = _ecdh(a, B)
        self.assertFalse(verify_dleq_proof(A, B, C, b"\x00" * 64))


class TestBIP374InputValidation(TestCase):
    """generate_dleq_proof should raise DLEQError on bad inputs."""

    def test_invalid_privkey_length(self):
        B = _pub_from_priv(_gen_key())
        with self.assertRaises(DLEQError):
            generate_dleq_proof(b"\x01" * 31, B)

    def test_invalid_B_length(self):
        a = _gen_key()
        with self.assertRaises(DLEQError):
            generate_dleq_proof(a, b"\x02" + b"\x01" * 31)  # 32 bytes not 33

    def test_invalid_r_length(self):
        a = _gen_key()
        B = _pub_from_priv(_gen_key())
        with self.assertRaises(DLEQError):
            generate_dleq_proof(a, B, r=b"\x00" * 16)


class TestBIP374DLEQAlgebra(TestCase):
    """
    Algebraic consistency: for keys a, b,
      A = a*G, B = b*G, C = a*B = a*b*G
    The proof proves log_G(A) == log_B(C), which equals a.
    """

    def test_commutativity(self):
        """a*B == b*A since both equal a*b*G."""
        a = _gen_key()
        b = _gen_key()
        A = _pub_from_priv(a)
        B = _pub_from_priv(b)
        C_ab = _ecdh(a, B)  # a * b*G
        C_ba = _ecdh(b, A)  # b * a*G
        # These should be equal
        self.assertEqual(C_ab, C_ba)

        # Proof with (a, B) should verify with (A, B, C_ab)
        proof = generate_dleq_proof(a, B)
        self.assertTrue(verify_dleq_proof(A, B, C_ab, proof))

        # But NOT with (A, B, C_ba) using proof from (b, A)
        # (because the proof was made for base B not A)
        proof_b = generate_dleq_proof(b, A)
        self.assertTrue(verify_dleq_proof(B, A, C_ba, proof_b))
        # Cross-check: proof_b should not verify with A,B,C_ab
        self.assertFalse(verify_dleq_proof(A, B, C_ab, proof_b))

    def test_same_dlog_different_bases(self):
        """Same secret, two different bases → two independent valid proofs."""
        a = _gen_key()
        B1 = _pub_from_priv(_gen_key())
        B2 = _pub_from_priv(_gen_key())
        A = _pub_from_priv(a)
        C1 = _ecdh(a, B1)
        C2 = _ecdh(a, B2)

        proof1 = generate_dleq_proof(a, B1)
        proof2 = generate_dleq_proof(a, B2)

        self.assertTrue(verify_dleq_proof(A, B1, C1, proof1))
        self.assertTrue(verify_dleq_proof(A, B2, C2, proof2))

        # Cross-base: proof1 should not verify with B2, C2
        self.assertFalse(verify_dleq_proof(A, B2, C2, proof1))
