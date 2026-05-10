"""
BIP-374: Discrete Log Equality Proofs (DLEQ).

Implements GenerateProof and VerifyProof as specified in BIP-374.

For given elliptic curve points A, B, C, G and scalar a where A = a*G and
C = a*B, the prover proves knowledge of a without revealing anything about a.

Reference: https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki
"""

import os

from . import hashes
from .util.key import SECP256K1_ORDER
from .util.secp256k1 import (
    ec_pubkey_create,
    ec_pubkey_parse,
    ec_pubkey_serialize,
    ec_pubkey_tweak_mul,
    ec_pubkey_combine,
    EC_COMPRESSED,
)


# Standard secp256k1 generator G in 33-byte compressed form (cbytes(G))
_G_COMPRESSED = bytes.fromhex(
    "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
)
DLEQ_TAG_AUX = "BIP0374/aux"
DLEQ_TAG_NONCE = "BIP0374/nonce"
DLEQ_TAG_CHALLENGE = "BIP0374/challenge"


class DLEQError(Exception):
    """Raised when DLEQ proof generation fails due to invalid inputs."""


def generate_dleq_proof(a_bytes, B_sec, r=None, m=None):
    """
    Generate a 64-byte DLEQ proof (BIP-374 GenerateProof).

    Proves log_G(A) == log_B(C) without revealing scalar a,
    where A = a*G and C = a*B.

    Args:
        a_bytes: 32-byte private key scalar.
        B_sec:   33-byte compressed pubkey (alternative base point B).
        r:       Optional 32-byte auxiliary randomness; generated securely if None.
        m:       Optional bytes message to bind into the proof.

    Returns:
        64-byte proof: bytes(32, e) || bytes(32, s).

    Raises:
        DLEQError: on invalid inputs or internal self-verification failure.
    """
    if len(a_bytes) != 32:
        raise DLEQError("a_bytes must be 32 bytes")
    if len(B_sec) != 33:
        raise DLEQError("B_sec must be a 33-byte compressed pubkey")

    n = SECP256K1_ORDER
    a_int = int.from_bytes(a_bytes, "big")
    if a_int == 0 or a_int >= n:
        raise DLEQError("a is out of range [1, n-1]")

    # A = a*G
    try:
        A_internal = ec_pubkey_create(a_bytes)
    except Exception as exc:
        raise DLEQError(f"ec_pubkey_create failed: {exc}")
    A_compressed = ec_pubkey_serialize(A_internal, EC_COMPRESSED)

    # C = a*B
    try:
        C_internal = ec_pubkey_parse(B_sec)
    except Exception as exc:
        raise DLEQError(f"Invalid B_sec: {exc}")
    try:
        ec_pubkey_tweak_mul(C_internal, a_bytes)
    except Exception as exc:
        raise DLEQError(f"ec_pubkey_tweak_mul failed: {exc}")
    C_compressed = ec_pubkey_serialize(C_internal, EC_COMPRESSED)

    # Aux-randomness masking: t = a XOR H_aux(r)
    if r is None:
        r = os.urandom(32)
    if len(r) != 32:
        raise DLEQError("r must be 32 bytes")

    aux_hash = hashes.tagged_hash(DLEQ_TAG_AUX, r)
    t_int = a_int ^ int.from_bytes(aux_hash, "big")
    t = t_int.to_bytes(32, "big")

    # m' = m if provided, else empty bytes
    m_prime = m if m is not None else b""

    # k = H_nonce(t || cbytes(A) || cbytes(C) || m') mod n
    rand = hashes.tagged_hash(DLEQ_TAG_NONCE, t + A_compressed + C_compressed + m_prime)
    k = int.from_bytes(rand, "big") % n
    if k == 0:
        raise DLEQError("Derived nonce k is zero")

    k_bytes = k.to_bytes(32, "big")

    # R1 = k*G
    R1_internal = ec_pubkey_create(k_bytes)
    R1_compressed = ec_pubkey_serialize(R1_internal, EC_COMPRESSED)

    # R2 = k*B
    R2_internal = ec_pubkey_parse(B_sec)
    ec_pubkey_tweak_mul(R2_internal, k_bytes)
    R2_compressed = ec_pubkey_serialize(R2_internal, EC_COMPRESSED)

    # e = int(H_challenge(A || B || C || G || R1 || R2 || m'))
    e_hash = hashes.tagged_hash(
        DLEQ_TAG_CHALLENGE,
        A_compressed
        + B_sec
        + C_compressed
        + _G_COMPRESSED
        + R1_compressed
        + R2_compressed
        + m_prime,
    )
    e = int.from_bytes(e_hash, "big")

    # s = (k + e*a) mod n
    s = (k + e * a_int) % n

    proof = e.to_bytes(32, "big") + s.to_bytes(32, "big")

    # Self-verify before returning (as required by spec)
    if not verify_dleq_proof(A_compressed, B_sec, C_compressed, proof, m=m):
        raise DLEQError("Self-verification of generated proof failed")

    return proof


def verify_dleq_proof(A_sec, B_sec, C_sec, proof, m=None):
    """
    Verify a 64-byte DLEQ proof (BIP-374 VerifyProof).

    Returns True if the proof is valid, False otherwise.
    Never raises exceptions — all failures return False.

    Args:
        A_sec:  33-byte compressed pubkey (a*G).
        B_sec:  33-byte compressed pubkey (alternative base point B).
        C_sec:  33-byte compressed pubkey (a*B, the ECDH result).
        proof:  64-byte proof bytes.
        m:      Optional message that was bound during generation.
    """
    if len(proof) != 64:
        return False

    n = SECP256K1_ORDER

    try:
        e = int.from_bytes(proof[:32], "big")
        s = int.from_bytes(proof[32:], "big")

        # s must be in [1, n-1]
        if s == 0 or s >= n:
            return False

        # neg_e = -e mod n  (used for point negation: -e*P)
        neg_e = (-e) % n
        if neg_e == 0:
            # e ≡ 0 mod n — can't happen with a valid proof
            return False

        m_prime = m if m is not None else b""
        s_bytes = s.to_bytes(32, "big")
        neg_e_bytes = neg_e.to_bytes(32, "big")

        # R1 = s*G - e*A  =  s*G + (-e)*A
        sG_internal = ec_pubkey_create(s_bytes)
        neg_eA_internal = ec_pubkey_parse(A_sec)
        ec_pubkey_tweak_mul(neg_eA_internal, neg_e_bytes)
        R1_internal = ec_pubkey_combine(sG_internal, neg_eA_internal)
        R1_compressed = ec_pubkey_serialize(R1_internal, EC_COMPRESSED)

        # R2 = s*B - e*C  =  s*B + (-e)*C
        sB_internal = ec_pubkey_parse(B_sec)
        ec_pubkey_tweak_mul(sB_internal, s_bytes)
        neg_eC_internal = ec_pubkey_parse(C_sec)
        ec_pubkey_tweak_mul(neg_eC_internal, neg_e_bytes)
        R2_internal = ec_pubkey_combine(sB_internal, neg_eC_internal)
        R2_compressed = ec_pubkey_serialize(R2_internal, EC_COMPRESSED)

        # Recompute e' = int(H_challenge(A || B || C || G || R1 || R2 || m'))
        e_check = int.from_bytes(
            hashes.tagged_hash(
                DLEQ_TAG_CHALLENGE,
                A_sec
                + B_sec
                + C_sec
                + _G_COMPRESSED
                + R1_compressed
                + R2_compressed
                + m_prime,
            ),
            "big",
        )

        return e == e_check

    except Exception:
        return False
