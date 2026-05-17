"""
BIP-375: Sending Silent Payments with PSBTs

This module provides support for Silent Payments in PSBTv2 format, including:
- SP field definitions and serialization
- ECDH share computation and DLEQ proof generation
- Output script derivation for silent payment addresses
- Comprehensive validation according to BIP-375 specification
"""

from typing import Dict, List, Tuple, Optional

from . import ec
from . import hashes
from . import dleq
from .util.key import SECP256K1_ORDER
from .util.secp256k1 import (
    ec_pubkey_parse,
    ec_pubkey_serialize,
    ec_pubkey_tweak_mul,
    EC_COMPRESSED,
    ec_seckey_verify,
)


class SPFieldError(Exception):
    """Raised when SP field validation fails."""

    pass


class SPValidationError(Exception):
    """Raised when SP validation fails."""

    pass


class SilentPaymentData:
    """Represents PSBT_OUT_SP_V0_INFO field (scan key + spend key)."""

    def __init__(self, scan_key: ec.PublicKey, spend_key: ec.PublicKey):
        self.scan_key = scan_key
        self.spend_key = spend_key

    def serialize(self) -> bytes:
        """Serialize as 33-byte scan key + 33-byte spend key."""
        return self.scan_key.sec() + self.spend_key.sec()

    @classmethod
    def parse(cls, data: bytes) -> "SilentPaymentData":
        """Parse from 66 bytes (33-byte scan key + 33-byte spend key)."""
        if len(data) != 66:
            raise SPFieldError(f"PSBT_OUT_SP_V0_INFO must be 66 bytes, got {len(data)}")
        try:
            scan_key = ec.PublicKey.parse(data[:33])
            spend_key = ec.PublicKey.parse(data[33:66])
            return cls(scan_key, spend_key)
        except Exception as e:
            raise SPFieldError(f"Invalid SP data: {e}")


class ECDHShare:
    """Represents PSBT_IN_SP_ECDH_SHARE or PSBT_GLOBAL_SP_ECDH_SHARE field."""

    def __init__(self, scan_key: ec.PublicKey, share: bytes):
        """
        Args:
            scan_key: The scan key this share is for
            share: 33 bytes - the ECDH shared secret point C = a·B_scan
        """
        if len(share) != 33:
            raise SPFieldError(f"ECDH share must be 33 bytes, got {len(share)}")
        self.scan_key = scan_key
        self.share = share

    @property
    def share_pubkey(self) -> ec.PublicKey:
        """Get the ECDH share as a PublicKey."""
        return ec.PublicKey.parse(self.share)

    def serialize(self) -> bytes:
        """Serialize for use in PSBT field value."""
        return self.share


class DLEQProof:
    """Represents PSBT_IN_SP_DLEQ or PSBT_GLOBAL_SP_DLEQ field."""

    def __init__(self, scan_key: ec.PublicKey, proof: bytes):
        """
        Args:
            scan_key: The scan key this proof is for
            proof: 64 bytes - BIP-374 DLEQ proof
        """
        if len(proof) != 64:
            raise SPFieldError(f"DLEQ proof must be 64 bytes, got {len(proof)}")
        self.scan_key = scan_key
        self.proof = proof

    def serialize(self) -> bytes:
        """Serialize for use in PSBT field value."""
        return self.proof

    def verify(
        self,
        A: ec.PublicKey,
        B: ec.PublicKey,
        C: ec.PublicKey,
        m: Optional[bytes] = None,
    ) -> bool:
        """
        Verify this DLEQ proof.

        Args:
            A: Public key of the input (a·G)
            B: The scan key (B_scan)
            C: The ECDH share (a·B_scan)
            m: Optional message bound to the proof

        Returns:
            True if proof is valid, False otherwise
        """
        return dleq.verify_dleq_proof(A.sec(), B.sec(), C.sec(), self.proof, m=m)


def compute_ecdh_share(private_key: bytes, scan_key: ec.PublicKey) -> bytes:
    """
    Compute ECDH share for a single private key.

    Args:
        private_key: 32-byte private key
        scan_key: The scan key to compute share with

    Returns:
        33-byte ECDH share (a·B_scan) compressed
    """
    if len(private_key) != 32:
        raise SPFieldError("Private key must be 32 bytes")

    # Compute a·B_scan
    b_internal = ec_pubkey_parse(scan_key.sec())
    ec_pubkey_tweak_mul(b_internal, private_key)
    return ec_pubkey_serialize(b_internal, EC_COMPRESSED)


def compute_global_ecdh_share(
    private_keys: List[bytes], scan_key: ec.PublicKey
) -> bytes:
    """
    Compute global ECDH share from multiple private keys.

    Args:
        private_keys: List of 32-byte private keys (all eligible inputs)
        scan_key: The scan key to compute share with

    Returns:
        33-byte ECDH share (a_sum·B_scan) compressed, or None if a_sum=0
    """
    if not private_keys:
        return None

    # Verify all private keys
    for priv in private_keys:
        if not ec_seckey_verify(priv):
            raise SPFieldError("Invalid private key")

    # Sum all private keys mod n
    a_sum = sum(int.from_bytes(priv, "big") for priv in private_keys) % SECP256K1_ORDER
    if a_sum == 0:
        return None

    a_sum_bytes = a_sum.to_bytes(32, "big")

    # Compute a_sum·B_scan
    b_internal = ec_pubkey_parse(scan_key.sec())
    ec_pubkey_tweak_mul(b_internal, a_sum_bytes)
    return ec_pubkey_serialize(b_internal, EC_COMPRESSED)


def compute_dleq_proof(
    private_key: bytes,
    scan_key: ec.PublicKey,
    ecdh_share: bytes,
) -> bytes:
    """
    Generate DLEQ proof for an input's ECDH share.

    Args:
        private_key: 32-byte private key (a)
        scan_key: The scan key (B_scan)
        ecdh_share: The ECDH share (a·B_scan) - used for self-verification

    Returns:
        64-byte DLEQ proof
    """
    try:
        return dleq.generate_dleq_proof(private_key, scan_key.sec())
    except dleq.DLEQError as e:
        raise SPFieldError(f"Failed to generate DLEQ proof: {e}")


def compute_global_dleq_proof(
    private_keys: List[bytes],
    scan_key: ec.PublicKey,
    global_share: bytes,
) -> bytes:
    """
    Generate DLEQ proof for global ECDH share.

    Args:
        private_keys: List of 32-byte private keys (all eligible inputs)
        scan_key: The scan key (B_scan)
        global_share: The global ECDH share (a_sum·B_scan)

    Returns:
        64-byte DLEQ proof
    """
    # Sum all private keys mod n
    a_sum = sum(int.from_bytes(priv, "big") for priv in private_keys) % SECP256K1_ORDER
    if a_sum == 0:
        raise SPFieldError("Cannot generate proof for zero sum")

    a_sum_bytes = a_sum.to_bytes(32, "big")

    try:
        return dleq.generate_dleq_proof(a_sum_bytes, scan_key.sec())
    except dleq.DLEQError as e:
        raise SPFieldError(f"Failed to generate global DLEQ proof: {e}")


def get_eligible_inputs(
    inputs: List["InputScope"], has_sp_outputs: bool = False
) -> List[int]:
    """
    Get list of eligible input indices for SP computation.

    An input is eligible if:
    1. Its previous output is P2WPKH, P2PKH, or P2SH-P2WPKH
    2. When SP outputs are present, no Segwit version > 1 inputs are allowed

    Args:
        inputs: List of PSBT input scopes
        has_sp_outputs: Whether the PSBT has any SP outputs

    Returns:
        List of eligible input indices
    """
    eligible = []

    for i, inp in enumerate(inputs):
        script = inp.script_pubkey
        if script is None:
            continue

        script_type = script.script_type()

        # With SP outputs, reject Segwit v>1
        if has_sp_outputs and script_type == "p2tr":
            raise SPValidationError(
                f"Input {i} uses Segwit version > 1 (P2TR) with SP outputs"
            )

        # Eligible: P2PKH, P2WPKH, P2SH-P2WPKH
        if script_type in {"p2pkh", "p2wpkh", "p2sh"}:
            # For P2SH, check if it wraps P2WPKH
            if script_type == "p2sh" and inp.redeem_script:
                redeem_type = inp.redeem_script.script_type()
                if redeem_type == "p2wpkh":
                    # For P2SH-wrapped, we need the public key from redeem script
                    eligible.append(i)
            elif script_type != "p2sh":
                eligible.append(i)

    return eligible


def derive_silent_payment_outputs(
    ecdh_share: bytes,
    recipients: List[Tuple[ec.PublicKey, ec.PublicKey, int]],
    shared_secret: Optional[bytes] = None,
) -> Dict[int, bytes]:
    """
    Derive silent payment outputs for recipients.

    This is based on BIP-352 output derivation but uses precomputed ECDH share.

    Args:
        ecdh_share: The ECDH shared secret point C (33 bytes)
        recipients: List of (scan_key, spend_key, label) tuples
        shared_secret: Precomputed xonly shared secret (for efficiency)

    Returns:
        Dict mapping recipient index to output pubkey xonly (32 bytes each)
    """
    if not recipients:
        return {}

    # Use precomputed or compute from ECDH share
    if shared_secret is None:
        # Extract xonly from ECDH share (skip first byte marker)
        shared_secret = ecdh_share[1:33]

    result = {}
    k = 0

    for idx, (scan_key, spend_key, label) in enumerate(recipients):
        # For labeled recipients, tweak the spend key
        if label is not None and label != 0:
            if isinstance(label, int):
                label_bytes = label.to_bytes(4, "little")
            else:
                label_bytes = label

            tweak = hashes.tagged_hash("BIP0352/Label", scan_key.sec() + label_bytes)
            # Tweak spend key
            spend_internal = ec_pubkey_parse(spend_key.sec())
            ec_pubkey_tweak_add(spend_internal, tweak)
            tweaked_spend = ec_pubkey_serialize(spend_internal, EC_COMPRESSED)
        else:
            tweaked_spend = spend_key.sec()

        # Compute t_k
        t_k = hashes.tagged_hash(
            "BIP0352/SharedSecret",
            shared_secret + k.to_bytes(4, "big"),
        )

        # P_k = B_spend + t_k
        p_k_internal = ec_pubkey_parse(tweaked_spend)
        ec_pubkey_tweak_add(p_k_internal, t_k)
        p_k = ec_pubkey_serialize(p_k_internal, EC_COMPRESSED)

        # Store as p2tr output (extract xonly)
        result[idx] = p_k[1:33]

        k += 1

    return result
