"""
BIP-375 Silent Payment output derivation helper.
"""

from typing import Dict, List, Tuple, Optional

from .. import ec
from .. import hashes
from ..util.secp256k1 import (
    ec_pubkey_parse,
    ec_pubkey_serialize,
    ec_pubkey_tweak_add,
    EC_COMPRESSED,
)


def derive_silent_payment_outputs(
    ecdh_share: bytes,
    recipients: List[Tuple[ec.PublicKey, ec.PublicKey, int]],
    shared_secret: Optional[bytes] = None,
) -> Dict[int, bytes]:
    """
    Derive silent payment outputs for recipients.

    This is based on BIP-352 output derivation but uses a precomputed ECDH share.

    Args:
        ecdh_share: The ECDH shared secret point C (33 bytes)
        recipients: List of (scan_key, spend_key, label) tuples
        shared_secret: Precomputed xonly shared secret (for efficiency)

    Returns:
        Dict mapping recipient index to output pubkey xonly (32 bytes each)
    """
    if not recipients:
        return {}

    # Use precomputed or default to the full 33-byte compressed point (BIP-352 §1)
    if shared_secret is None:
        shared_secret = ecdh_share

    result = {}

    for k, (scan_key, spend_key, label) in enumerate(recipients):
        # For labeled recipients, tweak the spend key
        if label is not None and label != 0:
            if isinstance(label, int):
                label_bytes = label.to_bytes(4, "big")
            else:
                label_bytes = label

            tweak = hashes.tagged_hash("BIP0352/Label", scan_key.sec() + label_bytes)
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
        result[k] = p_k[1:33]

    return result
