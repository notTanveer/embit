"""
BIP-352: Silent Payments
see: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki
"""

from .. import bech32, ec
from ..util import secp256k1
from ..hashes import tagged_hash
from ..util.key import SECP256K1_ORDER
from ..util.secp256k1 import (
    ec_pubkey_serialize,
    ec_pubkey_parse,
    ec_pubkey_tweak_add,
    ec_privkey_negate,
    ec_pubkey_combine,
    ec_pubkey_create,
    ec_pubkey_tweak_mul,
    ec_seckey_verify,
    EC_COMPRESSED,
)
from .fields import SPFieldError

K_MAX = 2323

# ============================================================================
# Crypto Math Utilities
# ============================================================================

def _sum_privkeys(private_keys):
    """Sum private key scalars mod SECP256K1_ORDER (BIP-352 a_sum)."""
    return sum(int.from_bytes(priv, "big") for priv in private_keys) % SECP256K1_ORDER

def normalize_xonly_keys(input_privkeys):
    """
    Normalize (secret, is_xonly) pairs: negate odd-Y xonly keys.
    Returns list of 32-byte private key scalars ready for summation.
    """
    normalized = []
    for sec, is_xonly in input_privkeys:
        if not ec_seckey_verify(sec):
            raise ValueError("Invalid private key")
        if is_xonly:
            pub = ec_pubkey_create(sec)
            ser = ec_pubkey_serialize(pub)
            if ser[0] == 0x03:
                sec = ec_privkey_negate(sec)
        normalized.append(sec)
    return normalized

def _tweak_mul(point_sec, scalar):
    """Multiply a compressed point by a scalar, returning the compressed result."""
    point = bytearray(ec_pubkey_parse(point_sec))
    ec_pubkey_tweak_mul(point, scalar)
    return ec_pubkey_serialize(point, EC_COMPRESSED)

def sum_pubkeys(pubkeys):
    """Sum a non-empty list of public keys, returning a 33-byte compressed point."""
    acc = ec_pubkey_parse(pubkeys[0].sec())
    for pk in pubkeys[1:]:
        acc = ec_pubkey_combine(acc, ec_pubkey_parse(pk.sec()))
    return ec_pubkey_serialize(acc, EC_COMPRESSED)

# ============================================================================
# Core ECDH Computation
# ============================================================================

def compute_ecdh_share(private_key, scan_key):
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
    return _tweak_mul(scan_key.sec(), private_key)

def compute_global_ecdh_share(private_keys, scan_key):
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

    for priv in private_keys:
        if not ec_seckey_verify(priv):
            raise SPFieldError("Invalid private key")

    a_sum = _sum_privkeys(private_keys)
    if a_sum == 0:
        return None

    a_sum_bytes = a_sum.to_bytes(32, "big")
    return _tweak_mul(scan_key.sec(), a_sum_bytes)

# ============================================================================
# Address and Label Logic
# ============================================================================

def apply_label(spend_pubkey, scan_privkey, m):
    """
    BIP-352 label tweak: B_m = B_spend + tagged_hash("BIP0352/Label", scan_priv || ser32(m))·G
    """
    if not isinstance(m, int) or isinstance(m, bool):
        raise TypeError("Label must be an int.")
    if not 0 <= m <= 0xFFFFFFFF:
        raise ValueError("Label must be a 32-bit unsigned integer in [0, 2**32 - 1].")
    tweak = tagged_hash("BIP0352/Label", scan_privkey.secret + m.to_bytes(4, "big"))
    return ec.PublicKey(
        secp256k1.ec_pubkey_add(secp256k1.ec_pubkey_parse(spend_pubkey.sec()), tweak)
    )

def encode_silent_payment_address(
    scan_pubkey,
    spend_pubkey,
    network="main",
    version=0,
):
    """Bech32m-encode a BIP-352 Silent Payment address from its scan/spend public keys."""
    data = bech32.convertbits(scan_pubkey.sec() + spend_pubkey.sec(), 8, 5)
    hrp = "sp" if network == "main" else "tsp"
    return bech32.bech32_encode(bech32.Encoding.BECH32M, hrp, [version] + data)

def generate_silent_payment_address(
    scan_privkey,
    spend_pubkey,
    label=None,
    network="main",
    version=0,
):
    """
    Generates the recipient's reusable silent payment address.
    """
    scan_pubkey = scan_privkey.get_public_key()
    if label is not None:
        if not isinstance(label, int) or isinstance(label, bool):
            raise TypeError("Label must be an int.")
        if not 1 <= label <= 0xFFFFFFFF:
            raise ValueError(
                "Label must be a 32-bit unsigned integer in [1, 2**32 - 1]."
            )
        spend_pubkey = apply_label(spend_pubkey, scan_privkey, label)

    return encode_silent_payment_address(
        scan_pubkey, spend_pubkey, network=network, version=version
    )

def decode_silent_payment_address(address):
    """
    Decode a silent payment address and return the scan and spend public keys.
    """
    lowered = address.lower()
    if lowered.startswith("sp1"):
        hrp = "sp"
    elif lowered.startswith("tsp1"):
        hrp = "tsp"
    else:
        raise ValueError("Invalid silent payment address: unknown HRP")

    try:
        encoding, hrpgot, data = bech32.bech32_decode(address)
    except bech32.Bech32DecodeError as e:
        raise ValueError("Invalid silent payment address: {}".format(e))

    if hrpgot != hrp:
        raise ValueError("Invalid silent payment address: HRP mismatch")

    if encoding != bech32.Encoding.BECH32M:
        raise ValueError("Invalid silent payment address: must use bech32m encoding")

    if data[0] != 0:
        raise ValueError(
            "Invalid silent payment address: unsupported version {}".format(data[0])
        )

    try:
        decoded = bech32.convertbits(data[1:], 5, 8, False)
    except bech32.Bech32DecodeError:
        raise ValueError("Invalid silent payment address: conversion failed")

    try:
        B_scan = ec.PublicKey.parse(bytes(decoded[:33]))
        B_spend = ec.PublicKey.parse(bytes(decoded[33:]))
    except Exception as e:
        raise ValueError(
            "Invalid silent payment address: invalid public keys - {}".format(e)
        )

    return B_scan, B_spend

# ============================================================================
# Output Derivation
# ============================================================================

def get_input_hash(outpoints, sum_pubkey_bytes):
    """
    BIP-352 input_hash: tagged_hash("BIP0352/Inputs", lowest_outpoint || A)
    """
    if not outpoints:
        raise ValueError("get_input_hash requires at least one outpoint")
    lowest_outpoint = min(outpoints, key=lambda o: o.serialize())
    preimage = lowest_outpoint.serialize() + sum_pubkey_bytes
    return tagged_hash("BIP0352/Inputs", preimage)

def derive_silent_payment_outputs(ecdh_share, spend_keys):
    """
    Derive silent payment outputs for recipients from a precomputed ECDH share.
    """
    if not spend_keys:
        return {}

    if len(spend_keys) > K_MAX:
        raise ValueError(
            "Too many outputs for one scan key: {} > {}".format(
                len(spend_keys), K_MAX
            )
        )

    result = {}

    for k, spend_key in enumerate(spend_keys):
        t_k = tagged_hash(
            "BIP0352/SharedSecret",
            ecdh_share + k.to_bytes(4, "big"),
        )

        p_k_internal = bytearray(ec_pubkey_parse(spend_key.sec()))
        ec_pubkey_tweak_add(p_k_internal, t_k)
        p_k = ec_pubkey_serialize(p_k_internal, EC_COMPRESSED)

        result[k] = p_k[1:33]

    return result

def derive_outputs_for_keys(priv_keys, outpoints, scan_spend_groups):
    """
    Core output derivation from private keys.

    Args:
        priv_keys: List of 32-byte normalized private key scalars.
        outpoints: List of COutPoint for input_hash computation.
        scan_spend_groups: {scan_key_bytes: (scan_key, [spend_key, ...])}.

    Returns:
        (a_sum_bytes, {scan_key_bytes: (ecdh_share, {k: xonly_bytes})}),
        or None if the private key sum is zero.
    """
    for _scan_key, spend_keys in scan_spend_groups.values():
        if len(spend_keys) > K_MAX:
            raise ValueError(
                "Too many outputs for one scan key: {} > {}".format(
                    len(spend_keys), K_MAX
                )
            )

    a_sum = _sum_privkeys(priv_keys)
    if a_sum == 0:
        return None
        
    a_sum_bytes = a_sum.to_bytes(32, "big")
    A_sum_bytes = ec_pubkey_serialize(ec_pubkey_create(a_sum_bytes))
    input_hash = get_input_hash(outpoints, A_sum_bytes)

    results = {}
    for sk_bytes, (scan_key, spend_keys) in scan_spend_groups.items():
        ecdh_share = compute_ecdh_share(a_sum_bytes, scan_key)
        adjusted_share = _tweak_mul(ecdh_share, input_hash)
        outputs = derive_silent_payment_outputs(adjusted_share, spend_keys)
        results[sk_bytes] = (ecdh_share, outputs)

    return a_sum_bytes, results


