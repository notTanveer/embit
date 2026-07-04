"""
BIP-352: Silent Payments
see: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki
"""

from .. import bech32, ec
from ..util import secp256k1
from ..hashes import tagged_hash
from ..util.secp256k1 import (
    ec_pubkey_serialize,
    ec_pubkey_parse,
    ec_pubkey_tweak_add,
    EC_COMPRESSED,
)

K_MAX = 2323


def apply_label(spend_pubkey: ec.PublicKey, scan_privkey: ec.PrivateKey, m: int) -> ec.PublicKey:
    """
    BIP-352 label tweak: B_m = B_spend + tagged_hash("BIP0352/Label", scan_priv || ser32(m))·G

    `m` is a 32-bit unsigned integer. `m = 0` is reserved for change; callers
    that expose labels to users (e.g. address generation) should reject it
    themselves — this primitive allows it since change derivation needs it.
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
    scan_pubkey: ec.PublicKey,
    spend_pubkey: ec.PublicKey,
    network: str = "main",
    version: int = 0,
) -> str:
    """Bech32m-encode a BIP-352 Silent Payment address from its scan/spend public keys."""
    data = bech32.convertbits(scan_pubkey.sec() + spend_pubkey.sec(), 8, 5)
    hrp = "sp" if network == "main" else "tsp"
    return bech32.bech32_encode(bech32.Encoding.BECH32M, hrp, [version] + data)


def generate_silent_payment_address(
    scan_privkey: ec.PrivateKey,
    spend_pubkey: ec.PublicKey,
    label=None,
    network: str = "main",
    version: int = 0,
) -> str:
    """
    Adapted from https://github.com/bitcoin/bips/blob/master/bip-0352/reference.py

    Generates the recipient's reusable silent payment address for a given:
        * scan private key
        * spend public key
        * optional label for labeled addresses. It must be a 32-bit unsigned
          integer `m`; `m = 0` is reserved for change and cannot be used here.
    """
    scan_pubkey = scan_privkey.get_public_key()
    if label is not None:
        # Labels are 32-bit unsigned ints; m = 0 is reserved for change. See
        # https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki#address-encoding
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


def decode_silent_payment_address(address: str):
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


def get_input_hash(outpoints, sum_pubkey_bytes: bytes) -> bytes:
    if not outpoints:
        raise ValueError("get_input_hash requires at least one outpoint")
    lowest_outpoint = sorted(outpoints, key=lambda o: o.serialize())[0]
    preimage = lowest_outpoint.serialize() + sum_pubkey_bytes
    return tagged_hash("BIP0352/Inputs", preimage)


def derive_silent_payment_outputs(ecdh_share, spend_keys):
    """
    Derive silent payment outputs for recipients from a precomputed ECDH share.

    Unlike create_outputs (which derives the share from input private keys),
    this takes the ECDH shared-secret point directly, as used by the BIP-375
    PSBT flow where shares are carried in the PSBT.

    Each spend key is the final per-output spend key as carried in
    PSBT_OUT_SP_V0_INFO (already label-tweaked when the address was labeled),
    so no label tweak is applied here. ``k`` is the key's position in
    ``spend_keys`` (the caller fixes the ordering).

    Args:
        ecdh_share: 33-byte compressed shared-secret point, already multiplied
            by input_hash (validator does this before calling).
        spend_keys: ordered list of recipient spend public keys.

    Returns:
        Dict mapping recipient position k to output pubkey x-only (32 bytes).
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

        # P_k = B_spend + t_k·G
        p_k_internal = bytearray(ec_pubkey_parse(spend_key.sec()))
        ec_pubkey_tweak_add(p_k_internal, t_k)
        p_k = ec_pubkey_serialize(p_k_internal, EC_COMPRESSED)

        # Store as p2tr output (extract xonly)
        result[k] = p_k[1:33]

    return result
