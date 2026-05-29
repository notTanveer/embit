"""
BIP-352: Silent Payments
see: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki
"""

from collections import Counter, defaultdict
from typing import Tuple, List, Dict, Optional

from .. import bech32, ec
from ..util import secp256k1
from ..hashes import tagged_hash
from ..util.key import SECP256K1_ORDER
from ..transaction import COutPoint
from ..util.secp256k1 import (
    ec_pubkey_create,
    ec_pubkey_serialize,
    ec_pubkey_parse,
    ec_pubkey_tweak_mul,
    ec_pubkey_tweak_add,
    ec_seckey_verify,
    ec_privkey_negate,
    EC_COMPRESSED,
)
from binascii import hexlify


def generate_silent_payment_address(
    scan_privkey: ec.PrivateKey,
    spend_pubkey: ec.PublicKey,
    label: int | str | bytes | None = None,
    network: str = "main",
    version: int = 0,
) -> str:
    """
    Adapted from https://github.com/bitcoin/bips/blob/master/bip-0352/reference.py

    Generates the recipient's reusable silent payment address for a given:
        * scan private key
        * spend public key
        * optional label for labeled addresses
    """
    scan_pubkey = scan_privkey.get_public_key()
    if label is not None:
        if isinstance(label, int):
            label = label.to_bytes(4, "big")
        elif isinstance(label, str):
            label = label.encode()
        tweak = tagged_hash("BIP0352/Label", scan_privkey.secret + label)
        spend_pubkey = ec.PublicKey(
            secp256k1.ec_pubkey_add(
                secp256k1.ec_pubkey_parse(spend_pubkey.sec()), tweak
            )
        )

    data = bech32.convertbits(scan_pubkey.sec() + spend_pubkey.sec(), 8, 5)
    hrp = "sp" if network == "main" else "tsp"
    return bech32.bech32_encode(bech32.Encoding.BECH32M, hrp, [version] + data)


def decode_silent_payment_address(address: str) -> Tuple[ec.PublicKey, ec.PublicKey]:
    """
    Decode a silent payment address and return the scan and spend public keys.
    Silent payment addresses can be longer than 90 characters, so we use the
    length-unrestricted bech32 decoder.
    """
    if address.startswith("sp1"):
        hrp = "sp"
    elif address.startswith("tsp1"):
        hrp = "tsp"
    else:
        raise ValueError("Invalid silent payment address: unknown HRP")

    encoding, hrpgot, data = bech32.bech32_decode_long(address)
    if encoding is None or data is None:
        raise ValueError("Invalid silent payment address: decoding failed")
    if encoding != bech32.Encoding.BECH32M:
        raise ValueError("Invalid silent payment address: must use bech32m encoding")
    if hrpgot != hrp:
        raise ValueError("Invalid silent payment address: HRP mismatch")
    if not data or data[0] != 0:
        raise ValueError("Invalid silent payment address: unsupported version")

    decoded = bech32.convertbits(data[1:], 5, 8, False)
    if decoded is None:
        raise ValueError("Invalid silent payment address: conversion failed")

    try:
        B_scan = ec.PublicKey.parse(bytes(decoded[:33]))
        B_spend = ec.PublicKey.parse(bytes(decoded[33:]))
    except Exception as e:
        raise ValueError(f"Invalid silent payment address: invalid public keys - {e}")

    return B_scan, B_spend


def get_input_hash(outpoints: List["COutPoint"], sum_pubkey_bytes: bytes) -> bytes:
    lowest_outpoint = sorted(outpoints, key=lambda o: o.serialize())[0]
    preimage = lowest_outpoint.serialize() + sum_pubkey_bytes
    return tagged_hash("BIP0352/Inputs", preimage)


def create_outputs(
    input_privkeys: List[Tuple[bytes, bool]],
    outpoints: List["COutPoint"],
    recipients: List[str],
) -> Dict[str, List[str]]:
    """
    Creates silent payment outputs for given recipients.

    Args:
        input_privkeys: List of (private_key_bytes, is_xonly) tuples
        outpoints: List of transaction outpoints
        recipients: List of silent payment addresses (strings) - duplicates are allowed

    Returns:
        Dictionary mapping each unique recipient address to list of output hex strings
    """
    if not input_privkeys:
        return {}

    signing_keys = []
    for sec, is_xonly in input_privkeys:
        if not ec_seckey_verify(sec):
            raise ValueError("Invalid private key")

        if is_xonly:
            pub = ec_pubkey_create(sec)
            ser = ec_pubkey_serialize(pub)
            if ser[0] == 0x03:
                sec = ec_privkey_negate(sec)
        signing_keys.append(int.from_bytes(sec, "big"))

    a_sum = sum(signing_keys) % SECP256K1_ORDER
    if a_sum == 0:
        return {}

    a_sum_bytes = a_sum.to_bytes(32, "big")
    A = ec_pubkey_create(a_sum_bytes)

    input_hash = get_input_hash(outpoints, ec_pubkey_serialize(A))

    recipient_counts = Counter(recipients)

    groups: Dict[ec.PublicKey, List[Tuple[ec.PublicKey, str, int]]] = defaultdict(list)
    for addr, count in recipient_counts.items():
        B_scan, B_spend = decode_silent_payment_address(addr)
        groups[B_scan].append((B_spend, addr, count))

    result: Dict[str, List[str]] = {addr: [] for addr in recipient_counts.keys()}
    scalar = (int.from_bytes(input_hash, "big") * a_sum) % SECP256K1_ORDER
    scalar_bytes = scalar.to_bytes(32, "big")

    for B_scan, B_spend_list in groups.items():
        ecdh_point = ec_pubkey_parse(B_scan.sec())
        ec_pubkey_tweak_mul(ecdh_point, scalar_bytes)
        shared_secret = ec_pubkey_serialize(ecdh_point)  # 33-byte compressed point

        k = 0
        for B_spend, addr, count in B_spend_list:
            for _ in range(count):
                t_k = tagged_hash(
                    "BIP0352/SharedSecret",
                    shared_secret + k.to_bytes(4, "big"),
                )

                P_k = ec_pubkey_parse(B_spend.sec())
                ec_pubkey_tweak_add(P_k, t_k)

                xonly = ec_pubkey_serialize(P_k)[1:33]
                result[addr].append(hexlify(xonly).decode())
                k += 1

    return result


def derive_silent_payment_outputs(
    ecdh_share: bytes,
    recipients: List[Tuple[ec.PublicKey, ec.PublicKey, int]],
    shared_secret: Optional[bytes] = None,
) -> Dict[int, bytes]:
    """
    Derive silent payment outputs for recipients from a precomputed ECDH share.

    Unlike create_outputs (which derives the share from input private keys),
    this takes the ECDH shared-secret point directly, as used by the BIP-375
    PSBT flow where shares are carried in the PSBT.

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

            tweak = tagged_hash("BIP0352/Label", scan_key.sec() + label_bytes)
            spend_internal = ec_pubkey_parse(spend_key.sec())
            ec_pubkey_tweak_add(spend_internal, tweak)
            tweaked_spend = ec_pubkey_serialize(spend_internal, EC_COMPRESSED)
        else:
            tweaked_spend = spend_key.sec()

        # Compute t_k
        t_k = tagged_hash(
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
