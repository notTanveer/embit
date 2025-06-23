"""
BIP-352: Silent Payments
see: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki
TODO:
* Implement deriving a destination addr for a given output and recipient SP address.
* Implement check to determine if a given output is an SP output for a given SP address.
* Implement signing SP spends (once psbt format is settled).
"""
from embit import bech32, ec
from embit.util import secp256k1
from embit.hashes import tagged_hash
from typing import Tuple
from . import transaction


def generate_silent_payment_address(
    B_scan: ec.PublicKey, B_spend: ec.PublicKey, network: str = "main", version: int = 0
) -> str:
    """
    Adapted from https://github.com/bitcoin/bips/blob/master/bip-0352/reference.py
    """
    data = bech32.convertbits(B_scan.sec() + B_spend.sec(), 8, 5)
    hrp = "sp" if network == "main" else "tsp"
    return bech32.bech32_encode(bech32.Encoding.BECH32M, hrp, [version] + data)


def generate_labeled_silent_payment_address(
    b_scan: ec.PrivateKey,
    B_spend: ec.PublicKey,
    label,
    network: str = "main",
    version: int = 0,
) -> str:
    """
    The spending key is tweaked with the label to generate a labeled silent payment address.
    see: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki#address-encoding
    `label` must be an int, str, or bytes.
    """
    if isinstance(label, int):
        label_bytes = label.to_bytes(4, "big")
    elif isinstance(label, str):
        label_bytes = label.encode()
    elif isinstance(label, bytes):
        label_bytes = label
    else:
        raise Exception("Label must be an int, str, or bytes.")

    tweak = tagged_hash("BIP0352/Label", b_scan.secret + label_bytes)
    label_pubkey = ec.PublicKey(
        secp256k1.ec_pubkey_add(secp256k1.ec_pubkey_parse(B_spend.sec()), tweak)
    )

    return generate_silent_payment_address(
        b_scan.get_public_key(), label_pubkey, network=network, version=version
    )


def decode_silent_payment_address(address: str) -> Tuple[ec.PublicKey, ec.PublicKey]:
    """
    Decode a silent payment address and return the scan and spend public keys.
    Silent payment addresses can be longer than 90 characters, so we need custom decoding.
    """
    if address.startswith("sp1"):
        hrp = "sp"
    elif address.startswith("tsp1"):
        hrp = "tsp"
    else:
        raise ValueError("Invalid silent payment address: unknown HRP")

    # Custom bech32 decode that bypasses the 90-character limit
    if (any(ord(x) < 33 or ord(x) > 126 for x in address)) or (
        address.lower() != address and address.upper() != address
    ):
        raise ValueError("Invalid silent payment address: invalid characters")

    address = address.lower()
    pos = address.rfind("1")
    if pos < 1 or pos + 7 > len(address):
        raise ValueError("Invalid silent payment address: invalid format")

    if not all(x in bech32.CHARSET for x in address[pos + 1 :]):
        raise ValueError(
            "Invalid silent payment address: invalid characters in data part"
        )

    hrpgot = address[:pos]
    data = [bech32.CHARSET.find(x) for x in address[pos + 1 :]]

    if hrpgot != hrp:
        raise ValueError("Invalid silent payment address: HRP mismatch")

    # Verify checksum
    encoding = bech32.bech32_verify_checksum(hrpgot, data)
    if encoding is None:
        raise ValueError("Invalid silent payment address: checksum verification failed")

    if encoding != bech32.Encoding.BECH32M:
        raise ValueError("Invalid silent payment address: must use bech32m encoding")

    # Remove checksum
    data = data[:-6]

    # Version should be 0
    if data[0] != 0:
        raise ValueError(
            f"Invalid silent payment address: unsupported version {data[0]}"
        )

    decoded = bech32.convertbits(data[1:], 5, 8, False)
    if decoded is None:
        raise ValueError("Invalid silent payment address: conversion failed")

    try:
        B_scan = ec.PublicKey.parse(bytes(decoded[:33]))
        B_spend = ec.PublicKey.parse(bytes(decoded[33:]))
    except Exception as e:
        raise ValueError(f"Invalid silent payment address: invalid public keys - {e}")

    return B_scan, B_spend


def create_silent_payment_outputs(
    input_privkeys: list[ec.PrivateKey],
    prevouts: list[transaction.TransactionOutput],
    outpoints: list[tuple[bytes, int]],
    recipient_addresses: list[str],
) -> list[ec.PublicKey]:
    """
    creates output public keys for given recipients.
    sender's side of the protocol.

    Args:
        input_privkeys: Private keys for the inputs being spent
        prevouts: Previous outputs being spent (for determining P2TR negation)
        outpoints: List of (txid, vout) tuples for the inputs
        recipient_addresses: List of silent payment addresses

    Returns:
        List of unique output public keys to create in the transaction
    """
    if len(input_privkeys) != len(prevouts) or len(input_privkeys) != len(outpoints):
        raise ValueError(
            "input_privkeys, prevouts, and outpoints must have the same length"
        )

    if not input_privkeys:
        return []

    sum_secret = b"\x00" * 32
    for i, privkey in enumerate(input_privkeys):
        secret = privkey.secret
        if prevouts[i].script_pubkey.is_p2tr():
            pubkey = privkey.get_public_key()
            if pubkey.sec()[0] == 0x03:  # y is odd
                secret = secp256k1.ec_privkey_negate(secret)
        sum_secret = secp256k1.ec_privkey_add(sum_secret, secret)

    if sum_secret == b"\x00" * 32:
        return []

    a_sum_priv = ec.PrivateKey(sum_secret)
    A_sum_pub = a_sum_priv.get_public_key()

    recipient_groups = {}
    for addr in recipient_addresses:
        B_scan, B_spend = decode_silent_payment_address(addr)
        scan_key = B_scan.sec()
        if scan_key not in recipient_groups:
            recipient_groups[scan_key] = []
        recipient_groups[scan_key].append((B_scan, B_spend))

    sorted_outpoints = sorted(
        outpoints, key=lambda o: o[0] + o[1].to_bytes(4, "little")
    )
    lowest_outpoint_txid, lowest_outpoint_vout = sorted_outpoints[0]
    lowest_outpoint_bytes = lowest_outpoint_txid + lowest_outpoint_vout.to_bytes(
        4, "little"
    )

    input_hash = tagged_hash(
        "BIP0352/Inputs", lowest_outpoint_bytes + A_sum_pub.sec(compressed=False)
    )

    output_pubkeys = []
    for scan_key, recipients in recipient_groups.items():
        B_scan = recipients[0][0]

        # ECDH shared secret: input_hash * a_sum * B_scan
        ecdh_point_1 = secp256k1.ec_pubkey_tweak_mul(B_scan._point, a_sum_priv.secret)
        if ecdh_point_1 is None:
            continue
        ecdh_point_2 = secp256k1.ec_pubkey_tweak_mul(ecdh_point_1, input_hash)
        if ecdh_point_2 is None:
            continue
        ecdh_shared_secret = ec.PublicKey(ecdh_point_2, compressed=False)

        k = 0
        for _, B_spend in recipients:
            # tweak: t_k = H("BIP0352/SharedSecret", ecdh_secret || k)
            t_k_bytes = tagged_hash(
                "BIP0352/SharedSecret",
                ecdh_shared_secret.sec() + k.to_bytes(4, "little"),
            )

            # output pubkey: P_k = B_spend + t_k * G
            t_k_point = secp256k1.ec_pubkey_create(t_k_bytes)
            if t_k_point is None:
                k += 1
                continue

            P_k_point = secp256k1.ec_pubkey_add(B_spend._point, t_k_point)
            if P_k_point is None:
                k += 1
                continue

            output_pubkeys.append(ec.PublicKey(P_k_point))
            k += 1

    unique_pubkeys = []
    seen_xonly = set()
    for pubkey in output_pubkeys:
        xonly = pubkey.xonly()
        if xonly not in seen_xonly:
            unique_pubkeys.append(pubkey)
            seen_xonly.add(xonly)

    return unique_pubkeys
