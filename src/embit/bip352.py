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
from embit.util.key import ECPubKey


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

    # custom bech32 to bypass the 90-character limit
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

    encoding = bech32.bech32_verify_checksum(hrpgot, data)
    if encoding is None:
        raise ValueError("Invalid silent payment address: checksum verification failed")

    if encoding != bech32.Encoding.BECH32M:
        raise ValueError("Invalid silent payment address: must use bech32m encoding")

    data = data[:-6]

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
