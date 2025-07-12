"""
BIP-352: Silent Payments
see: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki

TODO:
* Implement signing SP spends (once psbt format is settled).
"""
from embit import bech32, ec
from embit.util import secp256k1
from embit.hashes import tagged_hash
from typing import Tuple, List, Dict
from embit.util.key import SECP256K1_ORDER
from embit.transaction import COutPoint
from embit.util.secp256k1 import (
    ec_pubkey_create,
    ec_pubkey_serialize,
    ec_pubkey_parse,
    ec_pubkey_tweak_mul,
    ec_pubkey_tweak_add,
    ec_seckey_verify,
    ec_privkey_negate,
    ec_pubkey_serialize,
)
from embit.script import p2tr
from binascii import hexlify, unhexlify


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


# TODO: use the bech32 decode function once the flexible bech32 PR is in
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


def get_input_hash(outpoints: List[COutPoint], sum_pubkey_bytes: bytes) -> bytes:
    lowest_outpoint = sorted(outpoints, key=lambda o: o.serialize())[0]
    preimage = lowest_outpoint.serialize() + sum_pubkey_bytes
    return tagged_hash("BIP0352/Inputs", preimage)


def create_outputs(
    input_privkeys: List[Tuple[bytes, bool]],
    outpoints: List[COutPoint],
    recipients: List[str],
) -> List[str]:
    if not input_privkeys:
        return []

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
        return []

    a_sum_bytes = a_sum.to_bytes(32, "big")
    A = ec_pubkey_create(a_sum_bytes)

    input_hash = get_input_hash(outpoints, ec_pubkey_serialize(A))

    groups: Dict[ec.PublicKey, List[ec.PublicKey]] = {}
    for addr in recipients:
        B_scan, B_spend = decode_silent_payment_address(addr)
        groups.setdefault(B_scan, []).append(B_spend)

    outputs: List[str] = []
    scalar = (int.from_bytes(input_hash, "big") * a_sum) % SECP256K1_ORDER
    scalar_bytes = scalar.to_bytes(32, "big")

    for B_scan, B_spend_list in groups.items():
        ecdh_point = ec_pubkey_parse(B_scan.sec())
        ec_pubkey_tweak_mul(ecdh_point, scalar_bytes)
        xonly_shared_secret = ec_pubkey_serialize(ecdh_point)

        k = 0
        for B_spend in B_spend_list:
            t_k = tagged_hash(
                "BIP0352/SharedSecret",
                xonly_shared_secret + k.to_bytes(4, "big"),
            )

            P_k = ec_pubkey_parse(B_spend.sec())
            ec_pubkey_tweak_add(P_k, t_k)

            xonly = ec_pubkey_serialize(P_k)[1:33]
            outputs.append(hexlify(xonly).decode())
            k += 1

    return list(set(outputs))


def generate_sp_destination_address(
    input_privkeys: List[Tuple[bytes, bool]],
    outpoints: List[COutPoint],
    recipient_sp_address: str,
) -> str:
    outputs = create_outputs(input_privkeys, outpoints, [recipient_sp_address])

    dest_addr = []
    for output in outputs:
        pubkey = ec.PublicKey.parse(b"\x02" + unhexlify(output))
        dest_addr.append(p2tr(pubkey).address())
    return dest_addr
