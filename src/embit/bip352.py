"""
BIP-352: Silent Payments
see: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki

TODO:
* Implement signing SP spends (once psbt format is settled).
"""
from embit import bech32, ec
from embit.util import secp256k1
from embit.hashes import tagged_hash
from typing import Tuple, List
from . import transaction
from embit import script
from embit.networks import NETWORKS


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


def get_input_hash(outpoints: List[Tuple[bytes, int]], A_sum: ec.PublicKey) -> bytes:
    """compute input hash for silent payment protocol"""
    sorted_outpoints = sorted(
        outpoints, key=lambda o: o[0] + o[1].to_bytes(4, "little")
    )
    lowest_outpoint_txid, lowest_outpoint_vout = sorted_outpoints[0]
    lowest_outpoint_bytes = lowest_outpoint_txid + lowest_outpoint_vout.to_bytes(
        4, "little"
    )

    return tagged_hash("BIP0352/Inputs", lowest_outpoint_bytes + A_sum.xonly())


def generate_destination_address(
    input_privkeys: List[Tuple[ec.PrivateKey, bool]],
    outpoints: List[Tuple[bytes, int]],
    recipient_addresses: List[str],
    amounts: List[int],
    network: str = NETWORKS["main"],
) -> List[transaction.TxOut]:
    if not input_privkeys or not outpoints or not recipient_addresses:
        raise ValueError(
            "Input private keys, outpoints, and recipient addresses are required."
        )

    if len(recipient_addresses) != len(amounts):
        raise ValueError("Number of recipient addresses must match number of amounts")

    a_sum = _sum_private_keys(input_privkeys)
    A_sum = a_sum.get_public_key()
    input_hash = get_input_hash(outpoints, A_sum)
    recipient_groups = _group_recipients_by_scan_key(recipient_addresses, amounts)

    outputs = []
    for group in recipient_groups:
        group_outputs = _generate_outputs_for_group(a_sum, input_hash, group, network)
        outputs.extend(group_outputs)

    return outputs


def _sum_private_keys(
    input_privkeys: List[Tuple[ec.PrivateKey, bool]]
) -> ec.PrivateKey:
    """Sum private keys, negating x-only keys with odd y-coordinates."""
    if not input_privkeys:
        raise ValueError("No private keys provided")

    first_key, is_xonly = input_privkeys[0]
    if is_xonly:
        pubkey = first_key.get_public_key()
        if pubkey.sec()[0] == 0x03:  # odd y-coordinate
            result_secret = secp256k1.ec_privkey_negate(first_key.secret)
        else:
            result_secret = first_key.secret
    else:
        result_secret = first_key.secret

    for key, is_xonly in input_privkeys[1:]:
        key_secret = key.secret
        if is_xonly:
            pubkey = key.get_public_key()
            if pubkey.sec()[0] == 0x03:
                key_secret = secp256k1.ec_privkey_negate(key_secret)

        result_secret = secp256k1.ec_privkey_add(result_secret, key_secret)

    return ec.PrivateKey(result_secret)


def _group_recipients_by_scan_key(addresses: List[str], amounts: List[int]):
    """Group recipients by their scan public key."""
    groups = {}

    for i, (address, amount) in enumerate(zip(addresses, amounts)):
        if not address.startswith("sp1") and not address.startswith("tsp1"):
            continue

        B_scan, B_spend = decode_silent_payment_address(address)
        scan_key = B_scan.sec()

        if scan_key not in groups:
            groups[scan_key] = {"B_scan": B_scan, "recipients": []}

        groups[scan_key]["recipients"].append(
            {"B_spend": B_spend, "amount": amount, "index": i}
        )

    return list(groups.values())


def _generate_outputs_for_group(
    a_sum: ec.PrivateKey,
    input_hash: bytes,
    group: dict,
) -> List[transaction.TxOut]:
    """Generate outputs for a recipient group (same scan key)."""
    outputs = []

    ecdh_step1 = secp256k1.ec_privkey_tweak_mul(input_hash, a_sum.secret)
    ecdh_step1_key = ec.PrivateKey(ecdh_step1)

    B_scan_parsed = secp256k1.ec_pubkey_parse(group["B_scan"].sec())
    shared_secret = secp256k1.ecdh(B_scan_parsed, ecdh_step1_key.secret)

    for k, recipient in enumerate(group["recipients"]):
        # t_k = tagged_hash("BIP0352/SharedSecret", shared_secret || ser32(k))
        k_bytes = k.to_bytes(4, "big")
        t_k = tagged_hash("BIP0352/SharedSecret", shared_secret + k_bytes)

        # P_mk = t_k * G + B_spend
        t_k_pubkey = ec.PrivateKey(t_k).get_public_key()
        B_spend_parsed = secp256k1.ec_pubkey_parse(recipient["B_spend"].sec())
        P_mk_parsed = secp256k1.ec_pubkey_add(
            secp256k1.ec_pubkey_parse(t_k_pubkey.sec()), B_spend_parsed
        )
        P_mk = ec.PublicKey(secp256k1.ec_pubkey_serialize(P_mk_parsed))

        taproot_script = script.p2tr(P_mk)
        output = transaction.TransactionOutput(recipient["amount"], taproot_script)
        outputs.append(output)

    return outputs


def create_silent_payment_transaction(
    utxos: List[dict],
    targets: List[dict],
    fee_rate: int,
    network: str = NETWORKS["main"],
) -> transaction.Transaction:
    """
    Create a transaction with silent payment outputs.

    Args:
        utxos: List of UTXO dictionaries with keys:
               - txid: str
               - vout: int
               - value: int (satoshis)
               - script_pubkey: Script
               - private_key: PrivateKey
               - utxo_type: str ("p2wpkh", "p2tr", etc.)
        targets: List of target dictionaries with keys:
                - address: str (can be regular or silent payment address)
                - amount: int (satoshis)
        fee_rate: int (sats per vbyte)
        network: str

    Returns:
        Transaction object
    """
    sp_targets = []
    regular_targets = []
    sp_amounts = []
    regular_amounts = []

    for target in targets:
        if target["address"].startswith("sp1") or target["address"].startswith("tsp1"):
            sp_targets.append(target["address"])
            sp_amounts.append(target["amount"])
        else:
            regular_targets.append(target)
            regular_amounts.append(target["amount"])

    inputs = []
    input_privkeys = []
    outpoints = []

    for utxo in utxos:
        txin = transaction.TransactionInput(
            txid=bytes.fromhex(utxo["txid"]),
            vout=utxo["vout"],
            script_sig=script.Script(),  # empty scriptSig for P2WPKH or P2TR
            sequence=0xFFFFFFFF,
        )
        inputs.append(txin)
        is_xonly = utxo["utxo_type"] == "p2tr"
        input_privkeys.append((utxo["private_key"], is_xonly))
        outpoints.append((bytes.fromhex(utxo["txid"]), utxo["vout"]))

    outputs = []
    for target in regular_targets:
        script_pubkey = script.Script.from_address(target["address"])
        output = transaction.TransactionOutput(target["amount"], script_pubkey)
        outputs.append(output)

    if sp_targets:
        sp_outputs = generate_destination_address(
            input_privkeys, outpoints, sp_targets, sp_amounts, network
        )
        outputs.extend(sp_outputs)

    tx = transaction.Transaction(version=2, vin=inputs, vout=outputs, locktime=0)
    estimated_size = len(tx.serialize()) + len(inputs) * 107  # rough estimate
    required_fee = estimated_size * fee_rate

    total_input = sum(utxo["value"] for utxo in utxos)
    total_output = sum(target["amount"] for target in targets)

    if total_input < total_output + required_fee:
        raise ValueError("Insufficient funds")

    change_amount = total_input - total_output - required_fee
    if change_amount > 546:
        # scanning is computationally expensive, so we avoid small change outputs
        pass

    return tx
