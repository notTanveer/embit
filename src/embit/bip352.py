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
from . import transaction
from embit import script
from embit.networks import NETWORKS
from embit.util.key import ECKey, ECPubKey, SECP256K1_ORDER, SECP256K1


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
) -> List[transaction.TransactionOutput]:
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
        group_outputs = _generate_outputs_for_group(a_sum, input_hash, group)
        outputs.extend(group_outputs)

    return outputs


def _sum_private_keys(
    input_privkeys: List[Tuple[ec.PrivateKey, bool]]
) -> ec.PrivateKey:
    """Sum private keys using integer arithmetic modulo curve order."""
    total = 0
    for sk, is_xonly in input_privkeys:
        sk_int = int.from_bytes(sk.secret, "big")
        if is_xonly:
            pub = sk.get_public_key()
            if pub.sec()[0] == 0x03:  # Odd y-coordinate
                total = (total - sk_int) % SECP256K1_ORDER
            else:
                total = (total + sk_int) % SECP256K1_ORDER
        else:
            total = (total + sk_int) % SECP256K1_ORDER

    if total == 0:
        raise ValueError("Sum of private keys is zero, cannot create silent payment")

    return ec.PrivateKey(total.to_bytes(32, "big"))


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
) -> List[transaction.TransactionOutput]:
    """Generate outputs for a recipient group."""
    outputs = []

    print("\n--- Debugging _generate_outputs_for_group ---")
    print(f"a_sum (private key): {a_sum.secret.hex()}")
    print(f"input_hash: {input_hash.hex()}")
    print(f"B_scan (public key): {group['B_scan'].sec().hex()}")

    # Following the reference implementation exactly:
    # ecdh_shared_secret = input_hash * a_sum * B_scan

    # Step 1: Create ECKey objects from the embit types
    a_sum_key = ECKey()
    a_sum_key.set(a_sum.secret, True)

    B_scan_key = ECPubKey()
    B_scan_key.set(group["B_scan"].sec())

    # Step 2: Convert input_hash to an ECKey (treating it as a private key)
    input_hash_key = ECKey()
    input_hash_key.set(input_hash, True)

    # Step 3: Compute the shared secret following the reference:
    # ecdh_shared_secret = input_hash * a_sum * B_scan
    # This means: (input_hash * a_sum) * B_scan

    # First: input_hash * a_sum (this gives us a new private key)
    input_hash_int = int.from_bytes(input_hash, "big")
    a_sum_int = int.from_bytes(a_sum.secret, "big")
    combined_scalar = (input_hash_int * a_sum_int) % SECP256K1_ORDER
    combined_key = ECKey()
    combined_key.set(combined_scalar.to_bytes(32, "big"), True)

    # Second: combined_scalar * B_scan (point multiplication)
    shared_secret_point = SECP256K1.mul([(B_scan_key.p, combined_scalar)])
    shared_secret_affine = SECP256K1.affine(shared_secret_point)

    if shared_secret_affine is None:
        raise ValueError("Failed to compute shared secret")

    # Get uncompressed point bytes (65 bytes) like the reference uses with get_bytes(False)
    shared_secret_bytes = (
        bytes([0x04])
        + shared_secret_affine[0].to_bytes(32, "big")
        + shared_secret_affine[1].to_bytes(32, "big")
    )

    for k, recipient in enumerate(group["recipients"]):
        # t_k = TaggedHash("BIP0352/SharedSecret", shared_secret_bytes || ser32(k))
        k_bytes = k.to_bytes(4, "big")
        t_k = tagged_hash("BIP0352/SharedSecret", shared_secret_bytes + k_bytes)

        # P_mk = t_k * G + B_spend
        t_k_key = ECKey()
        t_k_key.set(t_k, True)
        t_k_pubkey = t_k_key.get_pubkey()

        B_spend_key = ECPubKey()
        B_spend_key.set(recipient["B_spend"].sec())

        # Add the points: P_mk = t_k * G + B_spend
        P_mk_point = SECP256K1.add(t_k_pubkey.p, B_spend_key.p)
        P_mk_affine = SECP256K1.affine(P_mk_point)

        if P_mk_affine is None:
            raise ValueError("Failed to compute P_mk")

        # Convert back to compressed format for the final public key
        P_mk_bytes = bytes([0x02 + (P_mk_affine[1] & 1)]) + P_mk_affine[0].to_bytes(
            32, "big"
        )
        P_mk = ec.PublicKey.parse(P_mk_bytes)

        taproot_script = script.p2tr(P_mk)
        output = transaction.TransactionOutput(recipient["amount"], taproot_script)
        outputs.append(output)

    return outputs


def create_outputs(
    input_privkeys: List[Tuple[ec.PrivateKey, bool]],
    outpoints: List[Tuple[bytes, int]],
    recipients: List[str],
    hrp: str = "sp",
) -> List[str]:
    # Create generator point G
    G = ECKey()
    G.set((1).to_bytes(32, "big"), True)
    G_pubkey = G.get_pubkey()

    negated_keys = []
    for key, is_xonly in input_privkeys:
        k = ECKey()
        k.set(key.secret, True)
        if is_xonly and k.get_pubkey().get_y() % 2 != 0:
            k.negate()
        negated_keys.append(k)

    # Sum the private keys
    a_sum = ECKey()
    total = 0
    for k in negated_keys:
        total = (total + int.from_bytes(k.get_bytes(), "big")) % SECP256K1_ORDER
    a_sum.set(total.to_bytes(32, "big"), True)

    if not a_sum.valid:
        # Input privkeys sum is zero -> fail
        return []

    # Get A_sum public key
    A_sum = a_sum.get_pubkey()

    # Compute input hash - need to convert A_sum to ECPubKey for get_bytes(False)
    A_sum_ecpubkey = ECPubKey()
    A_sum_ecpubkey.set(A_sum.get_bytes())
    input_hash = get_input_hash(outpoints, A_sum_ecpubkey)

    silent_payment_groups: Dict[ECPubKey, List[ECPubKey]] = {}
    for recipient in recipients:
        B_scan, B_m = decode_silent_payment_address(recipient)
        # Convert to ECPubKey for comparison
        B_scan_ecpubkey = ECPubKey()
        B_scan_ecpubkey.set(B_scan.sec())
        B_m_ecpubkey = ECPubKey()
        B_m_ecpubkey.set(B_m.sec())

        if B_scan_ecpubkey in silent_payment_groups:
            silent_payment_groups[B_scan_ecpubkey].append(B_m_ecpubkey)
        else:
            silent_payment_groups[B_scan_ecpubkey] = [B_m_ecpubkey]

    outputs = []
    for B_scan, B_m_values in silent_payment_groups.items():
        # Compute ecdh_shared_secret = input_hash * a_sum * B_scan
        input_hash_key = ECKey()
        input_hash_key.set(input_hash, True)

        # First: input_hash * a_sum
        combined_scalar = (
            int.from_bytes(input_hash, "big") * int.from_bytes(a_sum.get_bytes(), "big")
        ) % SECP256K1_ORDER
        combined_key = ECKey()
        combined_key.set(combined_scalar.to_bytes(32, "big"), True)

        # Second: combined_scalar * B_scan (point multiplication)
        shared_secret_point = SECP256K1.mul([(B_scan.p, combined_scalar)])
        shared_secret_affine = SECP256K1.affine(shared_secret_point)

        if shared_secret_affine is None:
            continue

        # Create ECPubKey for shared secret to use get_bytes(False)
        shared_secret_ecpubkey = ECPubKey()
        shared_secret_ecpubkey.p = shared_secret_point
        shared_secret_ecpubkey.valid = True
        shared_secret_ecpubkey.compressed = False

        k = 0
        for B_m in B_m_values:
            t_k = tagged_hash(
                "BIP0352/SharedSecret",
                shared_secret_ecpubkey.get_bytes() + k.to_bytes(4, "big"),
            )

            # P_km = B_m + t_k * G
            t_k_key = ECKey()
            t_k_key.set(t_k, True)
            t_k_pubkey = t_k_key.get_pubkey()

            P_km_point = SECP256K1.add(B_m.p, t_k_pubkey.p)
            P_km_affine = SECP256K1.affine(P_km_point)

            if P_km_affine is not None:
                P_km_ecpubkey = ECPubKey()
                P_km_ecpubkey.p = P_km_point
                P_km_ecpubkey.valid = True
                P_km_ecpubkey.compressed = True
                outputs.append(P_km_ecpubkey.get_bytes().hex())
            k += 1

    return list(set(outputs))
