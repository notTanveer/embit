"""
BIP-352: Silent Payments — core cryptography, address encoding, output
derivation, and PSBT input/output helpers.

see: https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki
"""

from .. import bech32, ec
from ..hashes import hash160, tagged_hash
from ..script import Script
from ..transaction import COutPoint
from ..util import secp256k1
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
from .fields import SPFieldError, SPValidationError

K_MAX = 2323
_NUMS_XONLY = ec.NUMS_PUBKEY.xonly()

# ── crypto math ───────────────────────────────────────────────────────────────


def sum_privkeys(private_keys):
    """Sum private key scalars mod SECP256K1_ORDER (BIP-352 a_sum)."""
    return sum(int.from_bytes(priv, "big") for priv in private_keys) % SECP256K1_ORDER


def normalize_xonly_keys(input_privkeys):
    """Normalize (secret, is_xonly) pairs: negate odd-Y xonly keys.
    Returns list of 32-byte private key scalars ready for summation."""
    normalized = []
    for sec, is_xonly in input_privkeys:
        if not ec_seckey_verify(sec):
            raise ValueError("Invalid private key")
        if is_xonly:
            if ec_pubkey_serialize(ec_pubkey_create(sec))[0] == 0x03:
                sec = ec_privkey_negate(sec)
        normalized.append(sec)
    return normalized


def tweak_mul(point_sec, scalar):
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


# ── core ECDH ─────────────────────────────────────────────────────────────────


def compute_ecdh_share(private_key, scan_key):
    """Compute ECDH share: a·B_scan (33-byte compressed)."""
    if len(private_key) != 32:
        raise SPFieldError("Private key must be 32 bytes")
    return tweak_mul(scan_key.sec(), private_key)


def compute_global_ecdh_share(private_keys, scan_key):
    """Compute global ECDH share: a_sum·B_scan (33-byte compressed),
    or None if a_sum=0."""
    if not private_keys:
        return None
    for priv in private_keys:
        if not ec_seckey_verify(priv):
            raise SPFieldError("Invalid private key")
    a_sum = sum_privkeys(private_keys)
    if a_sum == 0:
        return None
    return tweak_mul(scan_key.sec(), a_sum.to_bytes(32, "big"))


# ── addresses & labels ────────────────────────────────────────────────────────


def apply_label(spend_pubkey, scan_privkey, m):
    """BIP-352 label tweak:
    B_m = B_spend + tagged_hash("BIP0352/Label", scan_priv || ser32(m))·G"""
    if not isinstance(m, int) or isinstance(m, bool):
        raise TypeError("Label must be an int.")
    if not 0 <= m <= 0xFFFFFFFF:
        raise ValueError("Label must be a 32-bit unsigned integer in [0, 2**32 - 1].")
    tweak = tagged_hash("BIP0352/Label", scan_privkey.secret + m.to_bytes(4, "big"))
    return ec.PublicKey(
        secp256k1.ec_pubkey_add(secp256k1.ec_pubkey_parse(spend_pubkey.sec()), tweak)
    )


def encode_silent_payment_address(scan_pubkey, spend_pubkey, network="main", version=0):
    """Bech32m-encode a BIP-352 Silent Payment address from its scan/spend
    public keys."""
    data = bech32.convertbits(scan_pubkey.sec() + spend_pubkey.sec(), 8, 5)
    hrp = "sp" if network == "main" else "tsp"
    return bech32.bech32_encode(bech32.Encoding.BECH32M, hrp, [version] + data)


def generate_silent_payment_address(
    scan_privkey, spend_pubkey, label=None, network="main", version=0
):
    """Generates the recipient's reusable silent payment address."""
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
    """Decode a silent payment address and return the (scan, spend) public keys."""
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
        return (
            ec.PublicKey.parse(bytes(decoded[:33])),
            ec.PublicKey.parse(bytes(decoded[33:])),
        )
    except Exception as e:
        raise ValueError(
            "Invalid silent payment address: invalid public keys - {}".format(e)
        )


# ── output derivation ────────────────────────────────────────────────────────


def get_input_hash(outpoints, sum_pubkey_bytes):
    """BIP-352 input_hash: tagged_hash("BIP0352/Inputs", lowest_outpoint || A)"""
    if not outpoints:
        raise ValueError("get_input_hash requires at least one outpoint")
    lowest_outpoint = min(outpoints, key=lambda o: o.serialize())
    return tagged_hash("BIP0352/Inputs", lowest_outpoint.serialize() + sum_pubkey_bytes)


def derive_silent_payment_outputs(ecdh_share, spend_keys):
    """Derive silent payment x-only outputs for recipients from a
    precomputed ECDH share."""
    if not spend_keys:
        return {}
    if len(spend_keys) > K_MAX:
        raise ValueError(
            "Too many outputs for one scan key: {} > {}".format(len(spend_keys), K_MAX)
        )
    result = {}
    for k, spend_key in enumerate(spend_keys):
        t_k = tagged_hash("BIP0352/SharedSecret", ecdh_share + k.to_bytes(4, "big"))
        p_k = bytearray(ec_pubkey_parse(spend_key.sec()))
        ec_pubkey_tweak_add(p_k, t_k)
        result[k] = ec_pubkey_serialize(p_k, EC_COMPRESSED)[1:33]
    return result


def derive_outputs_for_keys(priv_keys, outpoints, scan_spend_groups):
    """Core output derivation from private keys.

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
    a_sum = sum_privkeys(priv_keys)
    if a_sum == 0:
        return None
    a_sum_bytes = a_sum.to_bytes(32, "big")
    input_hash = get_input_hash(
        outpoints, ec_pubkey_serialize(ec_pubkey_create(a_sum_bytes))
    )
    results = {}
    for sk_bytes, (scan_key, spend_keys) in scan_spend_groups.items():
        ecdh_share = compute_ecdh_share(a_sum_bytes, scan_key)
        outputs = derive_silent_payment_outputs(
            tweak_mul(ecdh_share, input_hash), spend_keys
        )
        results[sk_bytes] = (ecdh_share, outputs)
    return a_sum_bytes, results


# ── script helpers ────────────────────────────────────────────────────────────


def pubkey_hash_from_script(script, redeem_script=None):
    """Return the 20-byte HASH160(pubkey) committed by a single-key script.
    Handles P2WPKH, P2PKH, P2SH-P2WPKH; returns None for others."""
    if script is None:
        return None
    stype = script.script_type()
    if stype == "p2wpkh":
        return bytes(script.data[2:22])
    if stype == "p2pkh":
        return bytes(script.data[3:23])
    if stype == "p2sh" and redeem_script and redeem_script.script_type() == "p2wpkh":
        return bytes(redeem_script.data[2:22])
    return None


def witness_version(script):
    """Return the segwit witness version (0-16), or None if not a witness program."""
    data = script.data
    if len(data) < 4 or len(data) > 42:
        return None
    op = data[0]
    if op == 0x00:
        ver = 0
    elif 0x51 <= op <= 0x60:
        ver = op - 0x50
    else:
        return None
    return ver if data[1] == len(data) - 2 and 2 <= data[1] <= 40 else None


def input_public_key(inp):
    """Resolve an input's public key A used for SP shared-secret derivation."""
    script = inp.script_pubkey
    if script is None:
        return None
    if script.script_type() == "p2tr":
        return ec.PublicKey.from_xonly(bytes(script.data[2:34]))
    candidates = list(inp.bip32_derivations) + list(inp.partial_sigs)
    if not candidates:
        return None
    pkh = pubkey_hash_from_script(script, inp.redeem_script)
    if pkh is not None:
        for pubkey in candidates:
            if hash160(pubkey.sec()) == pkh:
                return pubkey
    unique = list(dict.fromkeys(candidates))
    return unique[0] if len(unique) == 1 else None


# ── PSBT helpers ──────────────────────────────────────────────────────────────


def get_eligible_inputs(inputs, has_sp_outputs=False):
    """Get list of eligible input indices for SP computation.
    Per BIP-352: P2PKH, P2WPKH, P2SH-P2WPKH, P2TR.
    Per BIP-375: if has_sp_outputs, reject inputs spending Segwit v>1."""
    eligible = []
    for i, inp in enumerate(inputs):
        script = inp.script_pubkey
        if script is None:
            continue
        stype = script.script_type()
        if has_sp_outputs:
            wv = witness_version(script)
            if wv is not None and wv > 1:
                raise SPValidationError(
                    "Input {} spends a Segwit version > 1 output with SP "
                    "outputs".format(i)
                )
        if stype == "p2tr":
            is_nums = (
                inp.taproot_internal_key is not None
                and inp.taproot_internal_key.xonly() == _NUMS_XONLY
            )
            if is_nums:
                continue
            eligible.append(i)
        elif stype in {"p2pkh", "p2wpkh"}:
            eligible.append(i)
        elif (
            stype == "p2sh"
            and inp.redeem_script
            and inp.redeem_script.script_type() == "p2wpkh"
        ):
            eligible.append(i)
    return eligible


def all_outpoints(psbt):
    """Return the COutPoint list for every input of a PSBT-like object."""
    return [
        COutPoint(txid=psbt.tx.vin[i].txid, out_idx=psbt.tx.vin[i].vout)
        for i in range(len(psbt.inputs))
    ]


def group_sp_outputs_by_scan_key(outputs):
    """Group SP outputs by scan key, preserving output-index order.
    Returns {scan_key_bytes: (scan_key, [(out_idx, spend_key), ...])}."""
    groups = {}
    for out_idx, out in enumerate(outputs):
        if out.sp_data is None:
            continue
        sk_bytes = out.sp_data.scan_key.sec()
        if sk_bytes not in groups:
            groups[sk_bytes] = (out.sp_data.scan_key, [])
        groups[sk_bytes][1].append((out_idx, out.sp_data.spend_key))
    return groups


def derive_sp_output_scripts(psbt, eligible=None, eligible_pubkeys=None):
    """Derive the taproot scriptPubKey for every SP output whose ECDH share is
    already resolvable."""
    groups = group_sp_outputs_by_scan_key(psbt.outputs)
    if not groups:
        return {}
    if eligible is None:
        eligible = get_eligible_inputs(psbt.inputs, has_sp_outputs=True)
    if eligible_pubkeys is None:
        eligible_pubkeys = [input_public_key(psbt.inputs[i]) for i in eligible]
    if not eligible_pubkeys or any(pk is None for pk in eligible_pubkeys):
        return {}

    outpoints = all_outpoints(psbt)
    A_sum_bytes = sum_pubkeys(eligible_pubkeys)
    input_hash = get_input_hash(outpoints, A_sum_bytes)

    resolved = {}
    for scan_key_bytes, (_scan_key, group) in groups.items():
        ecdh_share = psbt.sp_ecdh_shares.get(scan_key_bytes)
        if ecdh_share is None:
            share_sum, contributing = None, 0
            for i in eligible:
                share = psbt.inputs[i].sp_ecdh_shares.get(scan_key_bytes)
                if share is None:
                    continue
                parsed = ec_pubkey_parse(share)
                if share_sum is None:
                    share_sum = parsed
                else:
                    share_sum = ec_pubkey_combine(share_sum, parsed)
                contributing += 1
            if share_sum is None or contributing != len(eligible):
                continue
            ecdh_share = ec_pubkey_serialize(share_sum, EC_COMPRESSED)

        derived = derive_silent_payment_outputs(
            tweak_mul(ecdh_share, input_hash),
            [spend_key for _, spend_key in group],
        )
        for pos, (out_idx, _) in enumerate(group):
            resolved[out_idx] = Script(b"\x51\x20" + derived[pos])
    return resolved
