"""
BIP-375 ECDH share and DLEQ proof computation, plus input eligibility.
"""

from .. import ec
from ..base import EmbitError
from ..hashes import hash160, tagged_hash
from ..misc import urandom
from ..script import Script
from ..transaction import COutPoint
from . import dleq
from .fields import SPFieldError, SPValidationError
from ..util.secp256k1 import (
    ec_pubkey_parse,
    ec_pubkey_combine,
    ec_pubkey_serialize,
    EC_COMPRESSED,
)

# Import core BIP-352 math and derivation functions
from .bip352 import (
    _sum_privkeys,
    _tweak_mul,
    compute_ecdh_share,
    derive_silent_payment_outputs,
    get_input_hash,
    sum_pubkeys,
)

_NUMS_XONLY = ec.NUMS_PUBKEY.xonly()

# ============================================================================
# DLEQ Proof Generation
# ============================================================================

def _default_aux_rand(*secret_material):
    """
    Default aux_rand for a DLEQ proof when the caller doesn't supply one:
    fresh platform entropy hedged with the proof's own private-key material.
    """
    return tagged_hash(
        "embit/DLEQDefaultAuxRand", urandom(32) + b"".join(secret_material)
    )

def compute_dleq_proof(
    private_key, scan_key, ecdh_share, aux_rand=None, verify=True
):
    """
    Generate DLEQ proof for an input's ECDH share.
    
    Args:
        private_key: 32-byte private key (a)
        scan_key: The scan key (B_scan)
        ecdh_share: The ECDH share (a·B_scan)
        aux_rand: 32-byte auxiliary randomness
        verify: recompute the share and check it matches `ecdh_share`

    Returns:
        64-byte DLEQ proof
    """
    if verify and compute_ecdh_share(private_key, scan_key) != ecdh_share:
        raise SPFieldError("ecdh_share does not match private_key and scan_key")
        
    r = aux_rand if aux_rand is not None else _default_aux_rand(private_key, scan_key.sec())
    try:
        return dleq.generate_dleq_proof(private_key, scan_key.sec(), r=r)
    except dleq.DLEQError as e:
        raise SPFieldError("Failed to generate DLEQ proof: {}".format(e))

def compute_global_dleq_proof(
    private_keys, scan_key, global_share, aux_rand=None, verify=True, _a_sum_bytes=None
):
    """
    Generate DLEQ proof for global ECDH share.
    
    Args:
        private_keys: List of 32-byte private keys (all eligible inputs)
        scan_key: The scan key (B_scan)
        global_share: The global ECDH share (a_sum·B_scan)
        aux_rand: 32-byte auxiliary randomness
        verify: recompute a_sum·B_scan and check it matches
        _a_sum_bytes: Precomputed 32-byte summed private key scalar

    Returns:
        64-byte DLEQ proof
    """
    if _a_sum_bytes is not None:
        a_sum_bytes = _a_sum_bytes
    else:
        a_sum = _sum_privkeys(private_keys)
        if a_sum == 0:
            raise SPFieldError("Cannot generate proof for zero sum")
        a_sum_bytes = a_sum.to_bytes(32, "big")

    if verify and _tweak_mul(scan_key.sec(), a_sum_bytes) != global_share:
        raise SPFieldError("global_share does not match private_keys and scan_key")

    r = aux_rand if aux_rand is not None else _default_aux_rand(a_sum_bytes, scan_key.sec())
    try:
        return dleq.generate_dleq_proof(a_sum_bytes, scan_key.sec(), r=r)
    except dleq.DLEQError as e:
        raise SPFieldError("Failed to generate global DLEQ proof: {}".format(e))

# ============================================================================
# PSBT Input Resolution & Eligibility
# ============================================================================

def pubkey_hash_from_script(script, redeem_script=None):
    """
    Return the 20-byte HASH160(pubkey) committed by a single-key script.
    Handles P2WPKH, P2PKH, P2SH-P2WPKH; returns None for others.
    """
    if script is None:
        return None
        
    script_type = script.script_type()
    if script_type == "p2wpkh":
        return bytes(script.data[2:22])
    if script_type == "p2pkh":
        return bytes(script.data[3:23])
    if (
        script_type == "p2sh"
        and redeem_script is not None
        and redeem_script.script_type() == "p2wpkh"
    ):
        return bytes(redeem_script.data[2:22])
        
    return None

def witness_version(script):
    """
    Return the segwit witness version (0-16) of a witness program script,
    or None when the script is not a canonical witness program.
    """
    data = script.data
    if len(data) < 4 or len(data) > 42:
        return None
    op = data[0]
    if op == 0x00:
        version = 0
    elif 0x51 <= op <= 0x60:  # OP_1 .. OP_16
        version = op - 0x50
    else:
        return None
    if data[1] != len(data) - 2 or not (2 <= data[1] <= 40):
        return None
    return version

def input_public_key(inp):
    """
    Resolve an input's public key A used for SP shared-secret derivation.
    Returns an `ec.PublicKey` or None.
    """
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

    unique = []
    for pubkey in candidates:
        if pubkey not in unique:
            unique.append(pubkey)
    if len(unique) == 1:
        return unique[0]
        
    return None

def match_sp_spend_base(inp, root, fingerprint, derive_hdkey):
    """
    Return the base PrivateKey for a BIP-376 SP-spend input, matched via
    `sp_spend_bip32_derivations` for `fingerprint`, or None.
    """
    if fingerprint:
        for pub_bytes, derivation in inp.sp_spend_bip32_derivations.items():
            if derivation.fingerprint != fingerprint:
                continue
            hdkey = derive_hdkey(root, derivation)
            if hdkey is None or hdkey.xonly() != pub_bytes[1:]:
                continue
            return hdkey.key

    if fingerprint is None and hasattr(root, "secret"):
        return root

    return None

def _resolve_taproot_privkey(inp, root, fingerprint, derive_hdkey):
    """Helper to resolve the private key for a taproot input."""
    output_xonly = bytes(inp.script_pubkey.data[2:34])

    sp_tweak = getattr(inp, "sp_tweak", None)
    if sp_tweak is not None:
        base = match_sp_spend_base(inp, root, fingerprint, derive_hdkey)
        if base is None:
            return None
        try:
            out_priv = base.sp_spend_tweak(sp_tweak).even_y()
        except (EmbitError, ValueError):
            return None
        if out_priv.xonly() == output_xonly:
            return out_priv.secret
        return None

    merkle = inp.taproot_merkle_root or b""
    if fingerprint:
        for pub, (_leaves, derivation) in inp.taproot_bip32_derivations.items():
            if derivation.fingerprint != fingerprint:
                continue
            hdkey = derive_hdkey(root, derivation)
            if hdkey is None or hdkey.xonly() != pub.xonly():
                continue
            out_priv = hdkey.key.taproot_tweak(merkle)
            if out_priv.xonly() == output_xonly:
                return out_priv.secret
                
    if fingerprint is None and hasattr(root, "secret"):
        try:
            out_priv = root.taproot_tweak(merkle)
        except (EmbitError, ValueError):
            return None
        if out_priv.xonly() == output_xonly:
            return out_priv.secret
            
    return None

def _resolve_bip32_privkey(inp, root, fingerprint, derive_hdkey):
    """Helper to resolve the private key for non-taproot inputs via BIP32."""
    if fingerprint:
        for pub, derivation in inp.bip32_derivations.items():
            if derivation.fingerprint != fingerprint:
                continue
            hdkey = derive_hdkey(root, derivation)
            if hdkey is None or hdkey.xonly() != pub.xonly():
                continue
            return hdkey.key.secret

    if fingerprint is None and hasattr(root, "secret"):
        pkh = pubkey_hash_from_script(inp.script_pubkey, inp.redeem_script)
        if pkh is not None and pkh == hash160(root.get_public_key().sec()):
            return root.secret

    return None

def resolve_input_privkey(inp, root, fingerprint, derive_hdkey):
    """
    Return the 32-byte private scalar 'a' for an eligible input's ECDH
    share, or None if `root` does not control the input.
    """
    is_taproot = (
        inp.script_pubkey is not None
        and inp.script_pubkey.script_type() == "p2tr"
    )
    if is_taproot:
        return _resolve_taproot_privkey(inp, root, fingerprint, derive_hdkey)
    return _resolve_bip32_privkey(inp, root, fingerprint, derive_hdkey)

def get_eligible_inputs(inputs, has_sp_outputs=False):
    """
    Get list of eligible input indices for SP computation.
    
    Per BIP-352: P2PKH, P2WPKH, P2SH-P2WPKH, P2TR.
    Per BIP-375: if has_sp_outputs, reject inputs spending Segwit v>1.
    """
    eligible = []

    for i, inp in enumerate(inputs):
        script = inp.script_pubkey
        if script is None:
            continue

        script_type = script.script_type()

        if has_sp_outputs:
            wv = witness_version(script)
            if wv is not None and wv > 1:
                raise SPValidationError(
                    "Input {} spends a Segwit version > 1 output with SP outputs".format(i)
                )

        if script_type == "p2tr":
            if (
                inp.taproot_internal_key is not None
                and inp.taproot_internal_key.xonly() == _NUMS_XONLY
            ):
                continue
            eligible.append(i)
        elif script_type in {"p2pkh", "p2wpkh"}:
            eligible.append(i)
        elif script_type == "p2sh":
            if inp.redeem_script and inp.redeem_script.script_type() == "p2wpkh":
                eligible.append(i)

    return eligible

# ============================================================================
# PSBT Output Derivation
# ============================================================================

def all_outpoints(psbt):
    """Return the COutPoint list for every input of a PSBT-like object."""
    return [
        COutPoint(txid=psbt.tx.vin[i].txid, out_idx=psbt.tx.vin[i].vout)
        for i in range(len(psbt.inputs))
    ]

def group_sp_outputs_by_scan_key(outputs):
    """
    Group SP outputs by scan key, preserving output-index order.
    Returns {scan_key_bytes: (scan_key, [(out_idx, spend_key), ...])}.
    """
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
    """
    Derive the taproot scriptPubKey for every SP output whose ECDH share is
    already resolvable.
    """
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
            share_sum = None
            contributing = 0
            for i in eligible:
                share = psbt.inputs[i].sp_ecdh_shares.get(scan_key_bytes)
                if share is None:
                    continue
                parsed = ec_pubkey_parse(share)
                share_sum = parsed if share_sum is None else ec_pubkey_combine(share_sum, parsed)
                contributing += 1

            if share_sum is None or contributing != len(eligible):
                continue
            ecdh_share = ec_pubkey_serialize(share_sum, EC_COMPRESSED)

        adjusted_share = _tweak_mul(ecdh_share, input_hash)
        derived = derive_silent_payment_outputs(
            adjusted_share,
            [spend_key for _, spend_key in group],
        )
        
        for pos, (out_idx, _spend_key) in enumerate(group):
            resolved[out_idx] = Script(b"\x51\x20" + derived[pos])

    return resolved
