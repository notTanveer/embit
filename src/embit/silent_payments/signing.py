"""
BIP-375 signing helpers: DLEQ proof wrappers and PSBT input private key
resolution.

These need HD key derivation / root / fingerprint, unlike the pure crypto
in bip352.py.
"""

from ..base import EmbitError
from ..hashes import hash160, tagged_hash
from ..misc import urandom
from . import dleq
from .fields import SPFieldError
from .bip352 import compute_ecdh_share, pubkey_hash_from_script, sum_privkeys, tweak_mul

# ── DLEQ proof generation ────────────────────────────────────────────────────


def _default_aux_rand(*secret_material):
    """Default aux_rand: fresh entropy hedged with the proof's private-key material."""
    return tagged_hash(
        "embit/DLEQDefaultAuxRand", urandom(32) + b"".join(secret_material)
    )


def compute_dleq_proof(private_key, scan_key, ecdh_share, aux_rand=None, verify=True):
    """Generate a 64-byte DLEQ proof for an input's ECDH share (a·B_scan)."""
    if verify and compute_ecdh_share(private_key, scan_key) != ecdh_share:
        raise SPFieldError("ecdh_share does not match private_key and scan_key")
    if aux_rand is not None:
        r = aux_rand
    else:
        r = _default_aux_rand(private_key, scan_key.sec())
    try:
        return dleq.generate_dleq_proof(private_key, scan_key.sec(), r=r)
    except dleq.DLEQError as e:
        raise SPFieldError("Failed to generate DLEQ proof: {}".format(e))


def compute_global_dleq_proof(
    private_keys, scan_key, global_share, aux_rand=None, verify=True, _a_sum_bytes=None
):
    """Generate a 64-byte DLEQ proof for a global ECDH share (a_sum·B_scan)."""
    if _a_sum_bytes is not None:
        a_sum_bytes = _a_sum_bytes
    else:
        a_sum = sum_privkeys(private_keys)
        if a_sum == 0:
            raise SPFieldError("Cannot generate proof for zero sum")
        a_sum_bytes = a_sum.to_bytes(32, "big")

    if verify and tweak_mul(scan_key.sec(), a_sum_bytes) != global_share:
        raise SPFieldError("global_share does not match private_keys and scan_key")

    if aux_rand is not None:
        r = aux_rand
    else:
        r = _default_aux_rand(a_sum_bytes, scan_key.sec())
    try:
        return dleq.generate_dleq_proof(a_sum_bytes, scan_key.sec(), r=r)
    except dleq.DLEQError as e:
        raise SPFieldError("Failed to generate global DLEQ proof: {}".format(e))


# ── PSBT input key resolution ────────────────────────────────────────────────


def match_sp_spend_base(inp, root, fingerprint, derive_hdkey):
    """Return the base PrivateKey for a BIP-376 SP-spend input, matched via
    sp_spend_bip32_derivations for fingerprint, or None."""
    if fingerprint:
        for pub_bytes, derivation in inp.sp_spend_bip32_derivations.items():
            if derivation.fingerprint != fingerprint:
                continue
            hdkey = derive_hdkey(root, derivation)
            if hdkey is not None and hdkey.xonly() == pub_bytes[1:]:
                return hdkey.key
    if fingerprint is None and hasattr(root, "secret"):
        return root
    return None


def _resolve_taproot_privkey(inp, root, fingerprint, derive_hdkey):
    """Resolve the private key for a taproot input."""
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
        return out_priv.secret if out_priv.xonly() == output_xonly else None

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
    """Resolve the private key for non-taproot inputs via BIP32."""
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
    """Return the 32-byte private scalar for an eligible input's ECDH share,
    or None if root does not control the input."""
    if inp.script_pubkey is not None and inp.script_pubkey.script_type() == "p2tr":
        return _resolve_taproot_privkey(inp, root, fingerprint, derive_hdkey)
    return _resolve_bip32_privkey(inp, root, fingerprint, derive_hdkey)
