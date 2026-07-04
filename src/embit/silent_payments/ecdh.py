"""
BIP-375 ECDH share and DLEQ proof computation, plus input eligibility.
"""

from .. import ec
from ..hashes import hash160, tagged_hash
from ..misc import urandom
from ..script import Script
from ..transaction import COutPoint
from . import dleq
from .bip352 import get_input_hash, derive_silent_payment_outputs
from ..util.key import SECP256K1_ORDER
from ..util.secp256k1 import (
    ec_pubkey_combine,
    ec_pubkey_parse,
    ec_pubkey_serialize,
    ec_pubkey_tweak_mul,
    EC_COMPRESSED,
    ec_seckey_verify,
)
from .fields import SPFieldError, SPValidationError


def _default_aux_rand(*secret_material: bytes) -> bytes:
    """Default aux_rand for a DLEQ proof when the caller doesn't supply one:
    fresh platform entropy hedged with the proof's own private-key material,
    so a weak or compromised platform RNG alone cannot make the derived nonce
    predictable to an attacker who doesn't also know the private key. This is
    defense-in-depth on top of generate_dleq_proof's own internal aux-rand
    hedging (t = a XOR H(r)) -- it protects specifically against re-proving
    the exact same (private key, scan key) pair under a degenerate RNG, which
    the internal hedge alone cannot, since a predictable+repeated r under a
    fixed private key would otherwise collide.

    Not a BIP-374-specified construction -- purely an embit-side hardening of
    the "aux_rand is None" default path. Callers that pass an explicit
    aux_rand bypass this entirely and are unaffected.
    """
    return tagged_hash("embit/DLEQDefaultAuxRand", urandom(32) + b"".join(secret_material))


def compute_ecdh_share(private_key: bytes, scan_key: ec.PublicKey) -> bytes:
    """
    Compute ECDH share for a single private key.

    Args:
        private_key: 32-byte private key
        scan_key: The scan key to compute share with

    Returns:
        33-byte ECDH share (a·B_scan) compressed
    """
    if len(private_key) != 32:
        raise SPFieldError("Private key must be 32 bytes")

    # Compute a·B_scan
    b_internal = bytearray(ec_pubkey_parse(scan_key.sec()))
    ec_pubkey_tweak_mul(b_internal, private_key)
    return ec_pubkey_serialize(b_internal, EC_COMPRESSED)


def compute_global_ecdh_share(private_keys, scan_key: ec.PublicKey):
    """
    Compute global ECDH share from multiple private keys.

    Args:
        private_keys: List of 32-byte private keys (all eligible inputs)
        scan_key: The scan key to compute share with

    Returns:
        33-byte ECDH share (a_sum·B_scan) compressed, or None if a_sum=0
    """
    if not private_keys:
        return None

    # Verify all private keys
    for priv in private_keys:
        if not ec_seckey_verify(priv):
            raise SPFieldError("Invalid private key")

    # Sum all private keys mod n
    a_sum = sum(int.from_bytes(priv, "big") for priv in private_keys) % SECP256K1_ORDER
    if a_sum == 0:
        return None

    a_sum_bytes = a_sum.to_bytes(32, "big")

    # Compute a_sum·B_scan
    b_internal = bytearray(ec_pubkey_parse(scan_key.sec()))
    ec_pubkey_tweak_mul(b_internal, a_sum_bytes)
    return ec_pubkey_serialize(b_internal, EC_COMPRESSED)


def compute_dleq_proof(
    private_key: bytes,
    scan_key: ec.PublicKey,
    ecdh_share: bytes,
    aux_rand=None,
    verify: bool = True,
) -> bytes:
    """
    Generate DLEQ proof for an input's ECDH share.

    Args:
        private_key: 32-byte private key (a)
        scan_key: The scan key (B_scan)
        ecdh_share: The ECDH share (a·B_scan); verified against `private_key`
                    and `scan_key` before proving, so a caller can never
                    produce a proof for a share it didn't actually derive.
        aux_rand: 32-byte auxiliary randomness. When None, a default is
                  derived from fresh platform RNG hedged with the private key
                  material (see `_default_aux_rand`); pass explicit bytes for
                  deterministic behaviour or hardware wallet use.
        verify: recompute the share and check it matches `ecdh_share` before
                proving. Defaults to True (defence-in-depth for external
                callers). Trusted internal callers that just derived the share
                pass False to skip the extra scalar multiplication — on a
                constrained signer this is the most expensive op and would
                otherwise run twice per (input, scan key).

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
    private_keys,
    scan_key: ec.PublicKey,
    global_share: bytes,
    aux_rand=None,
    verify: bool = True,
) -> bytes:
    """
    Generate DLEQ proof for global ECDH share.

    Args:
        private_keys: List of 32-byte private keys (all eligible inputs)
        scan_key: The scan key (B_scan)
        global_share: The global ECDH share (a_sum·B_scan); verified against
                      `private_keys` and `scan_key` before proving.
        aux_rand: 32-byte auxiliary randomness. When None, a default is
                  derived from fresh platform RNG hedged with the summed
                  private key material (see `_default_aux_rand`).
        verify: recompute a_sum·B_scan and check it matches `global_share`
                before proving. Defaults to True; a trusted internal caller
                that just derived `global_share` via compute_global_ecdh_share
                passes False to avoid the duplicate scalar multiplication.

    Returns:
        64-byte DLEQ proof
    """
    # Sum all private keys mod n
    a_sum = sum(int.from_bytes(priv, "big") for priv in private_keys) % SECP256K1_ORDER
    if a_sum == 0:
        raise SPFieldError("Cannot generate proof for zero sum")
    a_sum_bytes = a_sum.to_bytes(32, "big")

    if verify:
        # Verify global_share against the already-summed a_sum instead of
        # calling compute_global_ecdh_share() again (which would re-sum
        # private_keys).
        b_internal = bytearray(ec_pubkey_parse(scan_key.sec()))
        ec_pubkey_tweak_mul(b_internal, a_sum_bytes)
        if ec_pubkey_serialize(b_internal, EC_COMPRESSED) != global_share:
            raise SPFieldError(
                "global_share does not match private_keys and scan_key"
            )

    r = aux_rand if aux_rand is not None else _default_aux_rand(a_sum_bytes, scan_key.sec())

    try:
        return dleq.generate_dleq_proof(a_sum_bytes, scan_key.sec(), r=r)
    except dleq.DLEQError as e:
        raise SPFieldError("Failed to generate global DLEQ proof: {}".format(e))


def pubkey_hash_from_script(script, redeem_script=None):
    """Return the 20-byte HASH160(pubkey) committed by a single-key script.

    Handles the SP-eligible script types (P2WPKH, P2PKH, P2SH-P2WPKH); returns
    None for any other type. This is the single source of truth for matching a
    pubkey to an input script, used by both the signer and the validator.
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


_NUMS_XONLY = ec.NUMS_PUBKEY.xonly()


def witness_version(script):
    """Return the segwit witness version (0-16) of a witness program script,
    or None when the script is not a canonical witness program."""
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
    # second byte must be a direct push of the remaining (2..40) program bytes
    if data[1] != len(data) - 2 or not (2 <= data[1] <= 40):
        return None
    return version


def input_public_key(inp):
    """Resolve an input's public key A used for SP shared-secret derivation.

    For taproot the key is the (even-Y) output key from the scriptPubKey.  For
    the other eligible types it comes from PSBT_IN_BIP32_DERIVATION (preferred,
    matched by hash160 against the script) or PSBT_IN_PARTIAL_SIG, falling back
    to the sole candidate when the scriptPubKey does not commit to it (e.g. the
    placeholder UTXOs in the BIP-375 test vectors). Returns an ``ec.PublicKey``
    or None.
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


def get_eligible_inputs(inputs, has_sp_outputs: bool = False):
    """
    Get list of eligible input indices for SP computation.

    Per BIP-352 the eligible input types are P2PKH, P2WPKH, P2SH-P2WPKH and
    P2TR (taproot, segwit v1).  Taproot inputs committing to the NUMS internal
    key are excluded (script-path-only, no usable key for ECDH).

    Per BIP-375, when there are SP outputs an input spending a Segwit version
    > 1 output is forbidden and the Signer must fail.

    Args:
        inputs: List of PSBT input scopes
        has_sp_outputs: Whether the PSBT has any SP outputs

    Returns:
        List of eligible input indices
    """
    eligible = []

    for i, inp in enumerate(inputs):
        script = inp.script_pubkey
        if script is None:
            continue

        script_type = script.script_type()

        # BIP-375: refuse to sign when an input spends a Segwit v>1 output.
        if has_sp_outputs:
            wv = witness_version(script)
            if wv is not None and wv > 1:
                raise SPValidationError(
                    "Input {} spends a Segwit version > 1 output with SP "
                    "outputs".format(i)
                )

        if script_type == "p2tr":
            # NUMS internal key -> script-path-only, not eligible.
            if (
                inp.taproot_internal_key is not None
                and inp.taproot_internal_key.xonly() == _NUMS_XONLY
            ):
                continue
            eligible.append(i)
        elif script_type in {"p2pkh", "p2wpkh"}:
            eligible.append(i)
        elif script_type == "p2sh":
            # Only P2SH-P2WPKH is eligible.
            if inp.redeem_script and inp.redeem_script.script_type() == "p2wpkh":
                eligible.append(i)

    return eligible


def sum_pubkeys(pubkeys) -> bytes:
    """Sum a non-empty list of public keys, returning a 33-byte compressed point."""
    acc = ec_pubkey_parse(pubkeys[0].sec())
    for pk in pubkeys[1:]:
        acc = ec_pubkey_combine(acc, ec_pubkey_parse(pk.sec()))
    return ec_pubkey_serialize(acc, EC_COMPRESSED)


def derive_sp_output_scripts(psbt, eligible=None) -> dict:
    """
    Derive the taproot scriptPubKey for every SP output whose ECDH share is
    already resolvable: a PSBT-global share for its scan key, or per-input
    shares contributed by every eligible input.

    Shared by ``BIP375Validator._validate_output_scripts`` (compares the
    result against each output's existing script) and
    ``SilentPaymentsPSBT.fill_output_scripts`` (assigns it).

    Args:
        psbt: A SilentPaymentsPSBT-like object (has .tx, .inputs, .outputs,
            .sp_ecdh_shares).
        eligible: Precomputed eligible input indices; computed via
            get_eligible_inputs() if not given.

    Returns:
        {out_idx: Script}. An SP output is omitted when its share isn't
        resolvable yet (an incomplete multi-party PSBT still missing a
        co-signer's contribution), or an empty dict when any eligible
        input's public key can't be recovered (a partial sum would derive
        wrong scripts, not just incomplete ones).
    """
    sp_outputs = [(i, o) for i, o in enumerate(psbt.outputs) if o.sp_data is not None]
    if not sp_outputs:
        return {}

    if eligible is None:
        eligible = get_eligible_inputs(psbt.inputs, has_sp_outputs=True)

    eligible_pubkeys = [input_public_key(psbt.inputs[i]) for i in eligible]
    if not eligible_pubkeys or any(pk is None for pk in eligible_pubkeys):
        # A partial A_sum (silently dropping unrecoverable keys) would derive
        # wrong scripts, not just incomplete ones - refuse outright instead.
        return {}

    # BIP-352 input_hash commits to the smallest outpoint over ALL transaction
    # inputs (not just the eligible ones), while A is the sum of eligible keys.
    outpoints = [
        COutPoint(txid=psbt.tx.vin[i].txid, out_idx=psbt.tx.vin[i].vout)
        for i in range(len(psbt.inputs))
    ]
    A_sum_bytes = sum_pubkeys(eligible_pubkeys)
    input_hash = get_input_hash(outpoints, A_sum_bytes)

    # Group SP outputs by scan key, preserving output-index order. The
    # derivation counter k is the output's position within its scan-key
    # group in this order (BIP-375: outputs sharing scan+spend are ordered
    # by output index).
    groups = {}
    for out_idx, out in sp_outputs:
        groups.setdefault(out.sp_data.scan_key.sec(), []).append((out_idx, out))

    resolved = {}
    for scan_key_bytes, group in groups.items():
        ecdh_share = psbt.sp_ecdh_shares.get(scan_key_bytes)
        if ecdh_share is None:
            # No global share yet - sum per-input shares (requires every
            # eligible input to have contributed one).
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

        # Apply input_hash: adjusted_share = input_hash . ecdh_share (BIP-352)
        adjusted = bytearray(ec_pubkey_parse(ecdh_share))
        ec_pubkey_tweak_mul(adjusted, input_hash)
        adjusted_share = ec_pubkey_serialize(adjusted, EC_COMPRESSED)

        derived = derive_silent_payment_outputs(
            adjusted_share,
            [o.sp_data.spend_key for _, o in group],
        )
        for pos, (out_idx, _out) in enumerate(group):
            resolved[out_idx] = Script(b"\x51\x20" + derived[pos])

    return resolved
