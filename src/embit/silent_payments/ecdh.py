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
from binascii import hexlify
from .bip352 import (
    get_input_hash,
    derive_silent_payment_outputs,
    decode_silent_payment_address,
    K_MAX,
)
from ..util.key import SECP256K1_ORDER
from ..util.secp256k1 import (
    ec_pubkey_combine,
    ec_pubkey_create,
    ec_pubkey_parse,
    ec_pubkey_serialize,
    ec_pubkey_tweak_mul,
    ec_privkey_negate,
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


def _sum_privkeys(private_keys):
    return sum(int.from_bytes(priv, "big") for priv in private_keys) % SECP256K1_ORDER


def _normalize_xonly_keys(input_privkeys):
    """Normalize (secret, is_xonly) pairs: negate odd-Y xonly keys.
    Returns list of 32-byte private key scalars ready for summation."""
    normalized = []
    for sec, is_xonly in input_privkeys:
        if not ec_seckey_verify(sec):
            raise ValueError("Invalid private key")
        if is_xonly:
            pub = ec_pubkey_create(sec)
            ser = ec_pubkey_serialize(pub)
            if ser[0] == 0x03:
                sec = ec_privkey_negate(sec)
        normalized.append(sec)
    return normalized


def _tweak_mul(point_sec: bytes, scalar: bytes) -> bytes:
    """Multiply a compressed point by a scalar, returning the compressed result."""
    point = bytearray(ec_pubkey_parse(point_sec))
    ec_pubkey_tweak_mul(point, scalar)
    return ec_pubkey_serialize(point, EC_COMPRESSED)


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

    return _tweak_mul(scan_key.sec(), private_key)


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

    for priv in private_keys:
        if not ec_seckey_verify(priv):
            raise SPFieldError("Invalid private key")

    a_sum = _sum_privkeys(private_keys)
    if a_sum == 0:
        return None

    a_sum_bytes = a_sum.to_bytes(32, "big")
    return _tweak_mul(scan_key.sec(), a_sum_bytes)


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
    _a_sum_bytes=None,
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
        _a_sum_bytes: Precomputed 32-byte summed private key scalar. When
                      provided, skips re-summation of `private_keys`.

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

    if verify:
        # Verify global_share against the already-summed a_sum instead of
        # calling compute_global_ecdh_share() again (which would re-sum
        # private_keys).
        if _tweak_mul(scan_key.sec(), a_sum_bytes) != global_share:
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


def match_sp_spend_base(inp, root, fingerprint, derive_hdkey):
    """Return the base PrivateKey for a BIP-376 SP-spend input, matched via
    ``sp_spend_bip32_derivations`` for ``fingerprint`` (or the raw ``root``
    key when there's no fingerprint), or None if ``root`` does not control
    this input's SP spend key.

    Returns the *untweaked* base key -- callers apply ``sp_spend_tweak``
    themselves, since the send path normalizes to even-Y for ECDH summation
    while the spend/signing path leaves parity to Schnorr signing.

    ``derive_hdkey`` is injected by the caller (PSBT-aware derivation
    honoring a descriptor key's origin prefix) to keep this module free of
    a psbt.py import.
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


def resolve_input_privkey(inp, root, fingerprint, derive_hdkey):
    """Return the 32-byte private scalar 'a' for an eligible input's ECDH
    share, or None if ``root`` does not control the input.

    For taproot inputs this is the (even-Y) output private key per the
    BIP-352 negation rule, obtained via taproot_tweak; for the other types
    it is the input key matched by derivation or by script hash.

    ``derive_hdkey`` is injected for the same reason as in
    ``match_sp_spend_base``.
    """
    is_taproot = (
        inp.script_pubkey is not None
        and inp.script_pubkey.script_type() == "p2tr"
    )

    if is_taproot:
        output_xonly = bytes(inp.script_pubkey.data[2:34])

        # BIP-376 spend-from input: the key is the tweaked spend key
        # b_spend + t, normalized to even Y so it can be summed into the
        # BIP-352 shared secret (Schnorr signing handles its own parity).
        # Matched via sp_spend_bip32_derivations rather than the BIP-86 path.
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
            for pub, (_leaves, derivation) in (
                inp.taproot_bip32_derivations.items()
            ):
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


def all_outpoints(psbt):
    """Return the COutPoint list for every input of a PSBT-like object
    (has .tx and .inputs), in input order."""
    return [
        COutPoint(txid=psbt.tx.vin[i].txid, out_idx=psbt.tx.vin[i].vout)
        for i in range(len(psbt.inputs))
    ]


def group_sp_outputs_by_scan_key(outputs):
    """Group SP outputs by scan key, preserving output-index order.

    Returns {scan_key_bytes: (scan_key, [(out_idx, spend_key), ...])}. The
    derivation counter k is the output's position within its scan-key group
    in this order (BIP-375: outputs sharing scan+spend are ordered by output
    index).
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


def derive_sp_output_scripts(psbt, eligible=None, eligible_pubkeys=None) -> dict:
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
    groups = group_sp_outputs_by_scan_key(psbt.outputs)
    if not groups:
        return {}

    if eligible is None:
        eligible = get_eligible_inputs(psbt.inputs, has_sp_outputs=True)

    if eligible_pubkeys is None:
        eligible_pubkeys = [input_public_key(psbt.inputs[i]) for i in eligible]
    if not eligible_pubkeys or any(pk is None for pk in eligible_pubkeys):
        # A partial A_sum (silently dropping unrecoverable keys) would derive
        # wrong scripts, not just incomplete ones - refuse outright instead.
        return {}

    # BIP-352 input_hash commits to the smallest outpoint over ALL transaction
    # inputs (not just the eligible ones), while A is the sum of eligible keys.
    outpoints = all_outpoints(psbt)
    A_sum_bytes = sum_pubkeys(eligible_pubkeys)
    input_hash = get_input_hash(outpoints, A_sum_bytes)

    resolved = {}
    for scan_key_bytes, (_scan_key, group) in groups.items():
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

        adjusted_share = _tweak_mul(ecdh_share, input_hash)

        derived = derive_silent_payment_outputs(
            adjusted_share,
            [spend_key for _, spend_key in group],
        )
        for pos, (out_idx, _spend_key) in enumerate(group):
            resolved[out_idx] = Script(b"\x51\x20" + derived[pos])

    return resolved


def _derive_outputs_for_keys(priv_keys, outpoints, scan_spend_groups):
    """Core output derivation from private keys.

    Computes ECDH shares and derives output pubkeys for each scan-key group.
    Used by both create_outputs (address API) and sign_single_party (PSBT API)
    so both paths run the same derivation verified against BIP-352 test vectors.

    Args:
        priv_keys: list of 32-byte private key scalars (parity-normalized)
        outpoints: list of COutPoint
        scan_spend_groups: {scan_key_bytes: (scan_key, [spend_key, ...])}

    Returns:
        (a_sum_bytes, {scan_key_bytes: (ecdh_share, {k: xonly_bytes})})
        or None if a_sum == 0
    """
    for _scan_key, spend_keys in scan_spend_groups.values():
        if len(spend_keys) > K_MAX:
            raise ValueError(
                "Too many outputs for one scan key: {} > {}".format(
                    len(spend_keys), K_MAX
                )
            )

    a_sum = _sum_privkeys(priv_keys)
    if a_sum == 0:
        return None
    a_sum_bytes = a_sum.to_bytes(32, "big")

    A_sum_bytes = ec_pubkey_serialize(ec_pubkey_create(a_sum_bytes))
    input_hash = get_input_hash(outpoints, A_sum_bytes)

    results = {}
    for sk_bytes, (scan_key, spend_keys) in scan_spend_groups.items():
        ecdh_share = compute_ecdh_share(a_sum_bytes, scan_key)
        adjusted_share = _tweak_mul(ecdh_share, input_hash)
        outputs = derive_silent_payment_outputs(adjusted_share, spend_keys)
        results[sk_bytes] = (ecdh_share, outputs)

    return a_sum_bytes, results


def create_outputs(input_privkeys, outpoints, recipients):
    """
    Creates silent payment outputs for given recipients.

    Args:
        input_privkeys: List of (private_key_bytes, is_xonly) tuples
        outpoints: List of transaction outpoints
        recipients: List of silent payment addresses (strings) - duplicates
            allowed; pass in vout order so k matches the BIP-375 validator.

    Returns:
        Dictionary mapping each unique recipient address to list of output hex
        strings. A repeated address's outputs are listed in occurrence order, so
        to rebuild the transaction in vout order, walk ``recipients`` and pop the
        next output from ``result[addr]`` (FIFO) for each entry. The k baked into
        each output assumes that ordering; flattening the dict by address instead
        would place outputs at the wrong vouts.
    """
    if not input_privkeys:
        return {}

    normalized = _normalize_xonly_keys(input_privkeys)

    decoded = {}
    for addr in recipients:
        if addr not in decoded:
            decoded[addr] = decode_silent_payment_address(addr)

    scan_spend_groups = {}
    addr_lists = {}
    for addr in recipients:
        B_scan, B_spend = decoded[addr]
        sk_bytes = B_scan.sec()
        if sk_bytes not in scan_spend_groups:
            scan_spend_groups[sk_bytes] = (B_scan, [])
            addr_lists[sk_bytes] = []
        scan_spend_groups[sk_bytes][1].append(B_spend)
        addr_lists[sk_bytes].append(addr)

    derivation = _derive_outputs_for_keys(normalized, outpoints, scan_spend_groups)
    if derivation is None:
        return {}

    _a_sum_bytes, results = derivation

    output = {addr: [] for addr in decoded}
    for sk_bytes, (_ecdh_share, outputs) in results.items():
        for k, addr in enumerate(addr_lists[sk_bytes]):
            output[addr].append(hexlify(outputs[k]).decode())

    return output
