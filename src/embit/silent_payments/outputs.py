"""
BIP-375 Silent Payment output derivation and PSBT population helpers.
"""

from typing import Dict, List, Tuple, Optional

from .. import ec
from .. import hashes
from . import bip352
from ..util.secp256k1 import (
    ec_pubkey_parse,
    ec_pubkey_serialize,
    ec_pubkey_tweak_add,
    ec_pubkey_tweak_mul,
    ec_pubkey_combine,
    ec_pubkey_create,
    EC_COMPRESSED,
    ec_seckey_verify,
)
from ..script import Script
from .fields import SilentPaymentData, SPFieldError, SPValidationError
from .ecdh import (
    compute_ecdh_share,
    compute_global_ecdh_share,
    compute_dleq_proof,
    compute_global_dleq_proof,
    get_eligible_inputs,
)
from ..transaction import COutPoint
from ..util.key import SECP256K1_ORDER


def sign_sp_psbt(psbt, root_key) -> int:
    """
    Sign an SP PSBTv2. Returns total fields added
    (signatures + ecdh_shares + dleq_proofs).
    Raises SPValidationError if the PSBT is invalid for SP signing.
    """
    if psbt.version != 2:
        raise SPValidationError("SP signing requires PSBTv2")
    if not any(out.sp_data is not None for out in psbt.outputs):
        raise SPValidationError("No SP outputs found in PSBT")
    # Raises SPValidationError if P2TR inputs are present with SP outputs
    get_eligible_inputs(psbt.inputs, has_sp_outputs=True)
    return psbt.sign_with(root_key)


def derive_silent_payment_outputs(
    ecdh_share: bytes,
    recipients: List[Tuple[ec.PublicKey, ec.PublicKey, int]],
    shared_secret: Optional[bytes] = None,
) -> Dict[int, bytes]:
    """
    Derive silent payment outputs for recipients.

    This is based on BIP-352 output derivation but uses precomputed ECDH share.

    Args:
        ecdh_share: The ECDH shared secret point C (33 bytes)
        recipients: List of (scan_key, spend_key, label) tuples
        shared_secret: Precomputed xonly shared secret (for efficiency)

    Returns:
        Dict mapping recipient index to output pubkey xonly (32 bytes each)
    """
    if not recipients:
        return {}

    # Use precomputed or default to the full 33-byte compressed point (BIP-352 §1)
    if shared_secret is None:
        shared_secret = ecdh_share

    result = {}
    k = 0

    for idx, (scan_key, spend_key, label) in enumerate(recipients):
        # For labeled recipients, tweak the spend key
        if label is not None and label != 0:
            if isinstance(label, int):
                label_bytes = label.to_bytes(4, "big")
            else:
                label_bytes = label

            tweak = hashes.tagged_hash("BIP0352/Label", scan_key.sec() + label_bytes)
            # Tweak spend key
            spend_internal = ec_pubkey_parse(spend_key.sec())
            ec_pubkey_tweak_add(spend_internal, tweak)
            tweaked_spend = ec_pubkey_serialize(spend_internal, EC_COMPRESSED)
        else:
            tweaked_spend = spend_key.sec()

        # Compute t_k
        t_k = hashes.tagged_hash(
            "BIP0352/SharedSecret",
            shared_secret + k.to_bytes(4, "big"),
        )

        # P_k = B_spend + t_k
        p_k_internal = ec_pubkey_parse(tweaked_spend)
        ec_pubkey_tweak_add(p_k_internal, t_k)
        p_k = ec_pubkey_serialize(p_k_internal, EC_COMPRESSED)

        # Store as p2tr output (extract xonly)
        result[idx] = p_k[1:33]

        k += 1

    return result


def _parse_sp_recipient(recipient_address: str):
    """Decode a silent payment address into scan/spend keys."""
    try:
        return bip352.decode_silent_payment_address(recipient_address)
    except Exception as e:
        raise SPValidationError(f"Invalid silent payment recipient address: {e}")


def _combine_shares(shares: List[bytes]) -> bytes:
    """Combine multiple compressed ECDH share points into one compressed point."""
    if not shares:
        raise SPValidationError("Cannot combine empty ECDH share set")
    if len(shares) == 1:
        return shares[0]

    acc = ec_pubkey_parse(shares[0])
    for share in shares[1:]:
        acc = ec_pubkey_combine(acc, ec_pubkey_parse(share))
    return ec_pubkey_serialize(acc, EC_COMPRESSED)


def populate_silent_payment_send_data(
    psbt,
    root,
    aux_rand: Optional[bytes] = None,
) -> int:
    """
    Populate per-input ECDH shares and DLEQ proofs for all SP outputs.

    Convenience wrapper around psbt._sign_with_sp.  Pass fresh 32-byte
    aux_rand from a trusted entropy source; omitting it is a security risk.

    Returns:
        Number of (ECDH-share, DLEQ-proof) pairs added.
    """
    if psbt.version != 2:
        raise SPValidationError("SP data population requires PSBTv2")
    if not any(out.sp_data is not None for out in psbt.outputs):
        raise SPValidationError("No SP outputs found in PSBT")
    return psbt._sign_with_sp(root, aux_rand=aux_rand)


def populate_silent_payment_send_data_from_keys(
    psbt,
    recipients: List[Tuple[int, str, Optional[int]]],
    input_private_keys: Dict[int, bytes],
    include_global_fields: bool = True,
    include_input_fields: bool = False,
    set_output_scripts: bool = True,
) -> Dict[int, bytes]:
    """
    Populate BIP-375 Silent Payment send fields and derived outputs in a PSBTv2.

    Args:
        psbt: PSBTv2 instance to update in-place.
        recipients: List of tuples `(output_index, sp_address, label)`.
            - `output_index`: target PSBT output index to annotate/derive.
            - `sp_address`: recipient Silent Payment address.
            - `label`: optional uint32 label (or None).
        input_private_keys: Mapping of input index -> 32-byte private key for
            eligible inputs.
        include_global_fields: Whether to populate
            PSBT_GLOBAL_SP_ECDH_SHARE / PSBT_GLOBAL_SP_DLEQ.
        include_input_fields: Whether to populate
            PSBT_IN_SP_ECDH_SHARE / PSBT_IN_SP_DLEQ on eligible inputs.
        set_output_scripts: Whether to set PSBT_OUT_SCRIPT from derived key.

    Returns:
        Dict mapping output index -> derived xonly output key (32 bytes).

    Raises:
        SPValidationError: If input validation fails or derivation cannot be
            completed safely.
        SPFieldError: For malformed key material.
    """
    if psbt.version != 2:
        raise SPValidationError("Silent Payment send fields require PSBTv2")
    if not recipients:
        raise SPValidationError("At least one recipient is required")
    if not include_global_fields and not include_input_fields:
        raise SPValidationError(
            "At least one of global or per-input SP fields must be populated"
        )

    output_count = len(psbt.outputs)
    recipient_rows = []
    seen_output_indexes = set()

    for output_index, address, label in recipients:
        if output_index < 0 or output_index >= output_count:
            raise SPValidationError(
                f"Recipient output index {output_index} is out of range"
            )
        if output_index in seen_output_indexes:
            raise SPValidationError(f"Duplicate recipient output index {output_index}")
        seen_output_indexes.add(output_index)

        if label is not None:
            if not isinstance(label, int):
                raise SPValidationError("Recipient label must be an int or None")
            if label < 0 or label > 0xFFFFFFFF:
                raise SPValidationError("Recipient label must be a uint32")

        scan_key, spend_key = _parse_sp_recipient(address)
        recipient_rows.append(
            {
                "output_index": output_index,
                "scan_key": scan_key,
                "spend_key": spend_key,
                "label": label,
            }
        )

    eligible_inputs = get_eligible_inputs(psbt.inputs, has_sp_outputs=True)
    if not eligible_inputs:
        raise SPValidationError("No eligible inputs for Silent Payment derivation")

    eligible_privkeys = []
    for inp_index in eligible_inputs:
        if inp_index not in input_private_keys:
            raise SPValidationError(
                f"Missing private key for eligible input {inp_index}"
            )
        priv = input_private_keys[inp_index]
        if not isinstance(priv, (bytes, bytearray)) or len(priv) != 32:
            raise SPFieldError(f"Input {inp_index} private key must be 32 bytes")
        if not ec_seckey_verify(bytes(priv)):
            raise SPFieldError(f"Input {inp_index} private key is invalid")
        eligible_privkeys.append(bytes(priv))

    # Compute input_hash = hash(lowest_outpoint || A_sum) per BIP-352.
    # This is the same for every scan-key group, so compute it once.
    outpoints = [
        COutPoint(txid=psbt.tx.vin[i].txid, out_idx=psbt.tx.vin[i].vout)
        for i in eligible_inputs
    ]
    a_sum = (
        sum(int.from_bytes(priv, "big") for priv in eligible_privkeys) % SECP256K1_ORDER
    )
    a_sum_bytes = a_sum.to_bytes(32, "big")
    A_sum_bytes = ec_pubkey_serialize(ec_pubkey_create(a_sum_bytes), EC_COMPRESSED)
    input_hash = bip352.get_input_hash(outpoints, A_sum_bytes)

    recipients_by_scan: Dict[bytes, List[dict]] = {}
    for row in recipient_rows:
        scan_key_bytes = row["scan_key"].sec()
        recipients_by_scan.setdefault(scan_key_bytes, []).append(row)

    derived_output_keys: Dict[int, bytes] = {}

    for scan_key_bytes, scan_recipients in recipients_by_scan.items():
        scan_key = scan_recipients[0]["scan_key"]

        global_share = None
        if include_global_fields:
            global_share = compute_global_ecdh_share(eligible_privkeys, scan_key)
            if global_share is None:
                raise SPValidationError(
                    "Global private key sum is zero; cannot derive Silent Payments"
                )
            psbt.sp_ecdh_shares[scan_key_bytes] = global_share
            psbt.sp_dleq_proofs[scan_key_bytes] = compute_global_dleq_proof(
                eligible_privkeys,
                scan_key,
                global_share,
            )

        per_input_shares = []
        if include_input_fields:
            for inp_index in eligible_inputs:
                priv = input_private_keys[inp_index]
                share = compute_ecdh_share(priv, scan_key)
                proof = compute_dleq_proof(priv, scan_key, share)
                psbt.inputs[inp_index].sp_ecdh_shares[scan_key_bytes] = share
                psbt.inputs[inp_index].sp_dleq_proofs[scan_key_bytes] = proof
                per_input_shares.append(share)

        derivation_share = (
            global_share
            if global_share is not None
            else _combine_shares(per_input_shares)
        )

        # Apply input_hash: adjusted = input_hash · derivation_share (BIP-352)
        adjusted_handle = ec_pubkey_parse(derivation_share)
        ec_pubkey_tweak_mul(adjusted_handle, input_hash)
        adjusted_share = ec_pubkey_serialize(adjusted_handle, EC_COMPRESSED)

        sorted_scan_recipients = sorted(
            scan_recipients,
            key=lambda r: r["spend_key"].sec(),
        )

        derived_for_scan = derive_silent_payment_outputs(
            adjusted_share,
            [
                (r["scan_key"], r["spend_key"], r["label"])
                for r in sorted_scan_recipients
            ],
        )

        for pos, recipient_row in enumerate(sorted_scan_recipients):
            output_index = recipient_row["output_index"]
            output_scope = psbt.outputs[output_index]
            xonly_key = derived_for_scan[pos]

            output_scope.sp_data = SilentPaymentData(
                recipient_row["scan_key"], recipient_row["spend_key"]
            )
            output_scope.sp_label = recipient_row["label"]
            if set_output_scripts:
                output_scope.script_pubkey = Script(b"\x51\x20" + xonly_key)

            derived_output_keys[output_index] = xonly_key

    # If scripts are set for SP outputs, BIP-375 requires non-modifiable tx flags.
    if set_output_scripts:
        psbt.tx_modifiable_flags = 0

    return derived_output_keys
