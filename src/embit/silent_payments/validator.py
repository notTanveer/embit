"""
BIP-375 PSBT Validation

Implements the 4-stage validation pipeline for Silent Payments in PSBTs:
1. PSBT Structure - Verify BIP-375 field requirements
2. ECDH Coverage - Verify ECDH share presence and correctness
3. Input Eligibility - Verify input constraints with SP outputs
4. Output Scripts - Verify output scripts match SP derivation
"""

from typing import List, Optional

from .. import ec
from . import dleq
from .fields import SPValidationError
from .ecdh import get_eligible_inputs
from ..transaction import SIGHASH
from ..script import Script


class BIP375Validator:
    """Validates PSBTs for BIP-375 compliance."""

    def __init__(self, psbt):
        """
        Args:
            psbt: A PSBTv2 instance to validate
        """
        self.psbt = psbt
        self.errors = []

    def has_sp_outputs(self) -> bool:
        """Check if PSBT has any SP outputs."""
        return any(out.sp_data is not None for out in self.psbt.outputs)

    def validate(self, skip_output_scripts: bool = False) -> bool:
        """
        Run full 4-stage validation pipeline.

        Args:
            skip_output_scripts: Skip stage 4 (output script validation) if True

        Returns:
            True if validation passes, False otherwise

        Raises:
            SPValidationError: With details of first validation failure
        """
        self.errors = []

        if self.psbt.version != 2:
            # SP fields only allowed in PSBTv2
            if self.has_sp_outputs():
                raise SPValidationError("SP fields only allowed in PSBTv2")
            return True

        # Stage 1: PSBT Structure
        try:
            self._validate_structure()
        except SPValidationError as e:
            raise SPValidationError(f"Structure validation failed: {e}")

        if not self.has_sp_outputs():
            return True

        # Stage 2: ECDH Coverage
        try:
            self._validate_ecdh_coverage()
        except SPValidationError as e:
            raise SPValidationError(f"ECDH coverage validation failed: {e}")

        # Stage 3: Input Eligibility
        try:
            self._validate_input_eligibility()
        except SPValidationError as e:
            raise SPValidationError(f"Input eligibility validation failed: {e}")

        # Stage 4: Output Scripts (optional)
        if not skip_output_scripts:
            try:
                self._validate_output_scripts()
            except SPValidationError as e:
                raise SPValidationError(f"Output script validation failed: {e}")

        return True

    def _validate_structure(self):
        """
        Stage 1: PSBT Structure validation.

        Checks:
        - SP fields only in outputs with PSBT_OUT_SP_V0_INFO
        - Field sizes are correct
        - Dependency relationships are valid
        - Modifiable flags when scripts are set
        """
        for i, out in enumerate(self.psbt.outputs):
            has_sp_info = out.sp_data is not None
            has_sp_label = out.sp_label is not None
            has_script = out.script_pubkey is not None

            # Label requires SP info
            if has_sp_label and not has_sp_info:
                raise SPValidationError(
                    f"Output {i}: PSBT_OUT_SP_V0_LABEL present without PSBT_OUT_SP_V0_INFO"
                )

            # Either script or SP info must be present
            if not has_script and not has_sp_info:
                raise SPValidationError(
                    f"Output {i}: Must have either PSBT_OUT_SCRIPT or PSBT_OUT_SP_V0_INFO"
                )

        # If any SP output has script set, modifiable flags must be 0
        if self.has_sp_outputs():
            for i, out in enumerate(self.psbt.outputs):
                if out.sp_data is not None and out.script_pubkey is not None:
                    # If script is set for SP output, modifiable flags must be 0
                    if (
                        self.psbt.tx_modifiable_flags is not None
                        and self.psbt.tx_modifiable_flags != 0
                    ):
                        raise SPValidationError(
                            f"Output {i}: PSBT_GLOBAL_TX_MODIFIABLE must be 0 when "
                            f"PSBT_OUT_SCRIPT is set for SP output"
                        )

    def _validate_ecdh_coverage(self):
        """
        Stage 2: ECDH Coverage validation.

        For each SP output, verify:
        - All eligible inputs have ECDH shares or global share exists
        - DLEQ proofs exist and verify correctly
        - BIP32 derivations present when needed
        """
        eligible_inputs = get_eligible_inputs(self.psbt.inputs, has_sp_outputs=True)

        for out_idx, out in enumerate(self.psbt.outputs):
            if out.sp_data is None:
                continue  # Not an SP output

            scan_key = out.sp_data.scan_key
            scan_key_bytes = scan_key.sec()

            # Check if global ECDH share exists for this scan key
            has_global_share = scan_key_bytes in self.psbt.sp_ecdh_shares
            has_global_proof = scan_key_bytes in self.psbt.sp_dleq_proofs

            if has_global_share and not has_global_proof:
                raise SPValidationError(
                    f"Output {out_idx}: PSBT_GLOBAL_SP_ECDH_SHARE present without "
                    f"PSBT_GLOBAL_SP_DLEQ"
                )

            if has_global_proof:
                # Verify global DLEQ proof
                if not out.script_pubkey:
                    # Can't verify without script (incomplete PSBT)
                    continue

                self._verify_global_dleq_proof(scan_key_bytes, out_idx, eligible_inputs)
            else:
                # Check per-input ECDH shares
                for inp_idx in eligible_inputs:
                    inp = self.psbt.inputs[inp_idx]

                    if scan_key_bytes not in inp.sp_ecdh_shares:
                        if out.script_pubkey:
                            # Script is set, all eligible inputs must have share
                            raise SPValidationError(
                                f"Output {out_idx}: Input {inp_idx} missing ECDH share "
                                f"for scan key when output script is set"
                            )
                        else:
                            # Incomplete PSBT - this is OK
                            continue

                    if scan_key_bytes not in inp.sp_dleq_proofs:
                        raise SPValidationError(
                            f"Output {out_idx}: Input {inp_idx} has ECDH share but "
                            f"missing DLEQ proof"
                        )

                    # Verify per-input DLEQ proof
                    if out.script_pubkey:  # Can verify only if complete
                        self._verify_input_dleq_proof(inp_idx, scan_key, out_idx)

                    # Check BIP32 derivation for per-input DLEQ.  Only required
                    # when the output script is absent: trimmed/finalized PSBTs
                    # legitimately strip BIP32 derivations, and Stage 4 provides
                    # equivalent verification via the output script in that case.
                    if scan_key_bytes in inp.sp_dleq_proofs:
                        if len(inp.bip32_derivations) == 0 and not out.script_pubkey:
                            raise SPValidationError(
                                f"Output {out_idx}: Input {inp_idx} has DLEQ proof "
                                f"but missing PSBT_IN_BIP32_DERIVATION"
                            )

    def _verify_global_dleq_proof(
        self, scan_key_bytes: bytes, out_idx: int, eligible_inputs: List[int]
    ):
        """Verify a global DLEQ proof."""
        scan_key = ec.PublicKey.parse(scan_key_bytes)
        proof_bytes = self.psbt.sp_dleq_proofs[scan_key_bytes]

        # Reconstruct sum of eligible input public keys
        eligible_pubkeys = []
        for inp_idx in eligible_inputs:
            inp = self.psbt.inputs[inp_idx]
            pubkey = self._get_input_public_key(inp, inp_idx)
            if pubkey:
                eligible_pubkeys.append(pubkey)

        if not eligible_pubkeys:
            raise SPValidationError(
                f"Output {out_idx}: Cannot verify global DLEQ - no eligible inputs "
                f"with public keys"
            )

        # Sum the public keys
        if len(eligible_pubkeys) == 1:
            A_sum = eligible_pubkeys[0]
        else:
            from ..util.secp256k1 import ec_pubkey_combine, ec_pubkey_parse

            pubkey_handles = [ec_pubkey_parse(pk.sec()) for pk in eligible_pubkeys]
            result = pubkey_handles[0]
            for pk_handle in pubkey_handles[1:]:
                result = ec_pubkey_combine(result, pk_handle)
            from ..util.secp256k1 import ec_pubkey_serialize, EC_COMPRESSED

            A_sum = ec.PublicKey.parse(ec_pubkey_serialize(result, EC_COMPRESSED))

        # Get ECDH share as public key
        ecdh_share = self.psbt.sp_ecdh_shares[scan_key_bytes]
        C = ec.PublicKey.parse(ecdh_share)

        # Verify proof
        if not dleq.verify_dleq_proof(
            A_sum.sec(), scan_key.sec(), C.sec(), proof_bytes
        ):
            raise SPValidationError(
                f"Output {out_idx}: Global DLEQ proof verification failed"
            )

    def _verify_input_dleq_proof(
        self, inp_idx: int, scan_key: ec.PublicKey, out_idx: int
    ):
        """Verify a per-input DLEQ proof."""
        inp = self.psbt.inputs[inp_idx]
        scan_key_bytes = scan_key.sec()

        # Get input's public key
        pubkey = self._get_input_public_key(inp, inp_idx)
        if not pubkey:
            # Can't verify without public key
            return

        # Get ECDH share
        ecdh_share = inp.sp_ecdh_shares[scan_key_bytes]
        C = ec.PublicKey.parse(ecdh_share)

        # Get proof
        proof_bytes = inp.sp_dleq_proofs[scan_key_bytes]

        # Verify
        if not dleq.verify_dleq_proof(
            pubkey.sec(), scan_key.sec(), C.sec(), proof_bytes
        ):
            raise SPValidationError(
                f"Output {out_idx}: Per-input DLEQ proof verification failed "
                f"for input {inp_idx}"
            )

    def _get_input_public_key(self, inp, inp_idx: int) -> Optional[ec.PublicKey]:
        """Extract the input's signing public key using hash-matching against the UTXO script.

        Falls back to partial_sigs keys when bip32_derivations is absent (e.g. a
        trimmed PSBT where the signer stripped BIP-32 metadata to save space).
        """
        from ..hashes import hash160

        script = inp.script_pubkey
        if script is None:
            return None

        script_type = script.script_type()

        if script_type == "p2wpkh":
            # script = 0x00 0x14 <20-byte hash160(pubkey)>
            pkh = bytes(script.data[2:22])
            for pubkey in inp.bip32_derivations:
                if hash160(pubkey.sec()) == pkh:
                    return pubkey
            for pubkey in inp.partial_sigs:
                if hash160(pubkey.sec()) == pkh:
                    return pubkey

        elif script_type == "p2pkh":
            # script = 0x76 0xa9 0x14 <20-byte hash160(pubkey)> 0x88 0xac
            pkh = bytes(script.data[3:23])
            for pubkey in inp.bip32_derivations:
                if hash160(pubkey.sec()) == pkh:
                    return pubkey
            for pubkey in inp.partial_sigs:
                if hash160(pubkey.sec()) == pkh:
                    return pubkey

        elif script_type == "p2sh" and inp.redeem_script:
            # P2SH-P2WPKH: redeem script = 0x00 0x14 <20-byte hash160(pubkey)>
            if inp.redeem_script.script_type() == "p2wpkh":
                pkh = bytes(inp.redeem_script.data[2:22])
                for pubkey in inp.bip32_derivations:
                    if hash160(pubkey.sec()) == pkh:
                        return pubkey
                for pubkey in inp.partial_sigs:
                    if hash160(pubkey.sec()) == pkh:
                        return pubkey

        return None

    def _validate_input_eligibility(self):
        """
        Stage 3: Input Eligibility validation.

        Checks:
        - No Segwit v>1 inputs with SP outputs
        - Only SIGHASH_ALL (if specified)
        """
        # Get eligible inputs - this will raise if Segwit v>1 found
        try:
            get_eligible_inputs(self.psbt.inputs, has_sp_outputs=True)
        except Exception as e:
            raise SPValidationError(f"Invalid input for SP: {e}")

        # Check sighash types
        for i, inp in enumerate(self.psbt.inputs):
            if inp.sighash_type is not None:
                # BIP-375: Only SIGHASH_ALL allowed with SP outputs
                if inp.sighash_type != SIGHASH.ALL:
                    raise SPValidationError(
                        f"Input {i}: Non-SIGHASH_ALL sighash type with SP outputs"
                    )

    def _validate_output_scripts(self):
        """
        Stage 4: Output Scripts validation.

        For each SP output:
        - Verify script is correctly derived from SP data and ECDH shares
        - Verify sorting of outputs by scan/spend keys
        """
        from ..hashes import tagged_hash
        from ..transaction import COutPoint
        from .bip352 import get_input_hash
        from ..util.secp256k1 import (
            ec_pubkey_combine,
            ec_pubkey_parse,
            ec_pubkey_serialize,
            ec_pubkey_tweak_add,
            ec_pubkey_tweak_mul,
            EC_COMPRESSED,
        )

        # Get eligible inputs
        eligible_inputs = get_eligible_inputs(self.psbt.inputs, has_sp_outputs=True)

        # Build outpoints and A_sum for input_hash (same for all scan-key groups).
        outpoints = [
            COutPoint(txid=self.psbt.tx.vin[i].txid, out_idx=self.psbt.tx.vin[i].vout)
            for i in eligible_inputs
        ]
        eligible_pubkeys = [
            self._get_input_public_key(self.psbt.inputs[i], i)
            for i in eligible_inputs
        ]
        eligible_pubkeys = [pk for pk in eligible_pubkeys if pk is not None]
        if not eligible_pubkeys:
            raise SPValidationError(
                "Cannot validate output scripts: no eligible input public keys found"
            )
        if len(eligible_pubkeys) == 1:
            A_sum_handle = ec_pubkey_parse(eligible_pubkeys[0].sec())
        else:
            A_sum_handle = ec_pubkey_parse(eligible_pubkeys[0].sec())
            for pk in eligible_pubkeys[1:]:
                A_sum_handle = ec_pubkey_combine(A_sum_handle, ec_pubkey_parse(pk.sec()))
        A_sum_bytes = ec_pubkey_serialize(A_sum_handle, EC_COMPRESSED)
        input_hash = get_input_hash(outpoints, A_sum_bytes)

        # Group SP outputs by scan key
        sp_outputs_by_scan = {}
        for out_idx, out in enumerate(self.psbt.outputs):
            if out.sp_data is not None:
                scan_key_bytes = out.sp_data.scan_key.sec()
                if scan_key_bytes not in sp_outputs_by_scan:
                    sp_outputs_by_scan[scan_key_bytes] = []
                sp_outputs_by_scan[scan_key_bytes].append((out_idx, out))

        # For each scan key, validate outputs
        for scan_key_bytes, outputs_for_scan in sp_outputs_by_scan.items():
            scan_key = ec.PublicKey.parse(scan_key_bytes)

            # Get ECDH share for this scan key
            ecdh_share = None
            if scan_key_bytes in self.psbt.sp_ecdh_shares:
                ecdh_share = self.psbt.sp_ecdh_shares[scan_key_bytes]
            else:
                # Sum per-input shares
                share_sum = None
                for inp_idx in eligible_inputs:
                    inp = self.psbt.inputs[inp_idx]
                    if scan_key_bytes in inp.sp_ecdh_shares:
                        share = ec_pubkey_parse(inp.sp_ecdh_shares[scan_key_bytes])
                        if share_sum is None:
                            share_sum = share
                        else:
                            share_sum = ec_pubkey_combine(share_sum, share)
                if share_sum is not None:
                    ecdh_share = ec_pubkey_serialize(share_sum, EC_COMPRESSED)

            if not ecdh_share:
                raise SPValidationError(f"No ECDH share found for scan key in outputs")

            # Apply input_hash: adjusted_share = input_hash · ecdh_share (BIP-352)
            adjusted_handle = ec_pubkey_parse(ecdh_share)
            ec_pubkey_tweak_mul(adjusted_handle, input_hash)
            adjusted_share = ec_pubkey_serialize(adjusted_handle, EC_COMPRESSED)

            # Sort outputs for this scan key by spend key (lexicographic)
            sorted_outputs = sorted(
                outputs_for_scan,
                key=lambda x: (x[1].sp_data.spend_key.sec()),
            )

            # Validate each output's script
            for pos, (out_idx, out) in enumerate(sorted_outputs):
                if out.script_pubkey is None:
                    # Incomplete PSBT
                    continue

                label = out.sp_label
                spend_key = out.sp_data.spend_key

                # Compute t_k using full 33-byte adjusted share (BIP-352)
                t_k = tagged_hash(
                    "BIP0352/SharedSecret",
                    adjusted_share + pos.to_bytes(4, "big"),
                )

                # Handle label
                if label is not None and label != 0:
                    label_bytes = label.to_bytes(4, "big")
                    label_tweak = tagged_hash(
                        "BIP0352/Label", scan_key.sec() + label_bytes
                    )
                    spend_internal = ec_pubkey_parse(spend_key.sec())
                    ec_pubkey_tweak_add(spend_internal, label_tweak)
                    spend_tweaked = ec_pubkey_serialize(spend_internal, EC_COMPRESSED)
                else:
                    spend_tweaked = spend_key.sec()

                p_internal = ec_pubkey_parse(spend_tweaked)
                ec_pubkey_tweak_add(p_internal, t_k)
                p_pubkey = ec_pubkey_serialize(p_internal, EC_COMPRESSED)

                expected_script = Script(b"\x51\x20" + p_pubkey[1:])

                # Compare with actual script
                if out.script_pubkey.serialize() != expected_script.serialize():
                    raise SPValidationError(
                        f"Output {out_idx}: Script does not match derived "
                        f"silent payment script"
                    )


def validate_bip375_psbt(psbt, skip_output_scripts: bool = False) -> bool:
    """
    Validate a PSBT for BIP-375 compliance.

    Args:
        psbt: A PSBTv2 instance
        skip_output_scripts: Skip output script validation if True

    Returns:
        True if valid

    Raises:
        SPValidationError: With validation error details
    """
    validator = BIP375Validator(psbt)
    return validator.validate(skip_output_scripts=skip_output_scripts)
