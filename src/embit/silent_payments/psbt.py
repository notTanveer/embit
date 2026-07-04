"""
SP-aware PSBT scopes and subclass.

Sections:
  1. SPInputScope / SPOutputScope — per-input/output BIP-375 field handlers
  2. SilentPaymentsPSBT — PSBT subclass with global SP fields and sign_with() SP hook
  3. finalize_sp_spends — BIP-376 finalizer for SP spend inputs
"""

import io
from collections import OrderedDict

from .. import ec
from ..base import EmbitError
from ..script import Script, Witness
from ..psbt import (
    PSBT,
    DerivationPath,
    InputScope,
    OutputScope,
    PSBTError,
    SIGHASH,
    derive_hdkey,
    read_string,
    resolve_signing_root,
    ser_string,
)
from . import dleq
from .bip352 import (
    derive_outputs_for_keys,
    compute_ecdh_share,
)
from .ecdh import (
    all_outpoints,
    compute_dleq_proof,
    compute_global_dleq_proof,
    derive_sp_output_scripts,
    get_eligible_inputs,
    group_sp_outputs_by_scan_key,
    match_sp_spend_base,
    input_public_key,
    resolve_input_privkey,
)
from .fields import SilentPaymentData, SPFieldError, SPValidationError

# ── scopes ────────────────────────────────────────────────────────────────────


class SPInputScope(InputScope):
    def __init__(self, *args, **kwargs):
        self.sp_ecdh_shares = OrderedDict()  # scan_key -> ecdh_share (33 bytes)
        self.sp_dleq_proofs = OrderedDict()  # scan_key -> dleq_proof (64 bytes)
        self.sp_spend_bip32_derivations = OrderedDict()  # pub_bytes -> DerivationPath
        self.sp_tweak = None  # 32 bytes or None
        super().__init__(*args, **kwargs)

    def clear_metadata(self, *args, **kwargs):
        super().clear_metadata(*args, **kwargs)
        self.sp_ecdh_shares = OrderedDict()
        self.sp_dleq_proofs = OrderedDict()
        self.sp_spend_bip32_derivations = OrderedDict()
        self.sp_tweak = None

    def update(self, other):
        super().update(other)
        if isinstance(other, SPInputScope):
            self.sp_ecdh_shares.update(other.sp_ecdh_shares)
            self.sp_dleq_proofs.update(other.sp_dleq_proofs)
            self.sp_spend_bip32_derivations.update(other.sp_spend_bip32_derivations)
            self.sp_tweak = other.sp_tweak or self.sp_tweak

    def read_value(self, stream, k, version=None):
        if k[0] == 0x1D:  # PSBT_IN_SP_ECDH_SHARE (BIP-375)
            v = read_string(stream)
            if version != 2:
                raise PSBTError("PSBT_IN_SP_ECDH_SHARE not allowed in PSBTv0")
            if len(k) != 34:
                raise PSBTError("Invalid PSBT_IN_SP_ECDH_SHARE key length")
            if len(v) != 33:
                raise PSBTError("PSBT_IN_SP_ECDH_SHARE value must be 33 bytes")
            scan_key = k[1:]
            if scan_key in self.sp_ecdh_shares:
                raise PSBTError("Duplicated PSBT_IN_SP_ECDH_SHARE for scan key")
            self.sp_ecdh_shares[scan_key] = v
        elif k[0] == 0x1E:  # PSBT_IN_SP_DLEQ (BIP-375)
            v = read_string(stream)
            if version != 2:
                raise PSBTError("PSBT_IN_SP_DLEQ not allowed in PSBTv0")
            if len(k) != 34:
                raise PSBTError("Invalid PSBT_IN_SP_DLEQ key length")
            if len(v) != 64:
                raise PSBTError("PSBT_IN_SP_DLEQ value must be 64 bytes")
            scan_key = k[1:]
            if scan_key in self.sp_dleq_proofs:
                raise PSBTError("Duplicated PSBT_IN_SP_DLEQ for scan key")
            self.sp_dleq_proofs[scan_key] = v
        elif k[0] == 0x1F:  # PSBT_IN_SP_SPEND_BIP32_DERIVATION (BIP-376)
            v = read_string(stream)
            if version != 2:
                raise PSBTError(
                    "PSBT_IN_SP_SPEND_BIP32_DERIVATION not allowed in PSBTv0"
                )
            if len(k) != 34:
                raise PSBTError("Invalid PSBT_IN_SP_SPEND_BIP32_DERIVATION key length")
            pub_bytes = k[1:]
            if pub_bytes in self.sp_spend_bip32_derivations:
                raise PSBTError(
                    "Duplicated PSBT_IN_SP_SPEND_BIP32_DERIVATION for pubkey"
                )
            self.sp_spend_bip32_derivations[pub_bytes] = DerivationPath.read_from(
                io.BytesIO(v)
            )
        elif k == b"\x20":  # PSBT_IN_SP_TWEAK (BIP-376)
            v = read_string(stream)
            if version != 2:
                raise PSBTError("PSBT_IN_SP_TWEAK not allowed in PSBTv0")
            if len(v) != 32:
                raise PSBTError("PSBT_IN_SP_TWEAK value must be 32 bytes")
            if self.sp_tweak is not None:
                raise PSBTError("Duplicated PSBT_IN_SP_TWEAK")
            self.sp_tweak = v
        else:
            super().read_value(stream, k, version=version)

    def write_to(self, stream, skip_separator=False, version=None, **kwargs) -> int:
        r = super().write_to(stream, skip_separator=True, version=version, **kwargs)
        if version == 2:
            for scan_key in self.sp_ecdh_shares:
                r += ser_string(stream, b"\x1d" + scan_key)
                r += ser_string(stream, self.sp_ecdh_shares[scan_key])
            for scan_key in self.sp_dleq_proofs:
                r += ser_string(stream, b"\x1e" + scan_key)
                r += ser_string(stream, self.sp_dleq_proofs[scan_key])
            for pub_bytes, derivation in self.sp_spend_bip32_derivations.items():
                r += ser_string(stream, b"\x1f" + pub_bytes)
                r += ser_string(stream, derivation.serialize())
            if self.sp_tweak is not None:
                r += ser_string(stream, b"\x20")
                r += ser_string(stream, self.sp_tweak)
        if not skip_separator:
            r += stream.write(b"\x00")
        return r


class SPOutputScope(OutputScope):
    def __init__(self, *args, **kwargs):
        self.sp_data = None  # SilentPaymentData (PSBT_OUT_SP_V0_INFO)
        self.sp_label = None  # uint32 label (PSBT_OUT_SP_V0_LABEL)
        super().__init__(*args, **kwargs)

    def clear_metadata(self, *args, **kwargs):
        super().clear_metadata(*args, **kwargs)
        self.sp_data = None
        self.sp_label = None

    def update(self, other):
        super().update(other)
        if isinstance(other, SPOutputScope):
            self.sp_data = other.sp_data or self.sp_data
            self.sp_label = (
                other.sp_label if other.sp_label is not None else self.sp_label
            )

    def read_value(self, stream, k, version=None):
        if k == b"\x09":  # PSBT_OUT_SP_V0_INFO (BIP-375)
            v = read_string(stream)
            if version != 2:
                raise PSBTError("PSBT_OUT_SP_V0_INFO not allowed in PSBTv0")
            if len(v) != 66:
                raise PSBTError("PSBT_OUT_SP_V0_INFO must be 66 bytes")
            if self.sp_data is not None:
                raise PSBTError("Duplicated PSBT_OUT_SP_V0_INFO")
            try:
                self.sp_data = SilentPaymentData.parse(v)
            except SPFieldError as e:
                raise PSBTError("Invalid PSBT_OUT_SP_V0_INFO: {}".format(e))
        elif k == b"\x0a":  # PSBT_OUT_SP_V0_LABEL (BIP-375)
            v = read_string(stream)
            if version != 2:
                raise PSBTError("PSBT_OUT_SP_V0_LABEL not allowed in PSBTv0")
            if len(v) != 4:
                raise PSBTError("PSBT_OUT_SP_V0_LABEL must be 4 bytes")
            if self.sp_label is not None:
                raise PSBTError("Duplicated PSBT_OUT_SP_V0_LABEL")
            self.sp_label = int.from_bytes(v, "little")
        else:
            super().read_value(stream, k, version=version)

    def write_to(self, stream, skip_separator=False, version=None, **kwargs) -> int:
        r = super().write_to(stream, skip_separator=True, version=version, **kwargs)
        if version == 2:
            if self.sp_data is not None:
                r += ser_string(stream, b"\x09")
                r += ser_string(stream, self.sp_data.serialize())
            if self.sp_label is not None:
                r += ser_string(stream, b"\x0a")
                r += ser_string(stream, self.sp_label.to_bytes(4, "little"))
        if not skip_separator:
            r += stream.write(b"\x00")
        return r


# ── PSBT subclass ─────────────────────────────────────────────────────────────


class SilentPaymentsPSBT(PSBT):
    PSBTIN_CLS = SPInputScope
    PSBTOUT_CLS = SPOutputScope

    def __init__(self, *args, **kwargs):
        self.sp_ecdh_shares = OrderedDict()  # scan_key -> ecdh_share (33 bytes)
        self.sp_dleq_proofs = OrderedDict()  # scan_key -> dleq_proof (64 bytes)
        super().__init__(*args, **kwargs)

    @property
    def has_sp_outputs(self) -> bool:
        """Whether this PSBT has any Silent Payment output (BIP-375)."""
        return any(out.sp_data is not None for out in self.outputs)

    @property
    def has_sp_spend_inputs(self) -> bool:
        """Whether this PSBT has any input spending a previously-received
        Silent Payment output (BIP-376)."""
        return any(inp.sp_tweak is not None for inp in self.inputs)

    @property
    def has_sp_content(self) -> bool:
        """Whether this PSBT carries any Silent Payment data at all (send or spend)."""
        return self.has_sp_outputs or self.has_sp_spend_inputs

    @classmethod
    def _validate_v2_output(cls, out, i):
        """Same as PSBT._validate_v2_output, but SP outputs may omit
        PSBT_OUT_SCRIPT (the taproot script is derived from ECDH shares, not
        known up front). Used by both the parser and add_output() (see
        base PSBT.add_output)."""
        if out.value is None:
            raise PSBTError(
                "PSBTv2 output %d missing required PSBT_OUT_AMOUNT (0x03)" % i
            )
        if out.script_pubkey is None and out.sp_data is None:
            raise PSBTError(
                "PSBTv2 output %d missing required PSBT_OUT_SCRIPT (0x04)" % i
            )

    def parse_unknowns(self):
        super().parse_unknowns()
        for k in list(self.unknown):
            if k[0] == 0x07 and len(k) == 34:  # PSBT_GLOBAL_SP_ECDH_SHARE
                if self.version != 2:
                    continue
                v = self.unknown.pop(k)
                if len(v) != 33:
                    raise PSBTError("PSBT_GLOBAL_SP_ECDH_SHARE value must be 33 bytes")
                scan_key = k[1:]
                if scan_key in self.sp_ecdh_shares:
                    raise PSBTError("Duplicated PSBT_GLOBAL_SP_ECDH_SHARE for scan key")
                self.sp_ecdh_shares[scan_key] = v
            elif k[0] == 0x08 and len(k) == 34:  # PSBT_GLOBAL_SP_DLEQ
                if self.version != 2:
                    continue
                v = self.unknown.pop(k)
                if len(v) != 64:
                    raise PSBTError("PSBT_GLOBAL_SP_DLEQ value must be 64 bytes")
                scan_key = k[1:]
                if scan_key in self.sp_dleq_proofs:
                    raise PSBTError("Duplicated PSBT_GLOBAL_SP_DLEQ for scan key")
                self.sp_dleq_proofs[scan_key] = v

    def _write_extra_globals(self, stream) -> int:
        r = 0
        if self.version == 2:
            for scan_key in self.sp_ecdh_shares:
                r += ser_string(stream, b"\x07" + scan_key)
                r += ser_string(stream, self.sp_ecdh_shares[scan_key])
            for scan_key in self.sp_dleq_proofs:
                r += ser_string(stream, b"\x08" + scan_key)
                r += ser_string(stream, self.sp_dleq_proofs[scan_key])
        return r

    def sign_with(self, root, sighash=None, with_sp_shares=True, **kwargs):
        has_sp = self.version == 2 and self.has_sp_outputs
        # BIP-375: only SIGHASH_ALL may be used when SP outputs are present.
        # SIGHASH.DEFAULT (taproot) is functionally SIGHASH_ALL.
        if (
            has_sp
            and sighash is not None
            and sighash not in (SIGHASH.ALL, SIGHASH.DEFAULT)
        ):
            raise SPValidationError(
                "Silent payment signing requires SIGHASH_ALL"
            )
        if sighash is not None:
            counter = super().sign_with(root, sighash=sighash, **kwargs)
        else:
            counter = super().sign_with(root, **kwargs)
        if has_sp and with_sp_shares:
            counter += self._sign_with_sp(root)
        if self.version == 2:
            counter += self._sign_sp_spends(root)
        return counter

    @staticmethod
    def _signing_fingerprint(root):
        """Resolve the signing fingerprint for ``root``.

        Returns ``(fingerprint, can_sign)``.  ``fingerprint`` is None for raw/WIF
        keys (which match by key material instead).  ``can_sign`` is False when
        ``root`` is a public-only descriptor key that cannot produce signatures.
        """
        fingerprint, can_sign, _root = resolve_signing_root(root)
        return fingerprint, can_sign

    def sign_input_with_sp_tweak(
        self,
        key: "ec.PrivateKey",
        input_index: int,
        inp=None,
        sighash=SIGHASH.DEFAULT,
    ) -> int:
        """BIP-376: sign a Silent Payment spend input using sp_tweak field."""
        inp = inp or self.inputs[input_index]
        sp_tweak = getattr(inp, "sp_tweak", None)
        if sp_tweak is None:
            return 0
        if not inp.is_taproot:
            return 0
        try:
            pk = key.sp_spend_tweak(sp_tweak)
        except (EmbitError, ValueError):
            return 0
        output_xonly = inp.utxo.script_pubkey.data[2:34]
        if pk.xonly() != output_xonly:
            return 0
        h = self.sighash(input_index, sighash=sighash)
        sig = pk.schnorr_sign(h)
        sigdata = sig.serialize()
        if sighash != SIGHASH.DEFAULT:
            sigdata += bytes([sighash])
        inp.taproot_key_sig = sigdata
        return 1

    def _sign_sp_spends(self, root) -> int:
        """BIP-376: sign inputs that carry sp_tweak using sp_spend_bip32_derivations."""
        fingerprint, can_sign = self._signing_fingerprint(root)
        if not can_sign:
            return 0

        counter = 0
        for i, inp in enumerate(self.inputs):
            if getattr(inp, "sp_tweak", None) is None:
                continue
            if inp.taproot_key_sig is not None:
                continue

            priv_key = match_sp_spend_base(inp, root, fingerprint, derive_hdkey)
            if priv_key is None:
                continue

            counter += self.sign_input_with_sp_tweak(priv_key, i, inp)

        return counter

    def _verify_existing_sp_shares(self, eligible, scan_keys) -> None:
        """Verify DLEQ proofs of ECDH shares already present on eligible inputs.

        Raises SPValidationError if a present share lacks a proof or its proof
        fails to verify against the input's public key.
        """
        for i in eligible:
            inp = self.inputs[i]
            pubkey = input_public_key(inp)
            for sk_bytes in scan_keys:
                if sk_bytes not in inp.sp_ecdh_shares:
                    continue
                proof = inp.sp_dleq_proofs.get(sk_bytes)
                if proof is None:
                    raise SPValidationError(
                        "Input %d has an SP ECDH share without a DLEQ proof" % i
                    )
                if pubkey is None:
                    # Cannot resolve the input key to verify; leave the share as
                    # provided (a malformed share is caught later by validation).
                    continue
                if not dleq.verify_dleq_proof(
                    pubkey.sec(), sk_bytes, inp.sp_ecdh_shares[sk_bytes], proof
                ):
                    raise SPValidationError(
                        "Input %d has an invalid SP ECDH share DLEQ proof" % i
                    )

    def _sign_with_sp(self, root, aux_rand=None) -> int:
        """Compute per-input ECDH shares and DLEQ proofs for SP outputs."""
        scan_keys = {}
        for out in self.outputs:
            if out.sp_data is not None:
                sk_bytes = out.sp_data.scan_key.sec()
                if sk_bytes not in scan_keys:
                    scan_keys[sk_bytes] = out.sp_data.scan_key

        if not scan_keys:
            return 0

        eligible = get_eligible_inputs(self.inputs, has_sp_outputs=True)

        if not eligible:
            return 0

        # BIP-375: verify ECDH shares already present (added by other signers)
        # using their DLEQ proofs before contributing our own, so we never
        # endorse an invalid share by adding to the same PSBT.
        self._verify_existing_sp_shares(eligible, scan_keys)

        fingerprint, can_sign = self._signing_fingerprint(root)
        if not can_sign:
            return 0

        counter = 0

        for i in eligible:
            inp = self.inputs[i]

            priv_bytes = resolve_input_privkey(inp, root, fingerprint, derive_hdkey)
            if priv_bytes is None:
                continue

            for sk_bytes, scan_key in scan_keys.items():
                if sk_bytes in inp.sp_ecdh_shares:
                    continue
                share = compute_ecdh_share(priv_bytes, scan_key)
                # verify=False: share was just derived from these exact
                # (priv_bytes, scan_key), so the self-check would only repeat
                # the scalar multiplication we already paid for above.
                proof = compute_dleq_proof(
                    priv_bytes, scan_key, share, aux_rand=aux_rand, verify=False
                )
                inp.sp_ecdh_shares[sk_bytes] = share
                inp.sp_dleq_proofs[sk_bytes] = proof
                counter += 1

        return counter

    def fill_output_scripts(self, eligible=None) -> bool:
        """Derive and assign the taproot scriptPubKey for every SP output
        whose ECDH share is already resolvable (see
        ``ecdh.derive_sp_output_scripts``).

        Returns False (no-op) if any SP output's share isn't yet resolvable
        (an incomplete multi-party PSBT); True otherwise, including the
        no-SP-outputs case.
        """
        sp_out_idxs = [i for i, o in enumerate(self.outputs) if o.sp_data is not None]
        if not sp_out_idxs:
            return True

        resolved = derive_sp_output_scripts(self, eligible=eligible)
        if len(resolved) != len(sp_out_idxs):
            return False

        for out_idx, spk in resolved.items():
            self.outputs[out_idx].script_pubkey = spk
        return True

    def sign_single_party(self, root, aux_rand=None) -> int:
        """BIP-375 single-signer Silent Payment send: this signer controls
        every eligible input and acts as its own output generator.

        Uses the same core derivation as create_outputs (verified against
        BIP-352 test vectors) to compute output scripts and global ECDH
        shares in one pass, then signs every input.

        Raises SPValidationError if an eligible input is not controlled by
        ``root`` (multi-party Silent Payment sends are out of scope for a
        stateless single-party signer), or if no eligible input matches
        ``root`` at all.
        """
        if not (self.version == 2 and self.has_sp_outputs):
            return self.sign_with(root)

        groups = group_sp_outputs_by_scan_key(self.outputs)
        scan_spend_groups = {}
        output_indices = {}
        for sk_bytes, (scan_key, pairs) in groups.items():
            scan_spend_groups[sk_bytes] = (scan_key, [spend_key for _, spend_key in pairs])
            output_indices[sk_bytes] = [out_idx for out_idx, _ in pairs]

        eligible = get_eligible_inputs(self.inputs, has_sp_outputs=True)
        if not eligible:
            raise SPValidationError(
                "Silent Payment send requires at least one eligible input "
                "(P2PKH, P2SH-P2WPKH, P2WPKH, or P2TR)."
            )

        fingerprint, _ = self._signing_fingerprint(root)
        priv_keys = []
        foreign_inputs = []
        for i in eligible:
            priv = resolve_input_privkey(self.inputs[i], root, fingerprint, derive_hdkey)
            if priv is None:
                foreign_inputs.append(i)
            else:
                priv_keys.append(priv)

        if foreign_inputs:
            if priv_keys:
                raise SPValidationError(
                    "Silent Payment signing failed: input(s) {} belong to another "
                    "signer; multi-party Silent Payment sends are not "
                    "supported.".format(
                        ", ".join(str(i) for i in foreign_inputs)
                    )
                )
            raise SPValidationError(
                "Silent Payment signing failed: no eligible input is controlled "
                "by this seed (check derivation / fingerprint)."
            )

        self.sp_ecdh_shares.clear()
        self.sp_dleq_proofs.clear()
        for inp in self.inputs:
            inp.sp_ecdh_shares.clear()
            inp.sp_dleq_proofs.clear()

        outpoints = all_outpoints(self)

        derivation = derive_outputs_for_keys(
            priv_keys, outpoints, scan_spend_groups
        )
        if derivation is None:
            raise SPValidationError(
                "Silent Payment signing failed: private key sum is zero."
            )

        a_sum_bytes, results = derivation

        for sk_bytes, (ecdh_share, outputs) in results.items():
            self.sp_ecdh_shares[sk_bytes] = ecdh_share
            scan_key = scan_spend_groups[sk_bytes][0]
            self.sp_dleq_proofs[sk_bytes] = compute_global_dleq_proof(
                priv_keys, scan_key, ecdh_share,
                aux_rand=aux_rand, verify=False, _a_sum_bytes=a_sum_bytes,
            )
            for pos, out_idx in enumerate(output_indices[sk_bytes]):
                self.outputs[out_idx].script_pubkey = Script(
                    b"\x51\x20" + outputs[pos]
                )

        return self.sign_with(root, with_sp_shares=False)


# ── BIP-376 finalizer ───────────────────────────────────────────────────────────


def finalize_sp_spends(psbt) -> int:
    """
    BIP-376 Finalizer: for each signed SP spend input, construct the final
    scriptwitness from taproot_key_sig and clear SP-specific fields.

    Returns number of inputs finalized.
    """
    count = 0
    for inp in psbt.inputs:
        if getattr(inp, "sp_tweak", None) is None:
            continue
        if inp.taproot_key_sig is None:
            continue
        inp.final_scriptwitness = Witness([inp.taproot_key_sig])
        inp.taproot_key_sig = None
        inp.sp_tweak = None
        inp.sp_spend_bip32_derivations = OrderedDict()
        count += 1
    return count
