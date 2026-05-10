"""
BIP-375 and BIP-376: Silent Payments PSBT extensions.

BIP-375 defines PSBT fields for coordinating ECDH share computation and DLEQ
proof generation/verification needed to derive silent payment output scripts.

BIP-376 defines PSBT fields for silent payment signer support: the SP tweak
and spend key BIP-32 derivation info needed to sign a silent payment output.

This module provides subclasses of embit's core PSBT classes that add support
for these fields, following the same pattern as embit.liquid.pset.

References:
  https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki
  https://github.com/bitcoin/bips/blob/master/bip-0376.mediawiki
"""

from collections import OrderedDict
from io import BytesIO

from .. import compact
from ..psbt import (
    PSBT,
    InputScope,
    OutputScope,
    DerivationPath,
    PSBTError,
    CompressMode,
    TxModifiable,
    ser_string,
    read_string,
)
from ..transaction import SIGHASH
from ..bip374 import generate_dleq_proof, verify_dleq_proof, DLEQError
from ..util.secp256k1 import (
    ec_pubkey_create,
    ec_pubkey_parse,
    ec_pubkey_serialize,
    ec_pubkey_tweak_mul,
    EC_COMPRESSED,
)

# ---------------------------------------------------------------------------
# BIP-375 global field types
# ---------------------------------------------------------------------------
# key: b"\x07" + 33-byte scan pubkey  |  value: 33-byte ECDH share
PSBT_GLOBAL_SP_ECDH_SHARE = 0x07
# key: b"\x08" + 33-byte scan pubkey  |  value: 64-byte DLEQ proof
PSBT_GLOBAL_SP_DLEQ = 0x08

# ---------------------------------------------------------------------------
# BIP-375 per-input field types
# ---------------------------------------------------------------------------
# key: b"\x1d" + 33-byte scan pubkey  |  value: 33-byte ECDH share
PSBT_IN_SP_ECDH_SHARE = 0x1D
# key: b"\x1e" + 33-byte scan pubkey  |  value: 64-byte DLEQ proof
PSBT_IN_SP_DLEQ = 0x1E

# ---------------------------------------------------------------------------
# BIP-375 per-output field types
# ---------------------------------------------------------------------------
# key: b"\x09"  |  value: 33-byte scan || 33-byte spend (66 bytes total)
PSBT_OUT_SP_V0_INFO = 0x09
# key: b"\x0a"  |  value: 4-byte LE uint32 label index
PSBT_OUT_SP_V0_LABEL = 0x0A

# ---------------------------------------------------------------------------
# BIP-376 per-input field types
# ---------------------------------------------------------------------------
# key: b"\x1f" + 33-byte spend pubkey  |  value: fingerprint (4) + path (n*4)
PSBT_IN_SP_SPEND_BIP32_DERIVATION = 0x1F
# key: b"\x20"  |  value: 32-byte tweak scalar
PSBT_IN_SP_TWEAK = 0x20


class SPInputScope(InputScope):
    """
    InputScope extended with BIP-375 ECDH share / DLEQ proof fields and
    BIP-376 silent payment spend derivation / tweak fields.
    """

    def __init__(self, unknown=None, vin=None, compress=CompressMode.KEEP_ALL):
        # Initialize SP fields before super().__init__ calls parse_unknowns()
        self.sp_ecdh_shares = OrderedDict()  # scan_pub_bytes → 33-byte share
        self.sp_dleq_proofs = OrderedDict()  # scan_pub_bytes → 64-byte proof
        self.sp_spend_bip32_derivations = (
            OrderedDict()
        )  # spend_pub_bytes → DerivationPath
        self.sp_tweak = None  # 32 bytes or None
        super().__init__(
            unknown if unknown is not None else {}, vin=vin, compress=compress
        )

    def read_value(self, stream, k, version=None):
        key_type = k[0] if k else None

        if key_type == PSBT_IN_SP_ECDH_SHARE and len(k) == 34:
            if version != 2:
                raise PSBTError("PSBT_IN_SP_ECDH_SHARE requires PSBTv2")
            scan_pub_bytes = bytes(k[1:])
            v = read_string(stream)
            if len(v) != 33:
                raise PSBTError("SP ECDH share must be 33 bytes")
            if scan_pub_bytes in self.sp_ecdh_shares:
                raise PSBTError("Duplicate PSBT_IN_SP_ECDH_SHARE key")
            self.sp_ecdh_shares[scan_pub_bytes] = v

        elif key_type == PSBT_IN_SP_DLEQ and len(k) == 34:
            if version != 2:
                raise PSBTError("PSBT_IN_SP_DLEQ requires PSBTv2")
            scan_pub_bytes = bytes(k[1:])
            v = read_string(stream)
            if len(v) != 64:
                raise PSBTError("SP DLEQ proof must be 64 bytes")
            if scan_pub_bytes in self.sp_dleq_proofs:
                raise PSBTError("Duplicate PSBT_IN_SP_DLEQ key")
            self.sp_dleq_proofs[scan_pub_bytes] = v

        elif key_type == PSBT_IN_SP_SPEND_BIP32_DERIVATION and len(k) == 34:
            spend_pub_bytes = bytes(k[1:])
            v = read_string(stream)
            if spend_pub_bytes in self.sp_spend_bip32_derivations:
                raise PSBTError("Duplicate PSBT_IN_SP_SPEND_BIP32_DERIVATION key")
            self.sp_spend_bip32_derivations[spend_pub_bytes] = DerivationPath.parse(v)

        elif k == b"\x20":  # PSBT_IN_SP_TWEAK
            if version != 2:
                raise PSBTError("PSBT_IN_SP_TWEAK requires PSBTv2")
            v = read_string(stream)
            if len(v) != 32:
                raise PSBTError("SP tweak must be 32 bytes")
            if self.sp_tweak is not None:
                raise PSBTError("Duplicate PSBT_IN_SP_TWEAK key")
            self.sp_tweak = v

        else:
            super().read_value(stream, k, version=version)

    def write_to(self, stream, skip_separator=False, version=None, **kwargs):
        r = super().write_to(stream, skip_separator=True, version=version, **kwargs)

        if version == 2:
            for scan_pub_bytes, share in self.sp_ecdh_shares.items():
                r += ser_string(stream, bytes([PSBT_IN_SP_ECDH_SHARE]) + scan_pub_bytes)
                r += ser_string(stream, share)
            for scan_pub_bytes, proof in self.sp_dleq_proofs.items():
                r += ser_string(stream, bytes([PSBT_IN_SP_DLEQ]) + scan_pub_bytes)
                r += ser_string(stream, proof)
            for spend_pub_bytes, der in self.sp_spend_bip32_derivations.items():
                r += ser_string(
                    stream, bytes([PSBT_IN_SP_SPEND_BIP32_DERIVATION]) + spend_pub_bytes
                )
                r += ser_string(stream, der.serialize())
            if self.sp_tweak is not None:
                r += ser_string(stream, b"\x20")
                r += ser_string(stream, self.sp_tweak)

        if not skip_separator:
            r += stream.write(b"\x00")
        return r


class SPOutputScope(OutputScope):
    """
    OutputScope extended with BIP-375 silent payment output info fields.
    """

    def __init__(self, unknown=None, vout=None, compress=CompressMode.KEEP_ALL):
        self.sp_v0_info = None  # (scan_bytes: bytes, spend_bytes: bytes) or None
        self.sp_v0_label = None  # int or None
        super().__init__(
            unknown if unknown is not None else {}, vout=vout, compress=compress
        )

    @property
    def is_sp_output(self):
        """True if this output has a BIP-375 SP v0 info field."""
        return self.sp_v0_info is not None

    def read_value(self, stream, k, version=None):
        if k == b"\x09":  # PSBT_OUT_SP_V0_INFO
            if version != 2:
                raise PSBTError("PSBT_OUT_SP_V0_INFO requires PSBTv2")
            v = read_string(stream)
            if len(v) != 66:
                raise PSBTError(
                    "PSBT_OUT_SP_V0_INFO must be 66 bytes (33 scan + 33 spend)"
                )
            if self.sp_v0_info is not None:
                raise PSBTError("Duplicate PSBT_OUT_SP_V0_INFO key")
            self.sp_v0_info = (bytes(v[:33]), bytes(v[33:]))

        elif k == b"\x0a":  # PSBT_OUT_SP_V0_LABEL
            if version != 2:
                raise PSBTError("PSBT_OUT_SP_V0_LABEL requires PSBTv2")
            v = read_string(stream)
            if len(v) != 4:
                raise PSBTError("PSBT_OUT_SP_V0_LABEL must be 4 bytes")
            if self.sp_v0_label is not None:
                raise PSBTError("Duplicate PSBT_OUT_SP_V0_LABEL key")
            self.sp_v0_label = int.from_bytes(v, "little")

        else:
            super().read_value(stream, k, version=version)

    def write_to(self, stream, skip_separator=False, version=None, **kwargs):
        r = super().write_to(stream, skip_separator=True, version=version, **kwargs)

        if version == 2:
            if self.sp_v0_info is not None:
                scan_bytes, spend_bytes = self.sp_v0_info
                r += ser_string(stream, b"\x09")
                r += ser_string(stream, scan_bytes + spend_bytes)
            if self.sp_v0_label is not None:
                r += ser_string(stream, b"\x0a")
                r += ser_string(stream, self.sp_v0_label.to_bytes(4, "little"))

        if not skip_separator:
            r += stream.write(b"\x00")
        return r


class SilentPaymentsPSBT(PSBT):
    """
    PSBT subclass with BIP-375 and BIP-376 silent payment field support.

    Extends the base PSBT to:
      - Store and serialize global SP ECDH shares and DLEQ proofs (BIP-375)
      - Store and serialize per-input SP ECDH shares, DLEQ proofs, SP tweaks,
        and SP spend BIP-32 derivation paths (BIP-375 + BIP-376)
      - Store and serialize per-output SP v0 info and label fields (BIP-375)
      - Provide helpers for DLEQ verification and SP output script computation
    """

    PSBTIN_CLS = SPInputScope
    PSBTOUT_CLS = SPOutputScope

    def __init__(self, tx=None, unknown=None, version=None):
        # Initialize SP global fields before super().__init__ calls parse_unknowns()
        self.sp_ecdh_shares = OrderedDict()  # scan_pub_bytes → 33-byte share
        self.sp_dleq_proofs = OrderedDict()  # scan_pub_bytes → 64-byte proof
        super().__init__(tx, unknown if unknown is not None else {}, version)

    def parse_unknowns(self):
        super().parse_unknowns()
        for k in list(self.unknown):
            if len(k) == 34 and k[0] == PSBT_GLOBAL_SP_ECDH_SHARE:
                scan_pub_bytes = bytes(k[1:])
                if scan_pub_bytes in self.sp_ecdh_shares:
                    raise PSBTError("Duplicate PSBT_GLOBAL_SP_ECDH_SHARE key")
                self.sp_ecdh_shares[scan_pub_bytes] = self.unknown.pop(k)
            elif len(k) == 34 and k[0] == PSBT_GLOBAL_SP_DLEQ:
                scan_pub_bytes = bytes(k[1:])
                if scan_pub_bytes in self.sp_dleq_proofs:
                    raise PSBTError("Duplicate PSBT_GLOBAL_SP_DLEQ key")
                self.sp_dleq_proofs[scan_pub_bytes] = self.unknown.pop(k)

    def write_to(self, stream) -> int:
        # magic bytes
        r = stream.write(self.MAGIC)

        if self.version != 2:
            # unsigned tx flag + serialized tx
            r += stream.write(b"\x01\x00")
            tx = self.tx.serialize()
            r += ser_string(stream, tx)

        # xpubs
        from .. import bip32

        for xpub in self.xpubs:
            r += ser_string(stream, b"\x01" + xpub.serialize())
            r += ser_string(stream, self.xpubs[xpub].serialize())

        if self.version == 2:
            if self.tx_version is not None:
                r += ser_string(stream, b"\x02")
                r += ser_string(stream, self.tx_version.to_bytes(4, "little"))
            if self.locktime is not None:
                r += ser_string(stream, b"\x03")
                r += ser_string(stream, self.locktime.to_bytes(4, "little"))
            r += ser_string(stream, b"\x04")
            r += ser_string(stream, compact.to_bytes(len(self.inputs)))
            r += ser_string(stream, b"\x05")
            r += ser_string(stream, compact.to_bytes(len(self.outputs)))
            if self.tx_modifiable_flags is not None:
                r += ser_string(stream, b"\x06")
                r += ser_string(stream, bytes([self.tx_modifiable_flags]))
            r += ser_string(stream, b"\xfb")
            r += ser_string(stream, self.version.to_bytes(4, "little"))

            # BIP-375 global SP fields
            for scan_pub_bytes, share in self.sp_ecdh_shares.items():
                r += ser_string(
                    stream, bytes([PSBT_GLOBAL_SP_ECDH_SHARE]) + scan_pub_bytes
                )
                r += ser_string(stream, share)
            for scan_pub_bytes, proof in self.sp_dleq_proofs.items():
                r += ser_string(stream, bytes([PSBT_GLOBAL_SP_DLEQ]) + scan_pub_bytes)
                r += ser_string(stream, proof)

        # remaining unknowns
        for key in self.unknown:
            r += ser_string(stream, key)
            r += ser_string(stream, self.unknown[key])

        # separator
        r += stream.write(b"\x00")

        # inputs and outputs
        for inp in self.inputs:
            r += inp.write_to(stream, version=self.version)
        for out in self.outputs:
            r += out.write_to(stream, version=self.version)

        return r

    # ------------------------------------------------------------------
    # SP helper accessors
    # ------------------------------------------------------------------

    def sp_outputs(self):
        """Return list of outputs that have BIP-375 SP v0 info."""
        return [o for o in self.outputs if o.is_sp_output]

    def has_sp_outputs(self):
        """True if any output has BIP-375 SP v0 info."""
        return any(o.is_sp_output for o in self.outputs)

    # ------------------------------------------------------------------
    # BIP-375: DLEQ proof verification
    # ------------------------------------------------------------------

    def verify_global_dleq_proofs(self) -> bool:
        """
        Verify all global DLEQ proofs (BIP-375 §Global DLEQ Proof).

        The global ECDH share for scan key B_scan is expected to equal the sum
        of all per-input ECDH shares.  Each DLEQ proof proves that the share was
        computed correctly with respect to the corresponding input private key.

        Returns True if all proofs are valid, raises PSBTError if invalid.
        """
        if not self.sp_dleq_proofs:
            return True

        for scan_pub_bytes, proof in self.sp_dleq_proofs.items():
            if scan_pub_bytes not in self.sp_ecdh_shares:
                raise PSBTError(
                    "DLEQ proof present without corresponding ECDH share for scan key"
                )
            share = self.sp_ecdh_shares[scan_pub_bytes]
            # The DLEQ proof is: prove(a, B_scan) where A = a*G and C = a*B_scan = share
            # We need A from the inputs' ECDH derivation — stored in per-input shares
            # For global proofs we look for any per-input share for this scan key to get A
            A_sec = None
            for inp in self.inputs:
                if scan_pub_bytes in inp.sp_ecdh_shares:
                    A_sec = inp.sp_ecdh_shares[scan_pub_bytes]
                    break
            if A_sec is None:
                raise PSBTError(
                    "Cannot verify global DLEQ: no per-input share found for scan key"
                )
            if not verify_dleq_proof(A_sec, scan_pub_bytes, share, proof):
                raise PSBTError("Global DLEQ proof verification failed")

        return True

    def verify_input_dleq_proofs(self) -> bool:
        """
        Verify all per-input DLEQ proofs (BIP-375).

        Each proof proves that the per-input ECDH share was computed as
        a_i * B_scan for the same private key a_i whose public key A_i is
        derivable from the input's signing key.

        Returns True if all proofs valid, raises PSBTError if invalid.
        """
        for i, inp in enumerate(self.inputs):
            for scan_pub_bytes, proof in inp.sp_dleq_proofs.items():
                if scan_pub_bytes not in inp.sp_ecdh_shares:
                    raise PSBTError(f"Input {i}: DLEQ proof present without ECDH share")
                share = inp.sp_ecdh_shares[scan_pub_bytes]

                # Derive A (the input public key) — use witness_utxo script pubkey
                # or the signing pubkey embedded in the partial_sigs / bip32_derivations
                A_sec = self._get_input_pubkey(i, inp)
                if A_sec is None:
                    raise PSBTError(
                        f"Input {i}: cannot determine public key A for DLEQ verification"
                    )
                if not verify_dleq_proof(A_sec, scan_pub_bytes, share, proof):
                    raise PSBTError(f"Input {i}: DLEQ proof verification failed")

        return True

    def _get_input_pubkey(self, i, inp):
        """
        Try to determine the 33-byte compressed signing pubkey for an input.
        Returns bytes or None.
        """
        # Try bip32_derivations first
        if inp.bip32_derivations:
            return next(iter(inp.bip32_derivations))
        # Try taproot internal key
        if inp.taproot_internal_key is not None:
            from .. import ec as _ec

            return inp.taproot_internal_key.sec()
        # Try partial sigs
        if inp.partial_sigs:
            return next(iter(inp.partial_sigs))
        return None

    # ------------------------------------------------------------------
    # BIP-375: compute output script from ECDH shares
    # ------------------------------------------------------------------

    def compute_output_scripts(self, m: bytes = None):
        """
        Compute and set script_pubkey for all SP outputs using the global
        ECDH shares (BIP-375 §Output Script Generation).

        For each SP output (scan_key, spend_key):
          - Retrieve the global ECDH share for scan_key
          - Compute the tweak: t = tagged_hash("BIP0352/SharedSecret", share || output_index)
          - Compute P = spend_key + t*G
          - Set output script_pubkey = OP_1 <P_xonly>

        Args:
            m: optional message bytes used in DLEQ proofs (passed through)
        """
        from .. import hashes as _hashes
        from .. import script as _script

        for out_idx, out in enumerate(self.outputs):
            if not out.is_sp_output:
                continue

            scan_bytes, spend_bytes = out.sp_v0_info

            if scan_bytes not in self.sp_ecdh_shares:
                raise PSBTError(f"Output {out_idx}: no global ECDH share for scan key")

            share = self.sp_ecdh_shares[scan_bytes]

            # BIP-352 §Sending: shared_secret = ecdh_share
            # t_k = int(tagged_hash("BIP0352/SharedSecret", shared_secret || ser32(k))) mod n
            k = out_idx
            k_bytes = k.to_bytes(4, "big")
            t_bytes = _hashes.tagged_hash("BIP0352/SharedSecret", share + k_bytes)

            # Apply optional label tweak
            if out.sp_v0_label is not None:
                label_bytes = out.sp_v0_label.to_bytes(4, "little")
                label_tweak = _hashes.tagged_hash(
                    "BIP0352/Label", spend_bytes + label_bytes
                )
                # Combine: t_bytes = t_bytes + label_tweak (mod n)
                n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
                t_int = (
                    int.from_bytes(t_bytes, "big") + int.from_bytes(label_tweak, "big")
                ) % n
                t_bytes = t_int.to_bytes(32, "big")

            # P = spend_key + t*G  (taproot key path tweak)
            spend_internal = ec_pubkey_parse(spend_bytes)
            t_G = ec_pubkey_create(t_bytes)
            from ..util.secp256k1 import ec_pubkey_combine

            P_internal = ec_pubkey_combine(spend_internal, t_G)
            P_compressed = ec_pubkey_serialize(P_internal, EC_COMPRESSED)
            P_xonly = P_compressed[1:]  # strip 02/03 prefix

            out.script_pubkey = _script.Script.from_raw(b"\x51\x20" + P_xonly)

    # ------------------------------------------------------------------
    # BIP-376: signing override
    # ------------------------------------------------------------------

    def sign_with(self, root, sighash=SIGHASH.DEFAULT):
        """
        Sign the PSBT.

        BIP-376 requires SIGHASH_ALL when signing SP inputs and forbids signing
        if any SP output still lacks a script_pubkey.
        """
        if self.has_sp_outputs():
            # Ensure we use SIGHASH_ALL (BIP-376 §Signer)
            if sighash not in (SIGHASH.DEFAULT, SIGHASH.ALL):
                raise PSBTError("BIP-376: must use SIGHASH_ALL when signing SP outputs")
            sighash = SIGHASH.ALL
            # Refuse to sign if any SP output is missing its script_pubkey
            for i, out in enumerate(self.outputs):
                if out.is_sp_output and out.script_pubkey is None:
                    raise PSBTError(
                        f"BIP-376: output {i} is an SP output but has no script_pubkey; "
                        "call compute_output_scripts() first"
                    )

        return super().sign_with(root, sighash=sighash)

    # ------------------------------------------------------------------
    # BIP-376: add SP tweak and derivation to an input
    # ------------------------------------------------------------------

    def set_sp_tweak(self, input_index: int, tweak: bytes):
        """
        Set the BIP-376 SP tweak on an input (32 bytes).

        The signer uses this tweak to compute the final signing key:
            d = (b_spend + tweak) mod n
        """
        if len(tweak) != 32:
            raise PSBTError("SP tweak must be 32 bytes")
        self.inputs[input_index].sp_tweak = tweak

    def set_sp_spend_derivation(
        self, input_index: int, spend_pub: bytes, derivation: DerivationPath
    ):
        """
        Set the BIP-376 SP spend key BIP-32 derivation on an input.

        Args:
            input_index: which input
            spend_pub:   33-byte compressed spend pubkey
            derivation:  DerivationPath with fingerprint + path
        """
        if len(spend_pub) != 33:
            raise PSBTError("spend_pub must be 33 bytes")
        self.inputs[input_index].sp_spend_bip32_derivations[spend_pub] = derivation

    # ------------------------------------------------------------------
    # BIP-376: add global ECDH share and DLEQ proof for a scan key
    # ------------------------------------------------------------------

    def add_global_ecdh_share(
        self,
        input_privkey_bytes: bytes,
        scan_pub_bytes: bytes,
        aux_rand: bytes = None,
        m: bytes = None,
    ):
        """
        Compute and add the global ECDH share and DLEQ proof for a scan key.

        Computes:
            share = input_privkey * B_scan
            proof = DLEQ.generate(input_privkey, B_scan, aux_rand, m)

        and stores them in self.sp_ecdh_shares and self.sp_dleq_proofs.

        Args:
            input_privkey_bytes: 32-byte private key for this input
            scan_pub_bytes:      33-byte compressed scan public key
            aux_rand:            optional 32-byte auxiliary randomness
            m:                   optional message for DLEQ binding
        """
        if len(input_privkey_bytes) != 32:
            raise PSBTError("input_privkey_bytes must be 32 bytes")
        if len(scan_pub_bytes) != 33:
            raise PSBTError("scan_pub_bytes must be 33 bytes")

        # ECDH: share = privkey * B_scan
        share_internal = ec_pubkey_parse(scan_pub_bytes)
        ec_pubkey_tweak_mul(share_internal, input_privkey_bytes)
        share = ec_pubkey_serialize(share_internal, EC_COMPRESSED)

        # DLEQ proof
        proof = generate_dleq_proof(input_privkey_bytes, scan_pub_bytes, aux_rand, m)

        self.sp_ecdh_shares[scan_pub_bytes] = share
        self.sp_dleq_proofs[scan_pub_bytes] = proof
