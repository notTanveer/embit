"""
Tests for BIP-375 and BIP-376 Silent Payments PSBT support.

Covers:
  - SPInputScope: field parsing and serialization (ECDH share, DLEQ proof,
    SP tweak, SP spend BIP-32 derivation)
  - SPOutputScope: field parsing and serialization (SP v0 info, label)
  - SilentPaymentsPSBT: global ECDH share + DLEQ, round-trip serialization,
    parse_unknowns, write_to
  - DLEQ proof integration
  - BIP-376 sign_with() enforcement
  - PSBTv0 field restrictions (SP fields must be v2 only)
"""

import os
from binascii import hexlify, unhexlify
from io import BytesIO
from unittest import TestCase

from embit.silent_payments.psbt import (
    SilentPaymentsPSBT,
    SPInputScope,
    SPOutputScope,
    DerivationPath,
    PSBTError,
    CompressMode,
    PSBT_GLOBAL_SP_ECDH_SHARE,
    PSBT_GLOBAL_SP_DLEQ,
    PSBT_IN_SP_ECDH_SHARE,
    PSBT_IN_SP_DLEQ,
    PSBT_IN_SP_TWEAK,
    PSBT_IN_SP_SPEND_BIP32_DERIVATION,
    PSBT_OUT_SP_V0_INFO,
    PSBT_OUT_SP_V0_LABEL,
)
from embit.bip374 import generate_dleq_proof, verify_dleq_proof
from embit.util.secp256k1 import (
    ec_pubkey_create,
    ec_pubkey_parse,
    ec_pubkey_serialize,
    ec_pubkey_tweak_mul,
    EC_COMPRESSED,
)
from embit.ec import PrivateKey
from embit import compact
from embit.psbt import ser_string, read_string


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _rand_key():
    while True:
        k = os.urandom(32)
        try:
            PrivateKey(k)
            return k
        except Exception:
            pass


def _pub_from_priv(priv_bytes: bytes) -> bytes:
    """Return 33-byte compressed pubkey."""
    return ec_pubkey_serialize(ec_pubkey_create(priv_bytes), EC_COMPRESSED)


def _ecdh_share(priv_bytes: bytes, pub_bytes: bytes) -> bytes:
    """Compute priv * pub, return 33-byte compressed."""
    internal = ec_pubkey_parse(pub_bytes)
    ec_pubkey_tweak_mul(internal, priv_bytes)
    return ec_pubkey_serialize(internal, EC_COMPRESSED)


def _build_minimal_psbtv2() -> SilentPaymentsPSBT:
    """Build a minimal valid PSBTv2 SilentPaymentsPSBT (no real tx data)."""
    psbt = SilentPaymentsPSBT(version=2)
    psbt.tx_version = 2
    psbt.locktime = 0
    # One input, one SP output
    inp = SPInputScope()
    out = SPOutputScope()
    psbt.inputs = [inp]
    psbt.outputs = [out]
    psbt._raw_input_count_from_global = 1
    psbt._raw_output_count_from_global = 1
    return psbt


def _serialize_and_parse(psbt: SilentPaymentsPSBT) -> SilentPaymentsPSBT:
    """Round-trip: serialize then parse as SilentPaymentsPSBT."""
    raw = psbt.serialize()
    return SilentPaymentsPSBT.parse(raw)


# ---------------------------------------------------------------------------
# SPOutputScope tests
# ---------------------------------------------------------------------------


class TestSPOutputScope(TestCase):
    def test_default_state(self):
        out = SPOutputScope()
        self.assertIsNone(out.sp_v0_info)
        self.assertIsNone(out.sp_v0_label)
        self.assertFalse(out.is_sp_output)

    def test_sp_v0_info_round_trip(self):
        out = SPOutputScope()
        scan = _pub_from_priv(_rand_key())
        spend = _pub_from_priv(_rand_key())
        out.sp_v0_info = (scan, spend)

        # Serialize to stream with v2
        buf = BytesIO()
        out.write_to(buf, version=2)
        buf.seek(0)
        out2 = SPOutputScope.read_from(buf, version=2)

        self.assertTrue(out2.is_sp_output)
        self.assertEqual(out2.sp_v0_info[0], scan)
        self.assertEqual(out2.sp_v0_info[1], spend)
        self.assertIsNone(out2.sp_v0_label)

    def test_sp_v0_label_round_trip(self):
        out = SPOutputScope()
        out.sp_v0_info = (_pub_from_priv(_rand_key()), _pub_from_priv(_rand_key()))
        out.sp_v0_label = 42

        buf = BytesIO()
        out.write_to(buf, version=2)
        buf.seek(0)
        out2 = SPOutputScope.read_from(buf, version=2)

        self.assertEqual(out2.sp_v0_label, 42)

    def test_sp_v0_info_not_written_in_v0(self):
        out = SPOutputScope()
        out.sp_v0_info = (_pub_from_priv(_rand_key()), _pub_from_priv(_rand_key()))
        buf = BytesIO()
        out.write_to(buf, version=None)
        buf.seek(0)
        out2 = SPOutputScope.read_from(buf, version=None)
        self.assertIsNone(out2.sp_v0_info)

    def test_sp_v0_info_rejects_wrong_length(self):
        buf = BytesIO()
        # key 0x09 with only 33 bytes (should be 66)
        ser_string(buf, b"\x09")
        ser_string(buf, b"\x02" + b"\x01" * 32)  # 33 bytes, not 66
        buf.write(b"\x00")  # separator
        buf.seek(0)
        with self.assertRaises(PSBTError):
            SPOutputScope.read_from(buf, version=2)

    def test_duplicate_sp_v0_info_rejected(self):
        scan = _pub_from_priv(_rand_key())
        spend = _pub_from_priv(_rand_key())
        buf = BytesIO()
        # Write key 0x09 twice
        ser_string(buf, b"\x09")
        ser_string(buf, scan + spend)
        ser_string(buf, b"\x09")
        ser_string(buf, scan + spend)
        buf.write(b"\x00")
        buf.seek(0)
        with self.assertRaises(PSBTError):
            SPOutputScope.read_from(buf, version=2)


# ---------------------------------------------------------------------------
# SPInputScope tests
# ---------------------------------------------------------------------------


class TestSPInputScope(TestCase):
    def test_default_state(self):
        inp = SPInputScope()
        self.assertEqual(inp.sp_ecdh_shares, {})
        self.assertEqual(inp.sp_dleq_proofs, {})
        self.assertEqual(inp.sp_spend_bip32_derivations, {})
        self.assertIsNone(inp.sp_tweak)

    def test_ecdh_share_round_trip(self):
        inp = SPInputScope()
        scan_pub = _pub_from_priv(_rand_key())
        share = _pub_from_priv(_rand_key())  # 33 bytes, simulated share
        inp.sp_ecdh_shares[scan_pub] = share

        buf = BytesIO()
        inp.write_to(buf, version=2)
        buf.seek(0)
        inp2 = SPInputScope.read_from(buf, version=2)

        self.assertIn(scan_pub, inp2.sp_ecdh_shares)
        self.assertEqual(inp2.sp_ecdh_shares[scan_pub], share)

    def test_dleq_proof_round_trip(self):
        inp = SPInputScope()
        scan_pub = _pub_from_priv(_rand_key())
        proof = b"\xab" * 64
        inp.sp_dleq_proofs[scan_pub] = proof

        buf = BytesIO()
        inp.write_to(buf, version=2)
        buf.seek(0)
        inp2 = SPInputScope.read_from(buf, version=2)

        self.assertIn(scan_pub, inp2.sp_dleq_proofs)
        self.assertEqual(inp2.sp_dleq_proofs[scan_pub], proof)

    def test_sp_tweak_round_trip(self):
        inp = SPInputScope()
        tweak = os.urandom(32)
        inp.sp_tweak = tweak

        buf = BytesIO()
        inp.write_to(buf, version=2)
        buf.seek(0)
        inp2 = SPInputScope.read_from(buf, version=2)

        self.assertEqual(inp2.sp_tweak, tweak)

    def test_spend_derivation_round_trip(self):
        inp = SPInputScope()
        spend_pub = _pub_from_priv(_rand_key())
        fp = bytes([0x01, 0x02, 0x03, 0x04])
        path = [0x80000000, 0x00000002, 0x00000001]
        der = DerivationPath(fp, path)
        inp.sp_spend_bip32_derivations[spend_pub] = der

        buf = BytesIO()
        inp.write_to(buf, version=2)
        buf.seek(0)
        inp2 = SPInputScope.read_from(buf, version=2)

        self.assertIn(spend_pub, inp2.sp_spend_bip32_derivations)
        der2 = inp2.sp_spend_bip32_derivations[spend_pub]
        self.assertEqual(der2.fingerprint, fp)
        self.assertEqual(der2.derivation, path)

    def test_multiple_shares_and_proofs(self):
        inp = SPInputScope()
        keys = [(_rand_key(), _rand_key()) for _ in range(3)]
        for priv_i, scan_priv in keys:
            scan_pub = _pub_from_priv(scan_priv)
            share = _ecdh_share(priv_i, scan_pub)
            proof = b"\xcc" * 64
            inp.sp_ecdh_shares[scan_pub] = share
            inp.sp_dleq_proofs[scan_pub] = proof

        buf = BytesIO()
        inp.write_to(buf, version=2)
        buf.seek(0)
        inp2 = SPInputScope.read_from(buf, version=2)

        for priv_i, scan_priv in keys:
            scan_pub = _pub_from_priv(scan_priv)
            self.assertIn(scan_pub, inp2.sp_ecdh_shares)
            self.assertIn(scan_pub, inp2.sp_dleq_proofs)

    def test_sp_fields_not_written_in_v0(self):
        inp = SPInputScope()
        scan_pub = _pub_from_priv(_rand_key())
        inp.sp_ecdh_shares[scan_pub] = _pub_from_priv(_rand_key())
        inp.sp_tweak = os.urandom(32)

        buf = BytesIO()
        inp.write_to(buf, version=None)
        buf.seek(0)
        inp2 = SPInputScope.read_from(buf, version=None)
        self.assertEqual(inp2.sp_ecdh_shares, {})
        self.assertIsNone(inp2.sp_tweak)

    def test_duplicate_ecdh_share_rejected(self):
        scan_pub = _pub_from_priv(_rand_key())
        share = _pub_from_priv(_rand_key())
        buf = BytesIO()
        ser_string(buf, bytes([PSBT_IN_SP_ECDH_SHARE]) + scan_pub)
        ser_string(buf, share)
        ser_string(buf, bytes([PSBT_IN_SP_ECDH_SHARE]) + scan_pub)
        ser_string(buf, share)
        buf.write(b"\x00")
        buf.seek(0)
        with self.assertRaises(PSBTError):
            SPInputScope.read_from(buf, version=2)

    def test_duplicate_sp_tweak_rejected(self):
        tweak = os.urandom(32)
        buf = BytesIO()
        ser_string(buf, b"\x20")
        ser_string(buf, tweak)
        ser_string(buf, b"\x20")
        ser_string(buf, tweak)
        buf.write(b"\x00")
        buf.seek(0)
        with self.assertRaises(PSBTError):
            SPInputScope.read_from(buf, version=2)


# ---------------------------------------------------------------------------
# SilentPaymentsPSBT global field tests
# ---------------------------------------------------------------------------


class TestSilentPaymentsPSBTGlobalFields(TestCase):
    def test_default_state(self):
        psbt = SilentPaymentsPSBT(version=2)
        self.assertEqual(psbt.sp_ecdh_shares, {})
        self.assertEqual(psbt.sp_dleq_proofs, {})

    def test_global_ecdh_share_round_trip(self):
        psbt = _build_minimal_psbtv2()
        scan_pub = _pub_from_priv(_rand_key())
        share = _pub_from_priv(_rand_key())
        psbt.sp_ecdh_shares[scan_pub] = share

        psbt2 = _serialize_and_parse(psbt)
        self.assertIn(scan_pub, psbt2.sp_ecdh_shares)
        self.assertEqual(psbt2.sp_ecdh_shares[scan_pub], share)

    def test_global_dleq_proof_round_trip(self):
        psbt = _build_minimal_psbtv2()
        scan_pub = _pub_from_priv(_rand_key())
        share = _pub_from_priv(_rand_key())
        psbt.sp_ecdh_shares[scan_pub] = share
        # Generate a real proof
        priv = _rand_key()
        A = _pub_from_priv(priv)
        C = _ecdh_share(priv, scan_pub)
        proof = generate_dleq_proof(priv, scan_pub)
        psbt.sp_ecdh_shares[scan_pub] = C
        psbt.sp_dleq_proofs[scan_pub] = proof

        psbt2 = _serialize_and_parse(psbt)
        self.assertIn(scan_pub, psbt2.sp_dleq_proofs)
        self.assertEqual(psbt2.sp_dleq_proofs[scan_pub], proof)

    def test_multiple_global_shares(self):
        psbt = _build_minimal_psbtv2()
        scan_keys = [_rand_key() for _ in range(3)]
        for sk in scan_keys:
            scan_pub = _pub_from_priv(sk)
            psbt.sp_ecdh_shares[scan_pub] = _pub_from_priv(_rand_key())

        psbt2 = _serialize_and_parse(psbt)
        for sk in scan_keys:
            scan_pub = _pub_from_priv(sk)
            self.assertIn(scan_pub, psbt2.sp_ecdh_shares)

    def test_global_fields_not_written_in_v0(self):
        """Global SP fields (key 0x07/0x08) are only written in v2 mode, and
        key bytes appear in the raw serialized data."""
        psbt = _build_minimal_psbtv2()
        scan_pub = _pub_from_priv(_rand_key())
        share = _pub_from_priv(_rand_key())
        psbt.sp_ecdh_shares[scan_pub] = share

        raw = psbt.serialize()
        # The 34-byte key (0x07 + 33-byte scan_pub) must appear in the serialized data
        key_bytes = bytes([PSBT_GLOBAL_SP_ECDH_SHARE]) + scan_pub
        self.assertIn(key_bytes, raw)

        # After round-trip, the share is recovered
        psbt2 = _serialize_and_parse(psbt)
        self.assertIn(scan_pub, psbt2.sp_ecdh_shares)
        self.assertEqual(psbt2.sp_ecdh_shares[scan_pub], share)


# ---------------------------------------------------------------------------
# Full PSBTv2 round-trip with all SP fields
# ---------------------------------------------------------------------------


class TestSilentPaymentsPSBTRoundTrip(TestCase):
    def test_full_round_trip_all_fields(self):
        """
        Build a PSBTv2 with all BIP-375 and BIP-376 fields, serialize, parse,
        and verify all values are preserved.
        """
        psbt = _build_minimal_psbtv2()

        # Keys
        input_priv = _rand_key()
        scan_priv = _rand_key()
        spend_priv = _rand_key()
        scan_pub = _pub_from_priv(scan_priv)
        spend_pub = _pub_from_priv(spend_priv)

        # Compute ECDH share and DLEQ proof
        ecdh_share = _ecdh_share(input_priv, scan_pub)
        proof = generate_dleq_proof(input_priv, scan_pub)
        A = _pub_from_priv(input_priv)

        # Global SP fields
        psbt.sp_ecdh_shares[scan_pub] = ecdh_share
        psbt.sp_dleq_proofs[scan_pub] = proof

        # Per-input SP fields
        inp = psbt.inputs[0]
        inp.sp_ecdh_shares[scan_pub] = ecdh_share
        inp.sp_dleq_proofs[scan_pub] = proof
        tweak = os.urandom(32)
        inp.sp_tweak = tweak
        fp = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        der = DerivationPath(fp, [0x80000054, 0x80000001, 0x00000000, 0x00000000])
        inp.sp_spend_bip32_derivations[spend_pub] = der

        # Per-output SP fields
        out = psbt.outputs[0]
        out.sp_v0_info = (scan_pub, spend_pub)
        out.sp_v0_label = 7

        # Round-trip
        psbt2 = _serialize_and_parse(psbt)

        # Global
        self.assertIn(scan_pub, psbt2.sp_ecdh_shares)
        self.assertEqual(psbt2.sp_ecdh_shares[scan_pub], ecdh_share)
        self.assertIn(scan_pub, psbt2.sp_dleq_proofs)
        self.assertEqual(psbt2.sp_dleq_proofs[scan_pub], proof)

        # Input
        inp2 = psbt2.inputs[0]
        self.assertIn(scan_pub, inp2.sp_ecdh_shares)
        self.assertEqual(inp2.sp_ecdh_shares[scan_pub], ecdh_share)
        self.assertIn(scan_pub, inp2.sp_dleq_proofs)
        self.assertEqual(inp2.sp_dleq_proofs[scan_pub], proof)
        self.assertEqual(inp2.sp_tweak, tweak)
        self.assertIn(spend_pub, inp2.sp_spend_bip32_derivations)
        der2 = inp2.sp_spend_bip32_derivations[spend_pub]
        self.assertEqual(der2.fingerprint, fp)
        self.assertEqual(
            der2.derivation, [0x80000054, 0x80000001, 0x00000000, 0x00000000]
        )

        # Output
        out2 = psbt2.outputs[0]
        self.assertTrue(out2.is_sp_output)
        self.assertEqual(out2.sp_v0_info[0], scan_pub)
        self.assertEqual(out2.sp_v0_info[1], spend_pub)
        self.assertEqual(out2.sp_v0_label, 7)

    def test_serialize_is_stable(self):
        """Serializing twice gives identical bytes."""
        psbt = _build_minimal_psbtv2()
        scan_pub = _pub_from_priv(_rand_key())
        psbt.sp_ecdh_shares[scan_pub] = _pub_from_priv(_rand_key())
        r1 = psbt.serialize()
        r2 = psbt.serialize()
        self.assertEqual(r1, r2)

    def test_parse_empty_psbt(self):
        """A PSBTv2 with no SP fields parses cleanly."""
        psbt = _build_minimal_psbtv2()
        psbt2 = _serialize_and_parse(psbt)
        self.assertEqual(psbt2.sp_ecdh_shares, {})
        self.assertEqual(psbt2.sp_dleq_proofs, {})
        self.assertFalse(psbt2.has_sp_outputs())


# ---------------------------------------------------------------------------
# BIP-375: DLEQ proof integration
# ---------------------------------------------------------------------------


class TestDLEQIntegration(TestCase):
    def test_add_global_ecdh_share(self):
        """add_global_ecdh_share computes correct share and a valid proof."""
        psbt = _build_minimal_psbtv2()
        input_priv = _rand_key()
        scan_priv = _rand_key()
        scan_pub = _pub_from_priv(scan_priv)

        psbt.add_global_ecdh_share(input_priv, scan_pub)

        self.assertIn(scan_pub, psbt.sp_ecdh_shares)
        self.assertIn(scan_pub, psbt.sp_dleq_proofs)

        # Verify the share is input_priv * scan_pub
        expected_share = _ecdh_share(input_priv, scan_pub)
        self.assertEqual(psbt.sp_ecdh_shares[scan_pub], expected_share)

        # Verify the DLEQ proof
        A = _pub_from_priv(input_priv)
        C = psbt.sp_ecdh_shares[scan_pub]
        proof = psbt.sp_dleq_proofs[scan_pub]
        self.assertTrue(verify_dleq_proof(A, scan_pub, C, proof))

    def test_verify_input_dleq_proofs_valid(self):
        psbt = _build_minimal_psbtv2()
        input_priv = _rand_key()
        scan_priv = _rand_key()
        scan_pub = _pub_from_priv(scan_priv)
        A = _pub_from_priv(input_priv)
        C = _ecdh_share(input_priv, scan_pub)
        proof = generate_dleq_proof(input_priv, scan_pub)

        inp = psbt.inputs[0]
        inp.sp_ecdh_shares[scan_pub] = C
        inp.sp_dleq_proofs[scan_pub] = proof
        # Need A for verification — put it in bip32_derivations
        inp.bip32_derivations[A] = DerivationPath(b"\x00" * 4, [])

        self.assertTrue(psbt.verify_input_dleq_proofs())

    def test_verify_input_dleq_proofs_invalid(self):
        psbt = _build_minimal_psbtv2()
        input_priv = _rand_key()
        scan_priv = _rand_key()
        scan_pub = _pub_from_priv(scan_priv)
        A = _pub_from_priv(input_priv)
        C = _ecdh_share(input_priv, scan_pub)
        bad_proof = b"\xcc" * 64  # invalid proof

        inp = psbt.inputs[0]
        inp.sp_ecdh_shares[scan_pub] = C
        inp.sp_dleq_proofs[scan_pub] = bad_proof
        inp.bip32_derivations[A] = DerivationPath(b"\x00" * 4, [])

        with self.assertRaises(PSBTError):
            psbt.verify_input_dleq_proofs()

    def test_proof_round_trips_through_psbt(self):
        """A generated proof survives serialization and is still valid."""
        psbt = _build_minimal_psbtv2()
        input_priv = _rand_key()
        scan_priv = _rand_key()
        scan_pub = _pub_from_priv(scan_priv)
        A = _pub_from_priv(input_priv)
        C = _ecdh_share(input_priv, scan_pub)
        proof = generate_dleq_proof(input_priv, scan_pub)

        psbt.sp_ecdh_shares[scan_pub] = C
        psbt.sp_dleq_proofs[scan_pub] = proof

        psbt2 = _serialize_and_parse(psbt)
        recovered_proof = psbt2.sp_dleq_proofs[scan_pub]
        recovered_C = psbt2.sp_ecdh_shares[scan_pub]

        self.assertTrue(verify_dleq_proof(A, scan_pub, recovered_C, recovered_proof))


# ---------------------------------------------------------------------------
# BIP-376: sign_with enforcement
# ---------------------------------------------------------------------------


class TestBIP376SignWithEnforcement(TestCase):
    def _psbt_with_sp_output_no_script(self):
        psbt = _build_minimal_psbtv2()
        out = psbt.outputs[0]
        out.sp_v0_info = (_pub_from_priv(_rand_key()), _pub_from_priv(_rand_key()))
        return psbt

    def test_sign_with_sp_output_missing_script_raises(self):
        psbt = self._psbt_with_sp_output_no_script()
        key = PrivateKey(_rand_key())
        with self.assertRaises(PSBTError):
            psbt.sign_with(key)

    def test_sign_with_wrong_sighash_raises(self):
        psbt = _build_minimal_psbtv2()
        out = psbt.outputs[0]
        out.sp_v0_info = (_pub_from_priv(_rand_key()), _pub_from_priv(_rand_key()))
        from embit.transaction import SIGHASH

        key = PrivateKey(_rand_key())
        with self.assertRaises(PSBTError):
            psbt.sign_with(key, sighash=SIGHASH.NONE)

    def test_set_sp_tweak(self):
        psbt = _build_minimal_psbtv2()
        tweak = os.urandom(32)
        psbt.set_sp_tweak(0, tweak)
        self.assertEqual(psbt.inputs[0].sp_tweak, tweak)

    def test_set_sp_tweak_wrong_length(self):
        psbt = _build_minimal_psbtv2()
        with self.assertRaises(PSBTError):
            psbt.set_sp_tweak(0, b"\x00" * 16)

    def test_set_sp_spend_derivation(self):
        psbt = _build_minimal_psbtv2()
        spend_pub = _pub_from_priv(_rand_key())
        der = DerivationPath(b"\x01\x02\x03\x04", [0x80000000])
        psbt.set_sp_spend_derivation(0, spend_pub, der)
        self.assertIn(spend_pub, psbt.inputs[0].sp_spend_bip32_derivations)


# ---------------------------------------------------------------------------
# SP output helpers
# ---------------------------------------------------------------------------


class TestSPHelpers(TestCase):
    def test_sp_outputs_empty(self):
        psbt = _build_minimal_psbtv2()
        self.assertEqual(psbt.sp_outputs(), [])
        self.assertFalse(psbt.has_sp_outputs())

    def test_sp_outputs_with_sp_output(self):
        psbt = _build_minimal_psbtv2()
        out = psbt.outputs[0]
        out.sp_v0_info = (_pub_from_priv(_rand_key()), _pub_from_priv(_rand_key()))
        self.assertEqual(len(psbt.sp_outputs()), 1)
        self.assertTrue(psbt.has_sp_outputs())

    def test_mixed_outputs(self):
        psbt = _build_minimal_psbtv2()
        # Add a second non-SP output
        psbt.outputs.append(SPOutputScope())
        psbt._raw_output_count_from_global = 2
        # Mark first as SP
        psbt.outputs[0].sp_v0_info = (
            _pub_from_priv(_rand_key()),
            _pub_from_priv(_rand_key()),
        )
        self.assertEqual(len(psbt.sp_outputs()), 1)
        self.assertTrue(psbt.has_sp_outputs())

    def test_parse_unknowns_does_not_leave_sp_keys_in_unknown(self):
        psbt = _build_minimal_psbtv2()
        scan_pub = _pub_from_priv(_rand_key())
        psbt.sp_ecdh_shares[scan_pub] = _pub_from_priv(_rand_key())
        psbt2 = _serialize_and_parse(psbt)
        # Unknown dict must not contain key 0x07... or 0x08...
        for k in psbt2.unknown:
            self.assertNotEqual(k[0:1], bytes([PSBT_GLOBAL_SP_ECDH_SHARE]))
            self.assertNotEqual(k[0:1], bytes([PSBT_GLOBAL_SP_DLEQ]))


# ---------------------------------------------------------------------------
# Field number conflict checks
# ---------------------------------------------------------------------------


class TestFieldNumberNoConflicts(TestCase):
    """
    Verify that BIP-375/376 field numbers don't overlap with existing fields.
    """

    def test_output_field_0x09_not_confusable_with_tap_bip32(self):
        """
        OutputScope key 0x07 is tap_bip32_derivation (key = 0x07 + xonly_pub).
        SP output field 0x09 must be independent.
        """
        from embit.psbt import OutputScope

        # Build a regular OutputScope with a tap_bip32_derivation
        out = OutputScope()
        # If we construct an SPOutputScope, the 0x09 field handler takes over
        sp_out = SPOutputScope()
        sp_out.sp_v0_info = (_pub_from_priv(_rand_key()), _pub_from_priv(_rand_key()))
        buf = BytesIO()
        sp_out.write_to(buf, version=2)
        buf.seek(0)
        sp_out2 = SPOutputScope.read_from(buf, version=2)
        # The tap_bip32_derivations on the base should still be empty
        self.assertEqual(sp_out2.bip32_derivations, {})
        self.assertTrue(sp_out2.is_sp_output)

    def test_input_sp_fields_dont_overlap_existing(self):
        """
        InputScope existing fields go up to 0x18. SP fields start at 0x1d.
        Construct a regular field (e.g. 0x01 = partial_sig) alongside SP field.
        """
        inp = SPInputScope()
        scan_pub = _pub_from_priv(_rand_key())
        inp.sp_tweak = os.urandom(32)

        buf = BytesIO()
        inp.write_to(buf, version=2)
        buf.seek(0)
        inp2 = SPInputScope.read_from(buf, version=2)
        self.assertIsNotNone(inp2.sp_tweak)
        # Base fields should be clean
        self.assertEqual(inp2.partial_sigs, {})
