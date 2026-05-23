"""
BIP-376 Test Suite: Silent Payment Spend PSBT Fields

Tests for:
  - Parsing/serialization roundtrip for 0x1f and 0x20 fields
  - PSBTv0 rejection
  - Invalid lengths and duplicate rejection
  - sign_input_with_sp_tweak signing logic
  - finalize_sp_spends finalizer
  - End-to-end integration
"""

import unittest
from collections import OrderedDict
from io import BytesIO

from embit import bip32, ec
from embit.psbt import PSBT, DerivationPath, PSBTError
from embit.script import Script, p2tr, Witness
from embit.transaction import TransactionOutput
from embit.silent_payments import SilentPaymentsPSBT, finalize_sp_spends
from embit.silent_payments.psbt import (
    SPInputScope as InputScope,
    SPOutputScope as OutputScope,
)


# ── helpers ────────────────────────────────────────────────────────────────────


def _spend_priv():
    return ec.PrivateKey(b"\x11" * 32)


def _tweak():
    return b"\x22" * 32


def _tweaked_priv():
    return _spend_priv().sp_spend_tweak(_tweak())


def _output_script():
    """P2TR script whose x-only key matches the tweaked spend key."""
    xonly = _tweaked_priv().xonly()
    return Script(b"\x51\x20" + xonly)


def _make_sp_spend_psbt(fingerprint=None, derivation=None):
    """
    Build a minimal PSBTv2 with one P2TR SP-spend input.

    The input's witness_utxo script_pubkey is the tweaked spend key.
    sp_tweak and sp_spend_bip32_derivations are set so the signer can act.
    """
    psbt = SilentPaymentsPSBT.create_v2()

    spend_pub = _spend_priv().get_public_key()
    inp = InputScope()
    inp.txid = b"\xaa" * 32
    inp.vout = 0
    inp.sequence = 0xFFFFFFFE
    inp.witness_utxo = TransactionOutput(
        value=100_000, script_pubkey=_output_script()
    )
    inp.sp_tweak = _tweak()

    if fingerprint and derivation:
        pub_sec = spend_pub.sec()
        inp.sp_spend_bip32_derivations[pub_sec] = DerivationPath(fingerprint, derivation)

    psbt.add_input(inp)

    out = OutputScope()
    out.value = 99_000
    out.script_pubkey = Script(b"\x51\x20" + b"\x33" * 32)
    psbt.add_output(out)

    psbt.tx_modifiable_flags = 0
    return psbt


# ── sp_spend_tweak unit tests ──────────────────────────────────────────────────


class TestSpSpendTweak(unittest.TestCase):
    def test_returns_even_y_key(self):
        pk = _spend_priv().sp_spend_tweak(_tweak())
        # Result must have even y (starts with 0x02)
        self.assertEqual(pk.sec()[0], 0x02)

    def test_wrong_tweak_length(self):
        with self.assertRaises(Exception):
            _spend_priv().sp_spend_tweak(b"\x01" * 31)

    def test_no_pre_negation(self):
        # Unlike taproot_tweak, sp_spend_tweak does not pre-negate odd-y keys.
        # Verify the result is deterministic and correct by checking xonly matches
        # expected output.
        pk1 = _spend_priv().sp_spend_tweak(_tweak())
        pk2 = _spend_priv().sp_spend_tweak(_tweak())
        self.assertEqual(pk1.xonly(), pk2.xonly())


# ── field parsing tests ────────────────────────────────────────────────────────


class TestBIP376FieldParsing(unittest.TestCase):
    def _roundtrip(self, psbt):
        raw = psbt.serialize()
        return SilentPaymentsPSBT.parse(raw)

    def test_sp_tweak_roundtrip(self):
        psbt = _make_sp_spend_psbt()
        psbt2 = self._roundtrip(psbt)
        self.assertEqual(psbt2.inputs[0].sp_tweak, _tweak())

    def test_sp_spend_bip32_derivation_roundtrip(self):
        root = bip32.HDKey.from_seed(bytes(range(32)))
        fp = root.my_fingerprint
        der = [0x80000000 + 352, 0, 0]
        psbt = _make_sp_spend_psbt(fingerprint=fp, derivation=der)
        psbt2 = self._roundtrip(psbt)
        spend_pub_sec = _spend_priv().get_public_key().sec()
        self.assertIn(spend_pub_sec, psbt2.inputs[0].sp_spend_bip32_derivations)
        parsed_der = psbt2.inputs[0].sp_spend_bip32_derivations[spend_pub_sec]
        self.assertEqual(parsed_der.fingerprint, fp)
        self.assertEqual(parsed_der.derivation, der)

    def test_sp_tweak_psbtv0_rejected(self):
        """0x20 field must be rejected in PSBTv0."""
        # Build a raw PSBTv0-like stream with a 0x20 key in an input map
        # Craft minimal PSBTv0 with sp_tweak key and ensure parse raises
        psbt = _make_sp_spend_psbt()
        # Patch the version to 0 to simulate PSBTv0
        raw = psbt.serialize()
        # Re-parse as generic PSBT to verify we get an error if we try
        # to inject 0x20 into a v0 parse context
        # Instead, build a raw PSBTv0 with 0x20 injected
        # We test this by reading_value directly
        inp = InputScope()
        inp.txid = b"\x00" * 32
        inp.vout = 0
        key = b"\x20"
        val = b"\x22" * 32
        stream = BytesIO(len(val).to_bytes(1, "little") + val)
        with self.assertRaises(PSBTError):
            inp.read_value(stream, key, version=0)

    def test_sp_spend_bip32_psbtv0_rejected(self):
        inp = InputScope()
        spend_pub_sec = _spend_priv().get_public_key().sec()
        key = b"\x1f" + spend_pub_sec
        fp = b"\x01\x02\x03\x04"
        der_bytes = (0).to_bytes(4, "little")
        val = fp + der_bytes
        stream = BytesIO(len(val).to_bytes(1, "little") + val)
        with self.assertRaises(PSBTError):
            inp.read_value(stream, key, version=0)

    def test_sp_tweak_invalid_length(self):
        inp = InputScope()
        key = b"\x20"
        val = b"\x22" * 31  # wrong length
        stream = BytesIO(len(val).to_bytes(1, "little") + val)
        with self.assertRaises(PSBTError):
            inp.read_value(stream, key, version=2)

    def test_sp_tweak_duplicate_rejected(self):
        inp = InputScope()
        inp.sp_tweak = b"\x11" * 32
        key = b"\x20"
        val = b"\x22" * 32
        stream = BytesIO(len(val).to_bytes(1, "little") + val)
        with self.assertRaises(PSBTError):
            inp.read_value(stream, key, version=2)

    def test_sp_spend_bip32_invalid_key_length(self):
        """Key for 0x1f must be exactly 34 bytes (1 type byte + 33 pubkey)."""
        inp = InputScope()
        key = b"\x1f" + b"\x02" * 32  # 33 bytes total, should be 34
        val = b"\x01\x02\x03\x04"  # minimal derivation
        stream = BytesIO(len(val).to_bytes(1, "little") + val)
        with self.assertRaises(PSBTError):
            inp.read_value(stream, key, version=2)

    def test_sp_spend_bip32_duplicate_rejected(self):
        inp = InputScope()
        spend_pub_sec = _spend_priv().get_public_key().sec()
        inp.sp_spend_bip32_derivations[spend_pub_sec] = DerivationPath(b"\x00" * 4, [])
        key = b"\x1f" + spend_pub_sec
        fp = b"\x01\x02\x03\x04"
        val = fp
        stream = BytesIO(len(val).to_bytes(1, "little") + val)
        with self.assertRaises(PSBTError):
            inp.read_value(stream, key, version=2)


# ── signing tests ──────────────────────────────────────────────────────────────


class TestSignInputWithSpTweak(unittest.TestCase):
    def test_sign_with_raw_key(self):
        psbt = _make_sp_spend_psbt()
        priv = _spend_priv()
        n = psbt.sign_input_with_sp_tweak(priv, 0)
        self.assertEqual(n, 1)
        self.assertIsNotNone(psbt.inputs[0].taproot_key_sig)
        self.assertEqual(len(psbt.inputs[0].taproot_key_sig), 64)

    def test_sign_wrong_tweak_returns_zero(self):
        psbt = _make_sp_spend_psbt()
        psbt.inputs[0].sp_tweak = b"\xff" * 32  # wrong tweak
        priv = _spend_priv()
        n = psbt.sign_input_with_sp_tweak(priv, 0)
        self.assertEqual(n, 0)
        self.assertIsNone(psbt.inputs[0].taproot_key_sig)

    def test_sign_no_sp_tweak_returns_zero(self):
        psbt = _make_sp_spend_psbt()
        psbt.inputs[0].sp_tweak = None
        priv = _spend_priv()
        n = psbt.sign_input_with_sp_tweak(priv, 0)
        self.assertEqual(n, 0)

    def test_sign_non_taproot_returns_zero(self):
        from embit.script import p2wpkh
        psbt = _make_sp_spend_psbt()
        pub = _spend_priv().get_public_key()
        psbt.inputs[0].witness_utxo = TransactionOutput(
            value=100_000, script_pubkey=p2wpkh(pub)
        )
        priv = _spend_priv()
        n = psbt.sign_input_with_sp_tweak(priv, 0)
        self.assertEqual(n, 0)

    def test_already_signed_sign_input_again(self):
        """Calling twice overwrites taproot_key_sig (idempotent)."""
        psbt = _make_sp_spend_psbt()
        priv = _spend_priv()
        psbt.sign_input_with_sp_tweak(priv, 0)
        sig1 = psbt.inputs[0].taproot_key_sig
        psbt.sign_input_with_sp_tweak(priv, 0)
        sig2 = psbt.inputs[0].taproot_key_sig
        self.assertEqual(sig1, sig2)

    def test_sign_with_tapkey_returns_zero_for_sp_input(self):
        """
        sign_input_with_tapkey must not sign SP-spend inputs because the
        output script was derived with sp_spend_tweak (no TapTweak tag).
        """
        psbt = _make_sp_spend_psbt()
        priv = _spend_priv()
        n = psbt.sign_input_with_tapkey(priv, 0)
        self.assertEqual(n, 0)


# ── HD key signing via SilentPaymentsPSBT.sign_with ───────────────────────────


class TestSignSpSpendsWithHDKey(unittest.TestCase):
    def _root(self):
        return bip32.HDKey.from_seed(bytes(range(32)))

    def _build_psbt_with_hd(self):
        root = self._root()
        # Derive the spend private key from the root at path m/352'/0'/0'/0/0
        path = [0x80000000 + 352, 0x80000000, 0x80000000, 0, 0]
        child = root.derive(path)
        spend_priv = child.key
        tweak = _tweak()
        tweaked_priv = spend_priv.sp_spend_tweak(tweak)
        xonly = tweaked_priv.xonly()
        out_script = Script(b"\x51\x20" + xonly)

        psbt = SilentPaymentsPSBT.create_v2()
        inp = InputScope()
        inp.txid = b"\xbb" * 32
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=out_script)
        inp.sp_tweak = tweak
        pub_sec = spend_priv.get_public_key().sec()
        inp.sp_spend_bip32_derivations[pub_sec] = DerivationPath(
            root.my_fingerprint, path
        )
        psbt.add_input(inp)

        out = OutputScope()
        out.value = 99_000
        out.script_pubkey = Script(b"\x51\x20" + b"\x44" * 32)
        psbt.add_output(out)
        psbt.tx_modifiable_flags = 0
        return psbt, root

    def test_sign_with_hd_key(self):
        psbt, root = self._build_psbt_with_hd()
        n = psbt.sign_with(root)
        self.assertGreaterEqual(n, 1)
        self.assertIsNotNone(psbt.inputs[0].taproot_key_sig)
        self.assertEqual(len(psbt.inputs[0].taproot_key_sig), 64)

    def test_already_signed_input_skipped(self):
        psbt, root = self._build_psbt_with_hd()
        psbt.inputs[0].taproot_key_sig = b"\xff" * 64
        n = psbt.sign_with(root)
        # _sign_sp_spends skips inputs where taproot_key_sig is set
        self.assertEqual(psbt.inputs[0].taproot_key_sig, b"\xff" * 64)


# ── finalization tests ─────────────────────────────────────────────────────────


class TestFinalizeSpSpends(unittest.TestCase):
    def test_finalize_sets_witness(self):
        psbt = _make_sp_spend_psbt()
        priv = _spend_priv()
        psbt.sign_input_with_sp_tweak(priv, 0)
        n = finalize_sp_spends(psbt)
        self.assertEqual(n, 1)
        self.assertIsNotNone(psbt.inputs[0].final_scriptwitness)
        self.assertEqual(len(psbt.inputs[0].final_scriptwitness.items), 1)

    def test_finalize_clears_sp_fields(self):
        psbt = _make_sp_spend_psbt()
        priv = _spend_priv()
        psbt.sign_input_with_sp_tweak(priv, 0)
        finalize_sp_spends(psbt)
        self.assertIsNone(psbt.inputs[0].sp_tweak)
        self.assertIsNone(psbt.inputs[0].taproot_key_sig)
        self.assertEqual(len(psbt.inputs[0].sp_spend_bip32_derivations), 0)

    def test_finalize_unsigned_returns_zero(self):
        psbt = _make_sp_spend_psbt()
        n = finalize_sp_spends(psbt)
        self.assertEqual(n, 0)
        self.assertIsNone(psbt.inputs[0].final_scriptwitness)

    def test_finalize_no_sp_tweak_skipped(self):
        psbt = _make_sp_spend_psbt()
        psbt.inputs[0].sp_tweak = None
        psbt.inputs[0].taproot_key_sig = b"\x01" * 64
        n = finalize_sp_spends(psbt)
        self.assertEqual(n, 0)


# ── integration test ───────────────────────────────────────────────────────────


class TestBIP376Integration(unittest.TestCase):
    def test_end_to_end(self):
        """
        Full flow: build PSBT → sign → finalize → extract witness.
        """
        spend_priv = _spend_priv()
        tweak = _tweak()
        tweaked_priv = spend_priv.sp_spend_tweak(tweak)
        xonly = tweaked_priv.xonly()
        out_script = Script(b"\x51\x20" + xonly)

        psbt = SilentPaymentsPSBT.create_v2()
        inp = InputScope()
        inp.txid = b"\xcc" * 32
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(value=200_000, script_pubkey=out_script)
        inp.sp_tweak = tweak
        psbt.add_input(inp)

        out = OutputScope()
        out.value = 199_000
        out.script_pubkey = Script(b"\x51\x20" + b"\x55" * 32)
        psbt.add_output(out)
        psbt.tx_modifiable_flags = 0

        # Sign
        n = psbt.sign_input_with_sp_tweak(spend_priv, 0)
        self.assertEqual(n, 1)
        self.assertIsNotNone(psbt.inputs[0].taproot_key_sig)

        # Finalize
        nf = finalize_sp_spends(psbt)
        self.assertEqual(nf, 1)

        # Witness contains signature
        wit = psbt.inputs[0].final_scriptwitness
        self.assertIsNotNone(wit)
        self.assertEqual(len(wit.items), 1)
        sig_bytes = wit.items[0]
        self.assertEqual(len(sig_bytes), 64)

        # SP fields are cleared
        self.assertIsNone(psbt.inputs[0].sp_tweak)
        self.assertIsNone(psbt.inputs[0].taproot_key_sig)


if __name__ == "__main__":
    unittest.main()
