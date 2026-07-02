"""
Tests for SilentPaymentsPSBT.sign_single_party() and fill_output_scripts() —
the BIP-375 single-party signer orchestration API: clear stale shares ->
per-input shares -> fill output scripts -> global share/proof -> sign, with
per-input shares dropped once the global pair is set (a signer covering
every input SHOULD prefer the smaller global fields).
"""

import unittest

from embit import bip32, ec
from embit.psbt import DerivationPath
from embit.silent_payments import SilentPaymentsPSBT as PSBT
from embit.silent_payments.psbt import SPInputScope as InputScope, SPOutputScope as OutputScope
from embit.silent_payments import SPValidationError, SilentPaymentData
from embit.silent_payments.validator import BIP375Validator
from embit.silent_payments.ecdh import (
    compute_dleq_proof,
    compute_ecdh_share,
    derive_sp_output_scripts,
)
from embit.script import p2wpkh, p2wsh, Script
from embit.transaction import TransactionOutput


def _root():
    return bip32.HDKey.from_seed(bytes(range(32)))


def _sp_keys():
    scan_priv = ec.PrivateKey(b"\x01" * 32)
    spend_priv = ec.PrivateKey(b"\x02" * 32)
    return scan_priv.get_public_key(), spend_priv.get_public_key()


def _make_psbt(root, scan_pub, spend_pub, num_inputs=1, finalize_flags=True):
    """PSBTv2 with `num_inputs` P2WPKH inputs controlled by `root` and one
    SP output with an unresolved script (as a real BIP-375 send starts).

    `finalize_flags=False` leaves inputs/outputs modifiable so the caller can
    append more inputs (e.g. a foreign co-signer's) before locking down
    tx_modifiable_flags itself.
    """
    psbt = PSBT.create_v2()
    for idx in range(num_inputs):
        child = root.derive([0, idx])
        pub = child.get_public_key()
        inp = InputScope()
        inp.txid = bytes([0xAA + idx] * 32)
        inp.vout = idx
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=p2wpkh(pub))
        inp.bip32_derivations[pub] = DerivationPath(root.my_fingerprint, [0, idx])
        psbt.add_input(inp)

    out = OutputScope()
    out.value = 95_000
    out.sp_data = SilentPaymentData(scan_pub, spend_pub)
    psbt.add_output(out)

    if finalize_flags:
        psbt.tx_modifiable_flags = 0
    return psbt


class TestSignSingleParty(unittest.TestCase):
    def test_signs_and_resolves_output_script(self):
        root = _root()
        scan_pub, spend_pub = _sp_keys()
        psbt = _make_psbt(root, scan_pub, spend_pub, num_inputs=2)

        count = psbt.sign_single_party(root)

        self.assertGreater(count, 0)
        self.assertIsNotNone(psbt.outputs[0].script_pubkey)
        for inp in psbt.inputs:
            self.assertGreater(len(inp.partial_sigs), 0)

        # The signed+filled PSBT must be BIP-375-clean end to end.
        BIP375Validator(psbt).validate(skip_output_scripts=False)

    def test_drops_per_input_shares_once_global_is_set(self):
        root = _root()
        scan_pub, spend_pub = _sp_keys()
        psbt = _make_psbt(root, scan_pub, spend_pub, num_inputs=2)

        psbt.sign_single_party(root)

        scan_key_bytes = scan_pub.sec()
        self.assertIn(scan_key_bytes, psbt.sp_ecdh_shares)
        self.assertIn(scan_key_bytes, psbt.sp_dleq_proofs)
        for inp in psbt.inputs:
            self.assertNotIn(scan_key_bytes, inp.sp_ecdh_shares)
            self.assertNotIn(scan_key_bytes, inp.sp_dleq_proofs)

    def test_wrong_seed_raises(self):
        root = _root()
        wrong_root = bip32.HDKey.from_seed(bytes([0x99] * 32))
        scan_pub, spend_pub = _sp_keys()
        psbt = _make_psbt(root, scan_pub, spend_pub)

        with self.assertRaisesRegex(SPValidationError, "no eligible input"):
            psbt.sign_single_party(wrong_root)

    def test_no_eligible_inputs_raises(self):
        # A PSBT with SP outputs but only BIP-352-ineligible inputs (e.g.
        # bare multisig P2WSH) must not silently return 0 - that renders as
        # an unexplained "Signing Failed" screen downstream.
        root = _root()
        scan_pub, spend_pub = _sp_keys()
        psbt = PSBT.create_v2()

        redeem_script = Script(bytes([0x51, 0x21]) + bytes(33) + bytes([0x51, 0xae]))
        inp = InputScope()
        inp.txid = bytes([0xAA] * 32)
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=p2wsh(redeem_script))
        psbt.add_input(inp)

        out = OutputScope()
        out.value = 95_000
        out.sp_data = SilentPaymentData(scan_pub, spend_pub)
        psbt.add_output(out)
        psbt.tx_modifiable_flags = 0

        with self.assertRaisesRegex(SPValidationError, "at least one eligible input"):
            psbt.sign_single_party(root)

    def test_multiparty_input_raises_and_preserves_foreign_share(self):
        root = _root()
        foreign_root = bip32.HDKey.from_seed(bytes([0x77] * 32))
        scan_pub, spend_pub = _sp_keys()
        psbt = _make_psbt(root, scan_pub, spend_pub, num_inputs=1, finalize_flags=False)

        foreign_pub = foreign_root.derive([0, 0]).get_public_key()
        inp = InputScope()
        inp.txid = bytes([0xBB] * 32)
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(value=50_000, script_pubkey=p2wpkh(foreign_pub))
        inp.bip32_derivations[foreign_pub] = DerivationPath(foreign_root.my_fingerprint, [0, 0])
        # Foreign co-signer already contributed their own share.
        foreign_share = compute_ecdh_share(foreign_root.derive([0, 0]).key.secret, scan_pub)
        foreign_proof = compute_dleq_proof(
            foreign_root.derive([0, 0]).key.secret, scan_pub, foreign_share
        )
        inp.sp_ecdh_shares[scan_pub.sec()] = foreign_share
        inp.sp_dleq_proofs[scan_pub.sec()] = foreign_proof
        psbt.add_input(inp)
        psbt.tx_modifiable_flags = 0

        with self.assertRaisesRegex(SPValidationError, "multi-party"):
            psbt.sign_single_party(root)

        # A stateless single-party signer must not have clobbered the other
        # signer's already-contributed share.
        self.assertEqual(psbt.inputs[1].sp_ecdh_shares[scan_pub.sec()], foreign_share)


class TestFillOutputScripts(unittest.TestCase):
    def test_agrees_with_validator_derivation(self):
        """fill_output_scripts()'s result must match what the validator
        independently derives (both call the shared derive_sp_output_scripts
        core), confirming there's exactly one derivation implementation."""
        root = _root()
        scan_pub, spend_pub = _sp_keys()
        psbt = _make_psbt(root, scan_pub, spend_pub, num_inputs=2)

        psbt._sign_with_sp(root)  # per-input shares only, no global yet
        eligible = [0, 1]
        self.assertTrue(psbt.fill_output_scripts(eligible=eligible))

        derived = derive_sp_output_scripts(psbt, eligible=eligible)
        self.assertEqual(
            psbt.outputs[0].script_pubkey.serialize(), derived[0].serialize()
        )

    def test_returns_false_when_shares_incomplete(self):
        root = _root()
        scan_pub, spend_pub = _sp_keys()
        psbt = _make_psbt(root, scan_pub, spend_pub, num_inputs=2)

        # Only input 0 has contributed a share (simulates an incomplete
        # multi-party PSBT still missing a co-signer's contribution).
        priv0 = root.derive([0, 0]).key.secret
        share = compute_ecdh_share(priv0, scan_pub)
        proof = compute_dleq_proof(priv0, scan_pub, share)
        psbt.inputs[0].sp_ecdh_shares[scan_pub.sec()] = share
        psbt.inputs[0].sp_dleq_proofs[scan_pub.sec()] = proof

        self.assertFalse(psbt.fill_output_scripts(eligible=[0, 1]))
        self.assertIsNone(psbt.outputs[0].script_pubkey)

    def test_returns_empty_when_any_eligible_pubkey_unrecoverable(self):
        """A partial A_sum (silently dropping an eligible input whose pubkey
        can't be recovered) would derive wrong scripts, not just incomplete
        ones - must refuse outright rather than sum the rest."""
        root = _root()
        scan_pub, spend_pub = _sp_keys()
        psbt = _make_psbt(root, scan_pub, spend_pub, num_inputs=2)

        # Input 1's pubkey becomes unrecoverable: no bip32_derivations or
        # partial_sigs candidates left to match against its scriptPubKey.
        psbt.inputs[1].bip32_derivations.clear()
        psbt._sign_with_sp(root)  # input 0 still contributes a share fine

        self.assertEqual(derive_sp_output_scripts(psbt, eligible=[0, 1]), {})
        self.assertFalse(psbt.fill_output_scripts(eligible=[0, 1]))
        self.assertIsNone(psbt.outputs[0].script_pubkey)

    def test_raises_when_controlled_input_pubkey_unrecoverable(self):
        """A raw-key input this signer controls (matched by key hash) but whose
        pubkey can't be recovered (no PSBT_IN_BIP32_DERIVATION / partial_sig)
        must raise with a reason, not return a bare 0."""
        raw = ec.PrivateKey(b"\x03" * 32)
        scan_pub, spend_pub = _sp_keys()
        pub = raw.get_public_key()

        psbt = PSBT.create_v2()
        inp = InputScope()
        inp.txid = bytes([0xDD] * 32)
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(
            value=100_000, script_pubkey=p2wpkh(pub)
        )
        psbt.add_input(inp)  # no bip32_derivations: pubkey is unrecoverable
        out = OutputScope()
        out.value = 95_000
        out.sp_data = SilentPaymentData(scan_pub, spend_pub)
        psbt.add_output(out)
        psbt.tx_modifiable_flags = 0

        with self.assertRaisesRegex(SPValidationError, "unrecoverable"):
            psbt.sign_single_party(raw)

    def test_no_sp_outputs_is_a_noop_success(self):
        root = _root()
        pub = root.derive([0, 0]).get_public_key()
        psbt = PSBT.create_v2()
        inp = InputScope()
        inp.txid = bytes([0xCC] * 32)
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=p2wpkh(pub))
        psbt.add_input(inp)
        out = OutputScope()
        out.value = 90_000
        out.script_pubkey = p2wpkh(pub)
        psbt.add_output(out)

        self.assertTrue(psbt.fill_output_scripts())


class TestSPContentProperties(unittest.TestCase):
    def test_has_sp_outputs_and_content(self):
        root = _root()
        scan_pub, spend_pub = _sp_keys()
        psbt = _make_psbt(root, scan_pub, spend_pub)

        self.assertTrue(psbt.has_sp_outputs)
        self.assertFalse(psbt.has_sp_spend_inputs)
        self.assertTrue(psbt.has_sp_content)

    def test_no_sp_content_on_vanilla_psbt(self):
        root = _root()
        pub = root.derive([0, 0]).get_public_key()
        psbt = PSBT.create_v2()
        inp = InputScope()
        inp.txid = bytes([0xCC] * 32)
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=p2wpkh(pub))
        psbt.add_input(inp)
        out = OutputScope()
        out.value = 90_000
        out.script_pubkey = p2wpkh(pub)
        psbt.add_output(out)

        self.assertFalse(psbt.has_sp_outputs)
        self.assertFalse(psbt.has_sp_spend_inputs)
        self.assertFalse(psbt.has_sp_content)


if __name__ == "__main__":
    unittest.main()
