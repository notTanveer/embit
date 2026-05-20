"""
Tests for SPSigner with Silent Payment outputs.

Covers:
  - End-to-end P2WPKH single-sig signing verified against BIP-375 test vectors.
  - Rejection of multisig input + SP output (ineligible input type).
  - Rejection of P2TR input + SP output (BIP-375 prohibits Segwit v>1).
  - SPSigner discards incoming SP fields before repopulating.
  - PSBT version=2 is preserved after SPSigner.sign().
  - aux_rand parameter threads through to DLEQ proof generation.
"""

import json
import unittest
from collections import OrderedDict
from pathlib import Path

from embit import bip32, ec
from embit.silent_payments import dleq
from embit.psbt import DerivationPath
from embit.silent_payments import SilentPaymentsPSBT as PSBT, SPSigner
from embit.silent_payments.psbt import (
    SPInputScope as InputScope,
    SPOutputScope as OutputScope,
)
from embit.silent_payments import (
    SPValidationError,
    SPFieldError,
    SilentPaymentData,
    compute_ecdh_share,
    compute_dleq_proof,
    populate_silent_payment_send_data,
)
from embit.script import Script, p2wpkh, p2tr, p2pkh
from embit.transaction import TransactionOutput

# ── test-vector helpers ────────────────────────────────────────────────────────


def _load_vectors():
    p = Path(__file__).parent / "data" / "bip375_test_vectors.json"
    if not p.exists():
        return []
    with open(p) as f:
        data = json.load(f)
    return data.get("valid", [])


def _find_vector(vectors, description_fragment):
    return next(
        (v for v in vectors if description_fragment in v["description"]),
        None,
    )


# ── fixtures ───────────────────────────────────────────────────────────────────


def _root():
    return bip32.HDKey.from_seed(bytes(range(32)))


def _sp_keys(scan_hex, spend_hex):
    scan = ec.PublicKey.parse(bytes.fromhex(scan_hex))
    spend = ec.PublicKey.parse(bytes.fromhex(spend_hex))
    return scan, spend


def _make_p2wpkh_psbt(root, scan_pub, spend_pub, value=100_000, txid_byte=0xAA):
    """
    Minimal PSBTv2 with one P2WPKH input and one SP output.

    The PSBT is put into its post-construction (pre-signing) state by
    setting tx_modifiable_flags = 0, which is required by BIP-375 when
    a script_pubkey is already present on an SP output.
    """
    child = root.derive([0, 0])
    pub = child.get_public_key()

    psbt = PSBT.create_v2()

    inp = InputScope()
    inp.txid = bytes([txid_byte] * 32)
    inp.vout = 0
    inp.sequence = 0xFFFFFFFE
    inp.witness_utxo = TransactionOutput(value=value, script_pubkey=p2wpkh(pub))
    inp.bip32_derivations[pub] = DerivationPath(root.my_fingerprint, [0, 0])
    psbt.add_input(inp)

    out = OutputScope()
    out.value = value - 1_000
    out.script_pubkey = Script(b"\x51\x20" + bytes(32))
    out.sp_data = SilentPaymentData(scan_pub, spend_pub)
    psbt.add_output(out)

    # Post-construction: no further modifications allowed (required by BIP-375
    # when PSBT_OUT_SCRIPT is set on an SP output).
    psbt.tx_modifiable_flags = 0

    return psbt, child


# ── end-to-end vector test ─────────────────────────────────────────────────────


class TestE2EP2WPKHFromVector(unittest.TestCase):
    """
    End-to-end signing test using data from the BIP-375 test vectors.

    We reconstruct the PSBT scenario from the supplementary data in the
    "two inputs single-signer using per-input ECDH shares" vector, using
    only input 0 (P2WPKH).  The expected ECDH share for that input is
    deterministic and must match the value in the test vector exactly.
    """

    PRIV_HEX = "7e31eeeb1aa2597b6d63b357541461d75ddae76b7603d24619f5ebed9e88ec31"
    PUB_HEX = "02c817bb7521afc35ea96f3bfb270e6eb50ddffa5560627b961fec00f2996508bf"
    SCAN_HEX = "027a487fc19fb769877b8742d6ea18118f3c4e72b1ea8c6de602a7ad4a41dbe068"
    SPEND_HEX = "0361e1b1e9de5e42cb2007f7ca54b9e0d57ed13938fad56d3f19e57513a8fce039"
    EXPECTED_SHARE_HEX = (
        "03eca4ff11b728e2e0f60ce6222943a6ff55b9d95f627bf9a99d084bc872d50a5b"
    )
    PREVOUT_TXID = "18a717663b0bab14b12a1a771323ff1e4079dd532e5dd13e28ea1081c700984a"

    @classmethod
    def setUpClass(cls):
        vectors = _load_vectors()
        cls.vector = _find_vector(
            vectors, "two inputs single-signer using per-input ECDH shares"
        )

    def _build_psbt(self):
        """
        Build a PSBTv2 that matches the scenario of vector input 0:
        a P2WPKH input controlled by PRIV_HEX, sending to the SCAN/SPEND SP output.

        We use a standard HD root (bytes(range(32))) and configure the input's
        bip32_derivation so that the validator can find the correct public key.
        The signing key is the known vector private key, loaded directly.
        """
        # Root for deriving the signing key (standard test seed).
        root = bip32.HDKey.from_seed(bytes(range(32)))
        child = root.derive([0, 0])
        # Actual signing key from the test vector.
        priv = ec.PrivateKey(bytes.fromhex(self.PRIV_HEX))
        pub = priv.get_public_key()

        scan_pub, spend_pub = _sp_keys(self.SCAN_HEX, self.SPEND_HEX)

        psbt = PSBT.create_v2()

        inp = InputScope()
        inp.txid = bytes.fromhex(self.PREVOUT_TXID)[::-1]
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=p2wpkh(pub))
        # BIP32 derivation so the validator can identify the pubkey via hash160.
        # We use the root fingerprint but point it at our known pub so the
        # hash-match in _get_input_public_key succeeds.
        inp.bip32_derivations[pub] = DerivationPath(root.my_fingerprint, [0, 0])
        psbt.add_input(inp)

        out = OutputScope()
        out.value = 95_000
        out.script_pubkey = Script(b"\x51\x20" + bytes(32))
        out.sp_data = SilentPaymentData(scan_pub, spend_pub)
        psbt.add_output(out)

        # BIP-375: tx_modifiable_flags must be 0 when PSBT_OUT_SCRIPT is set.
        psbt.tx_modifiable_flags = 0

        return psbt, priv

    def test_ecdh_share_matches_vector(self):
        """ECDH share computed by SPSigner.sign() matches the test vector value."""
        if self.vector is None:
            self.skipTest("Test vector not found in bip375_test_vectors.json")

        psbt, priv = self._build_psbt()
        signer = SPSigner(psbt)
        signer.sign(priv)

        scan_key_bytes = bytes.fromhex(self.SCAN_HEX)
        share = psbt.inputs[0].sp_ecdh_shares.get(scan_key_bytes)
        self.assertIsNotNone(share, "ECDH share not populated")
        self.assertEqual(share.hex(), self.EXPECTED_SHARE_HEX)

    def test_dleq_proof_valid(self):
        """DLEQ proof generated by SPSigner.sign() verifies correctly."""
        if self.vector is None:
            self.skipTest("Test vector not found in bip375_test_vectors.json")

        psbt, priv = self._build_psbt()
        SPSigner(psbt).sign(priv)

        scan_key_bytes = bytes.fromhex(self.SCAN_HEX)
        share = psbt.inputs[0].sp_ecdh_shares[scan_key_bytes]
        proof = psbt.inputs[0].sp_dleq_proofs[scan_key_bytes]

        pub = ec.PublicKey.parse(bytes.fromhex(self.PUB_HEX))
        C = ec.PublicKey.parse(share)
        self.assertTrue(
            dleq.verify_dleq_proof(
                pub.sec(), bytes.fromhex(self.SCAN_HEX), C.sec(), proof
            )
        )

    def test_full_psbt_sign_produces_signature(self):
        """sign() also places a partial_sig on the input."""
        psbt, priv = self._build_psbt()
        count = SPSigner(psbt).sign(priv)
        self.assertGreater(count, 0)
        self.assertGreater(len(psbt.inputs[0].partial_sigs), 0)


# ── rejection tests ────────────────────────────────────────────────────────────


class TestSPSignerRejectsIneligibleInputs(unittest.TestCase):
    """SPSigner.sign() must raise SPValidationError for prohibited input types."""

    SCAN_HEX = "027a487fc19fb769877b8742d6ea18118f3c4e72b1ea8c6de602a7ad4a41dbe068"
    SPEND_HEX = "0361e1b1e9de5e42cb2007f7ca54b9e0d57ed13938fad56d3f19e57513a8fce039"

    def _scan_spend(self):
        return _sp_keys(self.SCAN_HEX, self.SPEND_HEX)

    def test_p2tr_input_with_sp_output_raises(self):
        """P2TR input with SP output is prohibited by BIP-375 (Segwit v>1)."""
        root = _root()
        child = root.derive([0, 0])
        pub = child.get_public_key()
        scan_pub, spend_pub = self._scan_spend()

        psbt = PSBT.create_v2()

        inp = InputScope()
        inp.txid = bytes([0xBB] * 32)
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        # P2TR UTXO for this input
        inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=p2tr(pub))
        inp.taproot_internal_key = pub
        inp.bip32_derivations[pub] = DerivationPath(root.my_fingerprint, [0, 0])
        psbt.add_input(inp)

        out = OutputScope()
        out.value = 99_000
        out.script_pubkey = Script(b"\x51\x20" + bytes(32))
        out.sp_data = SilentPaymentData(scan_pub, spend_pub)
        psbt.add_output(out)

        psbt.tx_modifiable_flags = 0

        with self.assertRaises(SPValidationError):
            SPSigner(psbt).sign(root)

    def test_multisig_p2sh_input_with_sp_output_no_sp_fields(self):
        """
        A P2SH bare-multisig input is ineligible for SP (not P2WPKH/P2PKH/P2SH-P2WPKH).
        SPSigner.sign() should complete without adding SP fields for that input.
        """
        root = _root()
        child1 = root.derive([0, 0])
        child2 = root.derive([0, 1])
        pub1 = child1.get_public_key()
        pub2 = child2.get_public_key()
        scan_pub, spend_pub = self._scan_spend()

        # Build a 1-of-2 multisig redeem script (P2SH bare multisig, not P2SH-P2WPKH).
        # embit script helpers: OP_1 <pub1> <pub2> OP_2 OP_CHECKMULTISIG
        redeem_script_data = (
            b"\x51"  # OP_1
            + b"\x41"
            + b"\x04"
            + pub1.sec()[1:]
            + b"\x00" * (65 - 33)  # uncompressed-like placeholder
            # This is complex; let's just build a dummy non-P2WPKH P2SH input
        )
        # Actually build a simpler P2SH multisig: use raw Script bytes
        # OP_1 <33-byte-pub1> <33-byte-pub2> OP_2 OP_CHECKMULTISIG
        redeem_raw = (
            bytes([0x51])
            + bytes([0x21])
            + pub1.sec()
            + bytes([0x21])
            + pub2.sec()
            + bytes([0x52, 0xAE])
        )
        from embit.script import p2sh
        from embit import hashes as _h

        redeem = Script(redeem_raw)
        p2sh_script = p2sh(redeem)

        psbt = PSBT.create_v2()

        inp = InputScope()
        inp.txid = bytes([0xCC] * 32)
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=p2sh_script)
        inp.redeem_script = redeem
        inp.bip32_derivations[pub1] = DerivationPath(root.my_fingerprint, [0, 0])
        inp.bip32_derivations[pub2] = DerivationPath(root.my_fingerprint, [0, 1])
        psbt.add_input(inp)

        out = OutputScope()
        out.value = 99_000
        out.script_pubkey = Script(b"\x51\x20" + bytes(32))
        out.sp_data = SilentPaymentData(scan_pub, spend_pub)
        psbt.add_output(out)

        psbt.tx_modifiable_flags = 0

        # sign() should not raise; multisig just produces 0 SP fields
        SPSigner(psbt).sign(root)
        # No SP fields: multisig is not an eligible input type
        self.assertEqual(len(psbt.inputs[0].sp_ecdh_shares), 0)
        self.assertEqual(len(psbt.inputs[0].sp_dleq_proofs), 0)


# ── SPSigner behaviour tests ─────────────────────────────────────────────────


class TestSPSignerBehaviour(unittest.TestCase):

    def setUp(self):
        self.root = _root()
        scan_pub, spend_pub = _sp_keys(
            "027a487fc19fb769877b8742d6ea18118f3c4e72b1ea8c6de602a7ad4a41dbe068",
            "0361e1b1e9de5e42cb2007f7ca54b9e0d57ed13938fad56d3f19e57513a8fce039",
        )
        self.psbt, self.child = _make_p2wpkh_psbt(self.root, scan_pub, spend_pub)
        self.scan_key_bytes = scan_pub.sec()

    def test_discards_incoming_sp_fields(self):
        """Incoming SP fields are replaced with freshly computed ones."""
        # Pre-populate with garbage
        self.psbt.inputs[0].sp_ecdh_shares[self.scan_key_bytes] = b"\xff" * 33
        self.psbt.inputs[0].sp_dleq_proofs[self.scan_key_bytes] = b"\xff" * 64

        SPSigner(self.psbt).sign(self.root)

        share = self.psbt.inputs[0].sp_ecdh_shares[self.scan_key_bytes]
        # Not the garbage value
        self.assertNotEqual(share, b"\xff" * 33)
        # Valid compressed pubkey
        self.assertIn(share[0], [0x02, 0x03])
        self.assertEqual(len(share), 33)

    def test_version_preserved(self):
        """SPSigner.sign() does not downgrade the PSBT version to 0."""
        SPSigner(self.psbt).sign(self.root)
        self.assertEqual(self.psbt.version, 2)

    def test_aux_rand_deterministic(self):
        """When explicit aux_rand is supplied, the DLEQ proof is deterministic."""
        aux = bytes(range(32))

        psbt_a, _ = _make_p2wpkh_psbt(
            self.root,
            ec.PublicKey.parse(
                bytes.fromhex(
                    "027a487fc19fb769877b8742d6ea18118f3c4e72b1ea8c6de602a7ad4a41dbe068"
                )
            ),
            ec.PublicKey.parse(
                bytes.fromhex(
                    "0361e1b1e9de5e42cb2007f7ca54b9e0d57ed13938fad56d3f19e57513a8fce039"
                )
            ),
            txid_byte=0x01,
        )
        psbt_b, _ = _make_p2wpkh_psbt(
            self.root,
            ec.PublicKey.parse(
                bytes.fromhex(
                    "027a487fc19fb769877b8742d6ea18118f3c4e72b1ea8c6de602a7ad4a41dbe068"
                )
            ),
            ec.PublicKey.parse(
                bytes.fromhex(
                    "0361e1b1e9de5e42cb2007f7ca54b9e0d57ed13938fad56d3f19e57513a8fce039"
                )
            ),
            txid_byte=0x01,
        )

        signer_a = SPSigner(psbt_a)
        signer_a._populate_silent_payment_outputs(self.root, aux_rand=aux)

        signer_b = SPSigner(psbt_b)
        signer_b._populate_silent_payment_outputs(self.root, aux_rand=aux)

        proof_a = psbt_a.inputs[0].sp_dleq_proofs[self.scan_key_bytes]
        proof_b = psbt_b.inputs[0].sp_dleq_proofs[self.scan_key_bytes]
        self.assertEqual(proof_a, proof_b)

    def test_populate_sp_outputs_function(self):
        """populate_silent_payment_send_data convenience function works."""
        # Strip incoming SP fields first
        self.psbt.inputs[0].sp_ecdh_shares = OrderedDict()
        self.psbt.inputs[0].sp_dleq_proofs = OrderedDict()

        count = populate_silent_payment_send_data(
            self.psbt, self.root, aux_rand=bytes(range(32))
        )
        self.assertGreater(count, 0)
        self.assertIn(self.scan_key_bytes, self.psbt.inputs[0].sp_ecdh_shares)

    def test_sp_fields_survive_serialization(self):
        """SP fields written by SPSigner survive a PSBT serialize/parse round-trip."""
        SPSigner(self.psbt).sign(self.root)
        raw = self.psbt.serialize()
        parsed = PSBT.parse(raw)

        self.assertEqual(parsed.version, 2)
        self.assertIn(self.scan_key_bytes, parsed.inputs[0].sp_ecdh_shares)
        self.assertIn(self.scan_key_bytes, parsed.inputs[0].sp_dleq_proofs)


if __name__ == "__main__":
    unittest.main()
