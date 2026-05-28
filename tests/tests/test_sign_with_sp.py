from embit import bip32, ec
from embit.silent_payments import dleq
from embit.psbt import DerivationPath
from embit.silent_payments import SilentPaymentsPSBT as PSBT
from embit.silent_payments.psbt import (
    SPInputScope as InputScope,
    SPOutputScope as OutputScope,
)
from embit.silent_payments import (
    SilentPaymentData,
    compute_ecdh_share,
)
from embit.script import Script, p2pkh, p2wpkh
from embit.transaction import TransactionOutput
from unittest import TestCase


def _root():
    return bip32.HDKey.from_seed(bytes(range(32)))


def _sp_keys(scan_byte=0x11, spend_byte=0x22):
    scan_pub = ec.PrivateKey(bytes([scan_byte] * 32)).get_public_key()
    spend_pub = ec.PrivateKey(bytes([spend_byte] * 32)).get_public_key()
    return scan_pub, spend_pub


def _make_sp_psbt(root, scan_pub, spend_pub, txid_byte=0xAA):
    """PSBTv2 with one P2WPKH input (m/0/0) and one SP output."""
    child = root.derive([0, 0])
    child_pub = child.get_public_key()

    psbt = PSBT.create_v2()

    inp = InputScope()
    inp.txid = bytes([txid_byte] * 32)
    inp.vout = 0
    inp.sequence = 0xFFFFFFFE
    inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=p2wpkh(child_pub))
    inp.bip32_derivations[child_pub] = DerivationPath(root.my_fingerprint, [0, 0])
    psbt.add_input(inp)

    out = OutputScope()
    out.value = 99_000
    out.script_pubkey = Script(b"\x51\x20" + bytes(32))  # placeholder p2tr
    out.sp_data = SilentPaymentData(scan_pub, spend_pub)
    psbt.add_output(out)

    return psbt, child


class TestSignWithSP(TestCase):

    def setUp(self):
        self.root = _root()
        self.scan_pub, self.spend_pub = _sp_keys()
        self.psbt, self.child = _make_sp_psbt(self.root, self.scan_pub, self.spend_pub)

    def test_ecdh_share_and_dleq_added(self):
        """sign_with() populates sp_ecdh_shares and sp_dleq_proofs."""
        self.assertEqual(len(self.psbt.inputs[0].sp_ecdh_shares), 0)

        count = self.psbt.sign_with(self.root)

        self.assertGreater(count, 0)
        scan_key_bytes = self.scan_pub.sec()
        inp = self.psbt.inputs[0]
        self.assertIn(scan_key_bytes, inp.sp_ecdh_shares)
        self.assertIn(scan_key_bytes, inp.sp_dleq_proofs)
        self.assertEqual(len(inp.sp_ecdh_shares[scan_key_bytes]), 33)
        self.assertEqual(len(inp.sp_dleq_proofs[scan_key_bytes]), 64)

    def test_ecdh_share_value_correct(self):
        """ECDH share equals compute_ecdh_share(child_priv, scan_key)."""
        self.psbt.sign_with(self.root)
        share = self.psbt.inputs[0].sp_ecdh_shares[self.scan_pub.sec()]
        expected = compute_ecdh_share(self.child.key.secret, self.scan_pub)
        self.assertEqual(share, expected)

    def test_dleq_proof_verifies(self):
        """DLEQ proof verifies against (A = child_pub, B = scan_pub, C = share)."""
        self.psbt.sign_with(self.root)
        scan_key_bytes = self.scan_pub.sec()
        share = self.psbt.inputs[0].sp_ecdh_shares[scan_key_bytes]
        proof = self.psbt.inputs[0].sp_dleq_proofs[scan_key_bytes]

        A = self.child.get_public_key()
        C = ec.PublicKey.parse(share)
        self.assertTrue(
            dleq.verify_dleq_proof(A.sec(), self.scan_pub.sec(), C.sec(), proof)
        )

    def test_existing_share_not_overwritten(self):
        """Calling sign_with() twice does not overwrite existing ECDH shares."""
        self.psbt.sign_with(self.root)
        scan_key_bytes = self.scan_pub.sec()
        original = self.psbt.inputs[0].sp_ecdh_shares[scan_key_bytes]

        self.psbt.sign_with(self.root)

        self.assertEqual(self.psbt.inputs[0].sp_ecdh_shares[scan_key_bytes], original)

    def test_non_sp_output_unaffected(self):
        """PSBTv2 with no SP outputs does not produce SP fields."""
        root = _root()
        child = root.derive([0, 0])
        child_pub = child.get_public_key()

        psbt = PSBT.create_v2()
        inp = InputScope()
        inp.txid = bytes([0xBB] * 32)
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(
            value=100_000, script_pubkey=p2wpkh(child_pub)
        )
        inp.bip32_derivations[child_pub] = DerivationPath(root.my_fingerprint, [0, 0])
        psbt.add_input(inp)

        out = OutputScope()
        out.value = 99_000
        out.script_pubkey = Script(b"\x51\x20" + bytes(32))
        psbt.add_output(out)

        psbt.sign_with(root)
        self.assertEqual(len(psbt.inputs[0].sp_ecdh_shares), 0)
        self.assertEqual(len(psbt.inputs[0].sp_dleq_proofs), 0)

    def test_multiple_scan_keys(self):
        """Separate ECDH/DLEQ entries produced for each unique SP scan key."""
        root = _root()
        scan1, spend1 = _sp_keys(0x11, 0x22)
        scan2, spend2 = _sp_keys(0x33, 0x44)

        child = root.derive([0, 0])
        child_pub = child.get_public_key()

        psbt = PSBT.create_v2()
        inp = InputScope()
        inp.txid = bytes([0xCC] * 32)
        inp.vout = 0
        inp.sequence = 0xFFFFFFFE
        inp.witness_utxo = TransactionOutput(
            value=200_000, script_pubkey=p2wpkh(child_pub)
        )
        inp.bip32_derivations[child_pub] = DerivationPath(root.my_fingerprint, [0, 0])
        psbt.add_input(inp)

        for scan, spend in [(scan1, spend1), (scan2, spend2)]:
            out = OutputScope()
            out.value = 99_000
            out.script_pubkey = Script(b"\x51\x20" + bytes(32))
            out.sp_data = SilentPaymentData(scan, spend)
            psbt.add_output(out)

        psbt.sign_with(root)

        self.assertIn(scan1.sec(), psbt.inputs[0].sp_ecdh_shares)
        self.assertIn(scan2.sec(), psbt.inputs[0].sp_ecdh_shares)
        self.assertEqual(len(psbt.inputs[0].sp_ecdh_shares), 2)

    def test_psbt_roundtrip_preserves_sp_fields(self):
        """ECDH shares and DLEQ proofs survive PSBT serialise/parse round-trip."""
        self.psbt.sign_with(self.root)
        scan_key_bytes = self.scan_pub.sec()

        raw = self.psbt.serialize()
        psbt2 = PSBT.parse(raw)

        self.assertIn(scan_key_bytes, psbt2.inputs[0].sp_ecdh_shares)
        self.assertIn(scan_key_bytes, psbt2.inputs[0].sp_dleq_proofs)
        self.assertEqual(
            psbt2.inputs[0].sp_ecdh_shares[scan_key_bytes],
            self.psbt.inputs[0].sp_ecdh_shares[scan_key_bytes],
        )


class TestGetInputPublicKey(TestCase):

    def _validator(self):
        from embit.silent_payments.validator import BIP375Validator

        # The method under test doesn't use self.psbt; supply a dummy.
        return BIP375Validator(PSBT.create_v2())

    def test_p2wpkh_matched_by_hash160(self):
        """P2WPKH: pubkey returned is the one whose hash160 matches the script."""
        root = _root()
        child = root.derive([0, 0])
        pub = child.get_public_key()

        # 0x44*32 is a valid secp256k1 scalar (well below N)
        decoy = ec.PrivateKey(bytes([0x44] * 32)).get_public_key()

        inp = InputScope()
        inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=p2wpkh(pub))
        # Two BIP32 derivations; only one matches the script hash
        inp.bip32_derivations[pub] = DerivationPath(root.my_fingerprint, [0, 0])
        inp.bip32_derivations[decoy] = DerivationPath(root.my_fingerprint, [0, 1])

        result = self._validator()._get_input_public_key(inp, 0)
        self.assertIsNotNone(result)
        self.assertEqual(result.sec(), pub.sec())

    def test_p2pkh_matched_by_hash160(self):
        """P2PKH: pubkey returned is the one whose hash160 matches the script."""
        root = _root()
        child = root.derive([0, 0])
        pub = child.get_public_key()

        inp = InputScope()
        inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=p2pkh(pub))
        inp.bip32_derivations[pub] = DerivationPath(root.my_fingerprint, [0, 0])

        result = self._validator()._get_input_public_key(inp, 0)
        self.assertIsNotNone(result)
        self.assertEqual(result.sec(), pub.sec())

    def test_p2sh_p2wpkh_matched_by_redeem_script(self):
        """P2SH-P2WPKH: pubkey resolved through the redeem script hash."""
        from embit.script import p2sh

        root = _root()
        child = root.derive([0, 0])
        pub = child.get_public_key()

        redeem = p2wpkh(pub)

        inp = InputScope()
        inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=p2sh(redeem))
        inp.redeem_script = redeem
        inp.bip32_derivations[pub] = DerivationPath(root.my_fingerprint, [0, 0])

        result = self._validator()._get_input_public_key(inp, 0)
        self.assertIsNotNone(result)
        self.assertEqual(result.sec(), pub.sec())

    def test_no_utxo_returns_none(self):
        """Returns None when no UTXO information is present."""
        inp = InputScope()
        result = self._validator()._get_input_public_key(inp, 0)
        self.assertIsNone(result)

    def test_no_matching_derivation_returns_none(self):
        """Returns None when no BIP32 derivation matches the script hash."""
        root = _root()
        child = root.derive([0, 0])
        pub = child.get_public_key()

        wrong_pub = ec.PrivateKey(bytes([0xAB] * 32)).get_public_key()

        inp = InputScope()
        inp.witness_utxo = TransactionOutput(value=100_000, script_pubkey=p2wpkh(pub))
        # Derivation key does not match script hash
        inp.bip32_derivations[wrong_pub] = DerivationPath(root.my_fingerprint, [9, 9])

        result = self._validator()._get_input_public_key(inp, 0)
        self.assertIsNone(result)
