from unittest import TestCase

from embit import ec
from embit.silent_payments import (
    bip352,
    dleq,
    SilentPaymentsPSBT as PSBT,
    SPValidationError,
    populate_silent_payment_send_data_from_keys as populate_silent_payment_send_data,
)
from embit.script import Script, p2tr, p2wpkh
from embit.transaction import Transaction, TransactionInput, TransactionOutput, COutPoint
from embit.util.key import SECP256K1_ORDER


class BIP375SendFlowTest(TestCase):
    def _make_psbtv2_with_eligible_inputs(self):
        tx = Transaction(version=2, locktime=0)
        tx.vin = [
            TransactionInput(txid=b"\x11" * 32, vout=0, sequence=0xFFFFFFFE),
            TransactionInput(txid=b"\x22" * 32, vout=1, sequence=0xFFFFFFFE),
        ]
        tx.vout = [
            TransactionOutput(value=12000, script_pubkey=Script(b"\x51")),
            TransactionOutput(value=34000, script_pubkey=Script(b"\x51")),
        ]

        psbt = PSBT(tx, version=2)

        in_priv0 = b"\x11" * 32
        in_priv1 = b"\x22" * 32

        in_pub0 = ec.PrivateKey(in_priv0).get_public_key()
        in_pub1 = ec.PrivateKey(in_priv1).get_public_key()

        psbt.inputs[0].witness_utxo = TransactionOutput(
            value=50000,
            script_pubkey=p2wpkh(in_pub0),
        )
        psbt.inputs[1].witness_utxo = TransactionOutput(
            value=70000,
            script_pubkey=p2wpkh(in_pub1),
        )

        return psbt, {0: in_priv0, 1: in_priv1}

    def _make_recipients(self):
        scan_priv1 = ec.PrivateKey(b"\x31" * 32)
        spend_priv1 = ec.PrivateKey(b"\x41" * 32)
        scan_priv2 = ec.PrivateKey(b"\x32" * 32)
        spend_priv2 = ec.PrivateKey(b"\x42" * 32)

        addr1 = bip352.generate_silent_payment_address(
            scan_priv1,
            spend_priv1.get_public_key(),
        )
        addr2 = bip352.generate_silent_payment_address(
            scan_priv2,
            spend_priv2.get_public_key(),
        )

        # Intentionally out-of-order output indexes to ensure deterministic derivation
        # is independent from input recipient list order.
        recipients = [
            (1, addr2, None),
            (0, addr1, 7),
        ]
        return recipients

    def test_populate_send_data_sets_sp_fields_and_scripts(self):
        psbt, input_private_keys = self._make_psbtv2_with_eligible_inputs()
        recipients = self._make_recipients()

        derived = populate_silent_payment_send_data(
            psbt,
            recipients,
            input_private_keys,
            include_global_fields=True,
            include_input_fields=False,
            set_output_scripts=True,
        )

        self.assertEqual(set(derived.keys()), {0, 1})
        self.assertEqual(psbt.tx_modifiable_flags, 0)

        for output_index, _, _ in recipients:
            out = psbt.outputs[output_index]
            self.assertIsNotNone(out.sp_data)

            expected_script = Script(b"\x51\x20" + derived[output_index])
            self.assertEqual(out.script_pubkey.data, expected_script.data)

    def test_populate_send_data_is_deterministic_for_outputs(self):
        recipients = self._make_recipients()

        psbt1, keys1 = self._make_psbtv2_with_eligible_inputs()
        derived1 = populate_silent_payment_send_data(
            psbt1,
            recipients,
            keys1,
            include_global_fields=True,
            include_input_fields=False,
            set_output_scripts=True,
        )

        psbt2, keys2 = self._make_psbtv2_with_eligible_inputs()
        derived2 = populate_silent_payment_send_data(
            psbt2,
            recipients,
            keys2,
            include_global_fields=True,
            include_input_fields=False,
            set_output_scripts=True,
        )

        self.assertEqual(derived1, derived2)
        self.assertEqual(
            psbt1.outputs[0].script_pubkey.data, psbt2.outputs[0].script_pubkey.data
        )
        self.assertEqual(
            psbt1.outputs[1].script_pubkey.data, psbt2.outputs[1].script_pubkey.data
        )

    def test_populate_send_data_generates_verifiable_global_dleq(self):
        psbt, input_private_keys = self._make_psbtv2_with_eligible_inputs()
        recipients = self._make_recipients()

        populate_silent_payment_send_data(
            psbt,
            recipients,
            input_private_keys,
            include_global_fields=True,
            include_input_fields=False,
            set_output_scripts=False,
        )

        scan_key, _ = bip352.decode_silent_payment_address(recipients[0][1])
        scan_key_bytes = scan_key.sec()

        global_share = psbt.sp_ecdh_shares[scan_key_bytes]
        global_proof = psbt.sp_dleq_proofs[scan_key_bytes]

        a_sum = (
            int.from_bytes(input_private_keys[0], "big")
            + int.from_bytes(input_private_keys[1], "big")
        ) % SECP256K1_ORDER
        a_pub = ec.PrivateKey(a_sum.to_bytes(32, "big")).get_public_key()
        c_pub = ec.PublicKey.parse(global_share)

        self.assertTrue(
            dleq.verify_dleq_proof(
                a_pub.sec(),
                scan_key.sec(),
                c_pub.sec(),
                global_proof,
            )
        )

    def test_populate_send_data_supports_per_input_fields_only(self):
        psbt, input_private_keys = self._make_psbtv2_with_eligible_inputs()
        recipients = self._make_recipients()

        populate_silent_payment_send_data(
            psbt,
            recipients,
            input_private_keys,
            include_global_fields=False,
            include_input_fields=True,
            set_output_scripts=False,
        )

        self.assertEqual(psbt.sp_ecdh_shares, {})
        self.assertEqual(psbt.sp_dleq_proofs, {})

        scan_key, _ = bip352.decode_silent_payment_address(recipients[0][1])
        scan_key_bytes = scan_key.sec()
        self.assertIn(scan_key_bytes, psbt.inputs[0].sp_ecdh_shares)
        self.assertIn(scan_key_bytes, psbt.inputs[1].sp_ecdh_shares)
        self.assertIn(scan_key_bytes, psbt.inputs[0].sp_dleq_proofs)
        self.assertIn(scan_key_bytes, psbt.inputs[1].sp_dleq_proofs)

    def test_populate_send_data_rejects_invalid_inputs(self):
        psbt, input_private_keys = self._make_psbtv2_with_eligible_inputs()
        recipients = self._make_recipients()

        with self.assertRaises(SPValidationError):
            populate_silent_payment_send_data(
                psbt,
                [(0, "sp1invalidaddress", None)],
                input_private_keys,
            )

        with self.assertRaises(SPValidationError):
            populate_silent_payment_send_data(
                psbt,
                recipients,
                {0: input_private_keys[0]},
            )

        with self.assertRaises(SPValidationError):
            populate_silent_payment_send_data(
                psbt,
                [(3, recipients[0][1], None)],
                input_private_keys,
            )

        tx = Transaction(version=2, locktime=0)
        tx.vin = [TransactionInput(txid=b"\x33" * 32, vout=0, sequence=0xFFFFFFFE)]
        tx.vout = [TransactionOutput(value=1000, script_pubkey=Script(b"\x51"))]
        psbt_v0 = PSBT(tx, version=0)

        with self.assertRaises(SPValidationError):
            populate_silent_payment_send_data(
                psbt_v0,
                [(0, recipients[0][1], None)],
                {0: b"\x44" * 32},
            )

    def test_output_key_matches_bip352_reference(self):
        """populate_silent_payment_send_data_from_keys must produce the same output
        key as bip352.create_outputs() for the same inputs, outpoints, and recipient.

        This is the canonical cross-validation that catches both Bug 1 (missing
        input_hash) and Bug 2 (32-byte x-only vs 33-byte compressed shared secret).
        """
        psbt, input_private_keys = self._make_psbtv2_with_eligible_inputs()
        recipients = self._make_recipients()

        # Only use the first recipient (single scan-key group) for simplicity.
        single_recipient = [recipients[0]]  # (output_index=1, addr2, None)
        addr = single_recipient[0][1]

        derived = populate_silent_payment_send_data(
            psbt,
            single_recipient,
            input_private_keys,
            include_global_fields=True,
            include_input_fields=False,
            set_output_scripts=True,
        )
        psbt_xonly = derived[single_recipient[0][0]]

        # Independently derive expected output using the BIP-352 reference.
        outpoints = [
            COutPoint(txid=psbt.tx.vin[i].txid, out_idx=psbt.tx.vin[i].vout)
            for i in range(len(psbt.inputs))
        ]
        ref_outputs = bip352.create_outputs(
            [(input_private_keys[0], False), (input_private_keys[1], False)],
            outpoints,
            [addr],
        )
        ref_xonly = bytes.fromhex(ref_outputs[addr][0])

        self.assertEqual(
            psbt_xonly,
            ref_xonly,
            "Output key mismatch: PSBT=%s BIP-352=%s" % (psbt_xonly.hex(), ref_xonly.hex()),
        )

    def test_output_key_matches_bip352_reference_two_recipients(self):
        """Same cross-validation with two distinct scan-key groups (two recipients).

        Exercises input_hash being applied independently per scan-key group
        while the A_sum/outpoints are shared.  Uses unlabeled addresses so
        bip352.create_outputs() (which ignores labels) gives the right reference.
        """
        psbt, input_private_keys = self._make_psbtv2_with_eligible_inputs()

        scan_priv_a = ec.PrivateKey(b"\x33" * 32)
        spend_priv_a = ec.PrivateKey(b"\x44" * 32)
        scan_priv_b = ec.PrivateKey(b"\x55" * 32)
        spend_priv_b = ec.PrivateKey(b"\x66" * 32)

        addr_a = bip352.generate_silent_payment_address(
            scan_priv_a, spend_priv_a.get_public_key()
        )
        addr_b = bip352.generate_silent_payment_address(
            scan_priv_b, spend_priv_b.get_public_key()
        )
        # Two unlabeled recipients at distinct output indices.
        recipients = [(0, addr_a, None), (1, addr_b, None)]

        derived = populate_silent_payment_send_data(
            psbt,
            recipients,
            input_private_keys,
            include_global_fields=True,
            include_input_fields=False,
            set_output_scripts=True,
        )

        outpoints = [
            COutPoint(txid=psbt.tx.vin[i].txid, out_idx=psbt.tx.vin[i].vout)
            for i in range(len(psbt.inputs))
        ]
        input_privkey_list = [(input_private_keys[i], False) for i in range(len(psbt.inputs))]

        for output_index, addr, _label in recipients:
            ref_outputs = bip352.create_outputs(
                input_privkey_list,
                outpoints,
                [addr],
            )
            ref_xonly = bytes.fromhex(ref_outputs[addr][0])
            psbt_xonly = derived[output_index]
            self.assertEqual(
                psbt_xonly,
                ref_xonly,
                "Output key mismatch for addr %s: PSBT=%s BIP-352=%s"
                % (addr[:20], psbt_xonly.hex(), ref_xonly.hex()),
            )
