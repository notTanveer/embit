"""
BIP-375 Test Suite

Tests for Silent Payments PSBT support using official BIP-375 test vectors.
"""

import unittest
import json
from pathlib import Path

from embit.psbt import PSBT, PSBTError
from embit.silent_payments.validator import validate_bip375_psbt
from embit.silent_payments import (
    SPValidationError,
    SPFieldError,
    SilentPaymentData,
    ECDHShare,
    DLEQProof,
)
from embit import ec


class TestBIP375FieldParsing(unittest.TestCase):
    """Test SP field parsing and serialization."""

    def test_silent_payment_data_serialize(self):
        """Test SilentPaymentData serialization."""
        # Create test keys
        scan_key = ec.PrivateKey(b"\x01" * 32).get_public_key()
        spend_key = ec.PrivateKey(b"\x02" * 32).get_public_key()

        sp_data = SilentPaymentData(scan_key, spend_key)
        serialized = sp_data.serialize()

        # Should be 66 bytes (33 + 33)
        self.assertEqual(len(serialized), 66)
        self.assertEqual(serialized[:33], scan_key.sec())
        self.assertEqual(serialized[33:], spend_key.sec())

    def test_silent_payment_data_parse(self):
        """Test SilentPaymentData parsing."""
        # Create test keys
        scan_key = ec.PrivateKey(b"\x01" * 32).get_public_key()
        spend_key = ec.PrivateKey(b"\x02" * 32).get_public_key()

        data = scan_key.sec() + spend_key.sec()
        sp_data = SilentPaymentData.parse(data)

        self.assertEqual(sp_data.scan_key.sec(), scan_key.sec())
        self.assertEqual(sp_data.spend_key.sec(), spend_key.sec())

    def test_silent_payment_data_parse_invalid_length(self):
        """Test parsing rejects invalid length."""
        with self.assertRaises(SPFieldError):
            SilentPaymentData.parse(b"\x00" * 65)  # Too short

        with self.assertRaises(SPFieldError):
            SilentPaymentData.parse(b"\x00" * 67)  # Too long

    def test_ecdh_share_validate_length(self):
        """Test ECDHShare validates length."""
        scan_key = ec.PrivateKey(b"\x01" * 32).get_public_key()

        # Valid
        share = ECDHShare(scan_key, b"\x02" + b"\x00" * 32)
        self.assertEqual(len(share.share), 33)

        # Invalid length
        with self.assertRaises(SPFieldError):
            ECDHShare(scan_key, b"\x02" + b"\x00" * 31)

    def test_dleq_proof_validate_length(self):
        """Test DLEQProof validates length."""
        scan_key = ec.PrivateKey(b"\x01" * 32).get_public_key()

        # Valid
        proof = DLEQProof(scan_key, b"\x00" * 64)
        self.assertEqual(len(proof.proof), 64)

        # Invalid length
        with self.assertRaises(SPFieldError):
            DLEQProof(scan_key, b"\x00" * 63)


class TestBIP375TestVectors(unittest.TestCase):
    """Test using official BIP-375 test vectors."""

    @classmethod
    def setUpClass(cls):
        """Load test vectors."""
        vectors_path = Path(__file__).parent / "data" / "bip375_test_vectors.json"
        if not vectors_path.exists():
            # Try alternative paths
            vectors_path = Path("tests/tests/data/bip375_test_vectors.json")

        if vectors_path.exists():
            with open(vectors_path) as f:
                data = json.load(f)
            cls.invalid_vectors = data.get("invalid", [])
            cls.valid_vectors = data.get("valid", [])
        else:
            cls.invalid_vectors = []
            cls.valid_vectors = []
            print(f"Warning: test vectors not found at {vectors_path}")

    def parse_psbt_vector(self, vector, allow_failure=False):
        """Parse a test vector PSBT."""
        try:
            return PSBT.from_base64(vector["psbt"])
        except Exception:
            if allow_failure:
                return None
            raise

    def test_invalid_structure_missing_sp_info(self):
        """Test: missing PSBT_OUT_SP_V0_INFO field when PSBT_OUT_SP_V0_LABEL set."""
        # This should fail during parsing or validation
        vector = next(
            (
                v
                for v in self.invalid_vectors
                if "missing PSBT_OUT_SP_V0_INFO" in v["description"]
            ),
            None,
        )
        if not vector:
            self.skipTest("Test vector not found")

        psbt = self.parse_psbt_vector(vector, allow_failure=True)
        if psbt:
            # If parsing succeeded, validation should fail
            with self.assertRaises(SPValidationError):
                validate_bip375_psbt(psbt, skip_output_scripts=True)

    def test_invalid_structure_incorrect_sp_info_length(self):
        """Test: incorrect byte length for PSBT_OUT_SP_V0_INFO field."""
        vector = next(
            (
                v
                for v in self.invalid_vectors
                if "incorrect byte length for PSBT_OUT_SP_V0_INFO" in v["description"]
            ),
            None,
        )
        if not vector:
            self.skipTest("Test vector not found")

        # Should fail during parsing
        with self.assertRaises((PSBTError, SPFieldError)):
            self.parse_psbt_vector(vector)

    def test_invalid_ecdh_share_length(self):
        """Test: incorrect byte length for PSBT_IN_SP_ECDH_SHARE field."""
        vector = next(
            (
                v
                for v in self.invalid_vectors
                if "incorrect byte length for PSBT_IN_SP_ECDH_SHARE" in v["description"]
            ),
            None,
        )
        if not vector:
            self.skipTest("Test vector not found")

        # Should fail during parsing
        with self.assertRaises(PSBTError):
            self.parse_psbt_vector(vector)

    def test_invalid_dleq_proof_length(self):
        """Test: incorrect byte length for PSBT_IN_SP_DLEQ field."""
        vector = next(
            (
                v
                for v in self.invalid_vectors
                if "incorrect byte length for PSBT_IN_SP_DLEQ" in v["description"]
            ),
            None,
        )
        if not vector:
            self.skipTest("Test vector not found")

        # Should fail during parsing
        with self.assertRaises(PSBTError):
            self.parse_psbt_vector(vector)

    def test_valid_single_input_single_signer(self):
        """Test: one P2PKH input single-signer."""
        vector = next(
            (v for v in self.valid_vectors if "one P2PKH input" in v["description"]),
            None,
        )
        if not vector:
            self.skipTest("Test vector not found")

        psbt = self.parse_psbt_vector(vector)
        self.assertIsNotNone(psbt)

        # Basic parsing check
        self.assertEqual(psbt.version, 2)
        self.assertGreater(len(psbt.outputs), 0)

    def test_valid_with_sp_outputs(self):
        """Test: valid PSBT with SP outputs can be parsed."""
        # Find first valid vector with SP outputs
        for vector in self.valid_vectors:
            psbt = self.parse_psbt_vector(vector)
            if psbt and any(out.sp_data is not None for out in psbt.outputs):
                # Found one - basic check
                self.assertEqual(psbt.version, 2)
                break

    def test_invalid_vectors_fail_validation(self):
        """Test a sample of invalid vectors."""
        # Test structure validation failures
        invalid_categories = {
            "psbt structure": [],
            "ecdh coverage": [],
            "input eligibility": [],
            "output scripts": [],
        }

        for vector in self.invalid_vectors[:5]:  # Sample first 5
            description = vector["description"]
            category = next(
                (k for k in invalid_categories if k in description.lower()),
                None,
            )
            if category:
                psbt = self.parse_psbt_vector(vector, allow_failure=True)
                if psbt:
                    try:
                        validate_bip375_psbt(psbt, skip_output_scripts=True)
                        # Should not get here
                        self.fail(f"Vector should have failed: {description}")
                    except (SPValidationError, SPFieldError):
                        # Expected
                        pass


class TestBIP375Integration(unittest.TestCase):
    """Integration tests for BIP-375 functionality."""

    def test_psbt_roundtrip_with_sp_fields(self):
        """Test that PSBTs with SP fields can be serialized and deserialized."""
        # Create a basic PSBTv2 with SP fields
        from embit.transaction import Transaction, TransactionInput, TransactionOutput
        from embit.script import Script

        # Create simple transaction
        tx = Transaction(version=2, locktime=0)
        tx.vin = [
            TransactionInput(
                txid=b"\x00" * 32,
                vout=0,
                sequence=0xFFFFFFFE,
            )
        ]
        tx.vout = [
            TransactionOutput(
                value=100000,
                script_pubkey=Script(b"\x51"),
            )
        ]

        # Create PSBT from transaction
        psbt = PSBT(tx, version=2)

        # Add SP output data
        scan_key = ec.PrivateKey(b"\x01" * 32).get_public_key()
        spend_key = ec.PrivateKey(b"\x02" * 32).get_public_key()

        psbt.outputs[0].sp_data = SilentPaymentData(scan_key, spend_key)
        psbt.outputs[0].sp_label = None

        # Serialize and deserialize
        serialized = psbt.serialize()
        psbt2 = PSBT.parse(serialized)

        # Check SP data survived roundtrip
        self.assertIsNotNone(psbt2.outputs[0].sp_data)
        self.assertEqual(
            psbt2.outputs[0].sp_data.scan_key.sec(),
            scan_key.sec(),
        )
        self.assertEqual(
            psbt2.outputs[0].sp_data.spend_key.sec(),
            spend_key.sec(),
        )


class TestECDHComputations(unittest.TestCase):
    """Test ECDH share computations."""

    def test_compute_ecdh_share_single_key(self):
        """Test computing ECDH share for single key."""
        from embit.silent_payments import compute_ecdh_share

        priv = b"\x01" * 32
        scan_key = ec.PrivateKey(b"\x02" * 32).get_public_key()

        share = compute_ecdh_share(priv, scan_key)

        # Should be 33 bytes compressed pubkey
        self.assertEqual(len(share), 33)
        self.assertIn(share[0], [0x02, 0x03])

    def test_compute_global_ecdh_share(self):
        """Test computing global ECDH share."""
        from embit.silent_payments import compute_global_ecdh_share

        privs = [b"\x01" * 32, b"\x02" * 32]
        scan_key = ec.PrivateKey(b"\x03" * 32).get_public_key()

        share = compute_global_ecdh_share(privs, scan_key)

        # Should be 33 bytes compressed pubkey
        self.assertEqual(len(share), 33)
        self.assertIn(share[0], [0x02, 0x03])

    def test_dleq_proof_generation_and_verification(self):
        """Test DLEQ proof generation and verification."""
        from embit.silent_payments import compute_dleq_proof

        priv = b"\x01" * 32
        scan_key = ec.PrivateKey(b"\x02" * 32).get_public_key()

        # Generate share and proof
        from embit.silent_payments import compute_ecdh_share

        share = compute_ecdh_share(priv, scan_key)
        proof = compute_dleq_proof(priv, scan_key, share)

        # Verify proof
        from embit.silent_payments import dleq

        pub_key = ec.PrivateKey(priv).get_public_key()
        C = ec.PublicKey.parse(share)

        self.assertTrue(
            dleq.verify_dleq_proof(pub_key.sec(), scan_key.sec(), C.sec(), proof)
        )


if __name__ == "__main__":
    unittest.main()
