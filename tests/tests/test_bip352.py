"""
BIP-352 test vectors:
https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json
"""

from binascii import unhexlify
from unittest import TestCase

import pytest
from embit import bip352
from embit.ec import PrivateKey
import os
import json
from embit.transaction import COutPoint


BASIC_TEST_VECTORS = [
    {
        "spend_priv_key": "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
        "scan_priv_key": "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
        "sp_address": "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
    },
    {
        "spend_priv_key": "0000000000000000000000000000000000000000000000000000000000000001",
        "scan_priv_key": "0000000000000000000000000000000000000000000000000000000000000002",
        "sp_address": "sp1qqtrqglu5g8kh6mfsg4qxa9wq0nv9cauwfwxw70984wkqnw2uwz0w2qnehen8a7wuhwk9tgrzjh8gwzc8q2dlekedec5djk0js9d3d7qhnq6lqj3s",
    },
]


LABEL_TEST_VECTORS = {
    "spend_priv_key": "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
    "scan_priv_key": "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
    "labels": [2, 3, 1001337],
    "addresses": [
        "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjex54dmqmmv6rw353tsuqhs99ydvadxzrsy9nuvk74epvee55drs734pqq",
        "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqsg59z2rppn4qlkx0yz9sdltmjv3j8zgcqadjn4ug98m3t6plujsq9qvu5n",
        "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq7c2zfthc6x3a5yecwc52nxa0kfd20xuz08zyrjpfw4l2j257yq6qgnkdh5",
    ],
}


class BIP352Test(TestCase):
    def test_generate_silent_payment_address(self):
        """Should generate the expected silent payment address"""
        for test_vector in BASIC_TEST_VECTORS:
            spend_priv_key = PrivateKey(unhexlify(test_vector["spend_priv_key"]))
            scan_priv_key = PrivateKey(unhexlify(test_vector["scan_priv_key"]))
            sp_address = bip352.generate_silent_payment_address(
                scan_priv_key, spend_priv_key.get_public_key()
            )
            assert sp_address == test_vector["sp_address"]

    def test_generate_labeled_silent_payment_address(self):
        """Should generate the expected labeled silent payment addresses"""
        spend_priv_key = PrivateKey(unhexlify(LABEL_TEST_VECTORS["spend_priv_key"]))
        scan_priv_key = PrivateKey(unhexlify(LABEL_TEST_VECTORS["scan_priv_key"]))
        for label, address in zip(
            LABEL_TEST_VECTORS["labels"], LABEL_TEST_VECTORS["addresses"]
        ):
            sp_address = bip352.generate_silent_payment_address(
                scan_priv_key, spend_priv_key.get_public_key(), label
            )
            assert sp_address == address

        # Label may also be a string, but the bip does not provide any test vectors
        bip352.generate_silent_payment_address(
            scan_priv_key, spend_priv_key.get_public_key(), label="tenant 6102"
        )

        # Label may also be passed in as bytes
        bip352.generate_silent_payment_address(
            scan_priv_key, spend_priv_key.get_public_key(), label="I am bytes".encode()
        )

        with pytest.raises(Exception):
            # Label must be an int, str, or bytes
            bip352.generate_silent_payment_address(
                scan_priv_key, spend_priv_key.get_public_key(), label=1.0
            )

    def test_decode_silent_payment_address(self):
        """Should decode the silent payment address and return the expected keys"""
        for test_vector in BASIC_TEST_VECTORS:
            scan_priv_key = PrivateKey(unhexlify(test_vector["scan_priv_key"]))
            spend_priv_key = PrivateKey(unhexlify(test_vector["spend_priv_key"]))
            B_scan, B_spend = bip352.decode_silent_payment_address(
                test_vector["sp_address"]
            )

            assert B_scan == scan_priv_key.get_public_key()
            assert B_spend == spend_priv_key.get_public_key()

        with pytest.raises(ValueError):
            # Invalid HRP
            bip352.decode_silent_payment_address(
                "st1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"
            )

        with pytest.raises(ValueError):
            # Invalid encoding
            bip352.decode_silent_payment_address(
                "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwvm"
            )

    def test_create_silent_payments_outputs(self):
        """Test silent payment output generation using test vectors"""
        __location__ = os.path.realpath(
            os.path.join(os.getcwd(), os.path.dirname(__file__))
        )
        with open(
            os.path.join(__location__, "data/send_and_receive_test_vectors.json"), "r"
        ) as f:
            SEND_AND_RECEIVE_TEST_VECTORS = json.load(f)

        from embit.script import Script, Witness, get_input_pubkey
        from io import BytesIO

        for case in SEND_AND_RECEIVE_TEST_VECTORS:
            for sending_test in case["sending"]:
                given = sending_test["given"]
                expected = sending_test["expected"]

                outpoints: list[COutPoint] = []
                input_privkeys: list[tuple] = []

                for txin in given["vin"]:
                    outpoints.append(
                        COutPoint(txid=unhexlify(txin["txid"]), out_idx=txin["vout"])
                    )

                    spk_hex = txin["prevout"]["scriptPubKey"]["hex"]
                    spk = Script(unhexlify(spk_hex))

                    wit_hex = txin.get("txinwitness", "") or ""
                    witness = None
                    if wit_hex:
                        try:
                            witness = Witness.read_from(BytesIO(bytes.fromhex(wit_hex)))
                        except Exception:
                            witness = None

                    pub = get_input_pubkey(spk, txin.get("scriptSig", ""), witness)
                    if not getattr(pub, "valid", False):
                        continue

                    is_xonly = spk.is_p2tr()
                    input_privkeys.append((unhexlify(txin["private_key"]), is_xonly))

                outputs_map = bip352.create_outputs(
                    input_privkeys=input_privkeys,
                    outpoints=outpoints,
                    recipients=given["recipients"],
                )

                expected_outputs = expected["outputs"]

                actual_outputs = []
                for recipient, outputs in outputs_map.items():
                    actual_outputs.extend(outputs)

                self.assertTrue(
                    any(
                        set(actual_outputs) == set(expected_set)
                        for expected_set in expected_outputs
                    ),
                    f"Actual outputs {set(actual_outputs)} did not match any expected set {expected_outputs}",
                )
