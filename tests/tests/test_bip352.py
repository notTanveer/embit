"""
BIP-352 test vectors:
https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json
"""

from binascii import unhexlify
from unittest import TestCase

import pytest
from embit import bip352
from embit.ec import PrivateKey
from embit.networks import NETWORKS
import os
import json
from embit.transaction import (
    COutPoint,
    VinInfo,
    CTxInWitness,
    deser_txid,
    get_pubkey_from_input,
    from_hex,
)
from embit.script import Script


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
                scan_priv_key.get_public_key(), spend_priv_key.get_public_key()
            )
            assert sp_address == test_vector["sp_address"]

    def test_generate_silent_payment_address_for_network(self):
        """Test network silent payment addrs should start with "tsp" """
        test_networks = [k for k in NETWORKS.keys() if k != "main"]
        scan_pubkey = PrivateKey(
            unhexlify(BASIC_TEST_VECTORS[0]["spend_priv_key"])
        ).get_public_key()
        spend_pubkey = PrivateKey(
            unhexlify(BASIC_TEST_VECTORS[0]["scan_priv_key"])
        ).get_public_key()

        for network in test_networks:
            payment_addr = bip352.generate_silent_payment_address(
                scan_pubkey, spend_pubkey, network=network
            )
            assert payment_addr.startswith("tsp")

    def test_generate_labeled_silent_payment_address(self):
        """Should generate the expected labeled silent payment addresses"""
        spend_priv_key = PrivateKey(unhexlify(LABEL_TEST_VECTORS["spend_priv_key"]))
        scan_priv_key = PrivateKey(unhexlify(LABEL_TEST_VECTORS["scan_priv_key"]))
        for label, address in zip(
            LABEL_TEST_VECTORS["labels"], LABEL_TEST_VECTORS["addresses"]
        ):
            sp_address = bip352.generate_labeled_silent_payment_address(
                scan_priv_key, spend_priv_key.get_public_key(), label
            )
            assert sp_address == address

        # Label may also be a string, but the bip does not provide any test vectors
        bip352.generate_labeled_silent_payment_address(
            scan_priv_key, spend_priv_key.get_public_key(), label="tenant 6102"
        )

        # Label may also be passed in as bytes
        bip352.generate_labeled_silent_payment_address(
            scan_priv_key, spend_priv_key.get_public_key(), label="I am bytes".encode()
        )

        with pytest.raises(Exception):
            # Label is required
            bip352.generate_labeled_silent_payment_address(
                scan_priv_key, spend_priv_key.get_public_key()
            )

        with pytest.raises(Exception):
            # Label must be an int, str, or bytes
            bip352.generate_labeled_silent_payment_address(
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

        for case in SEND_AND_RECEIVE_TEST_VECTORS:
            for sending_test in case["sending"]:
                given = sending_test["given"]
                expected = sending_test["expected"]

                vins = [
                    VinInfo(
                        outpoint=COutPoint(
                            hash=deser_txid(input["txid"]), n=input["vout"]
                        ),
                        scriptSig=unhexlify(input["scriptSig"]),
                        txinwitness=CTxInWitness().deserialize(
                            from_hex(input["txinwitness"])
                        ),
                        prevout=unhexlify(input["prevout"]["scriptPubKey"]["hex"]),
                        private_key=(unhexlify(input["private_key"])),
                    )
                    for input in given["vin"]
                ]

                input_priv_keys = []
                input_pub_keys = []
                for vin in vins:
                    pubkey = get_pubkey_from_input(vin)
                    if not pubkey.valid:
                        continue
                    input_priv_keys.append(
                        (
                            vin.private_key,
                            Script(vin.prevout).is_p2tr(),
                        )
                    )
                    input_pub_keys.append(pubkey)

                sending_outputs = []
                if len(input_pub_keys) > 0:
                    outpoints = [vin.outpoint for vin in vins]
                    sending_outputs = bip352.create_outputs(
                        input_priv_keys, outpoints, given["recipients"]
                    )
                    # Note: order doesn't matter for creating/finding the outputs. However, different orderings of the recipient addresses
                    # will produce different generated outputs if sending to multiple silent payment addresses belonging to the
                    # same sender but with different labels. Because of this, expected["outputs"] contains all possible valid output sets,
                    # based on all possible permutations of recipient address orderings. Must match exactly one of the possible output sets.
                    assert any(
                        set(sending_outputs) == set(lst) for lst in expected["outputs"]
                    ), "Sending test failed"
                    print(f"Sending outputs: {sending_outputs}")
                else:
                    assert (
                        sending_outputs == expected["outputs"][0] == []
                    ), "Sending test failed"
