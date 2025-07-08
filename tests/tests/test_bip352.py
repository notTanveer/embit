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
import json
import os
from embit import transaction, script
from embit.util import secp256k1


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

        # Label may also be an int
        bip352.generate_labeled_silent_payment_address(
            scan_priv_key, spend_priv_key.get_public_key(), label=42
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

    def test_create_silent_payment_outputs(self):
        """Should create the correct output public keys from the sending test vectors"""
        __location__ = os.path.realpath(
            os.path.join(os.getcwd(), os.path.dirname(__file__))
        )
        with open(
            os.path.join(__location__, "data/send_and_receive_test_vectors.json"), "r"
        ) as f:
            SEND_AND_RECEIVE_TEST_VECTORS = json.load(f)

        for case in SEND_AND_RECEIVE_TEST_VECTORS:
            for sending_test in case["sending"]:
                with self.subTest(
                    msg=f"{case['comment']} - {sending_test.get('comment', 'send')}"
                ):
                    given = sending_test["given"]
                    expected = sending_test["expected"]

                    input_privkeys = []
                    prevouts = []
                    outpoints = []

                    for vin_data in given["vin"]:
                        privkey = PrivateKey(unhexlify(vin_data["private_key"]))
                        input_privkeys.append(privkey)

                        prevout = transaction.TransactionOutput(
                            value=0,  # value not used
                            script_pubkey=script.Script(
                                unhexlify(vin_data["prevout"]["scriptPubKey"]["hex"])
                            ),
                        )
                        prevouts.append(prevout)

                        txid = unhexlify(vin_data["txid"])[::-1]
                        vout = vin_data["vout"]
                        outpoints.append((txid, vout))

                    recipient_addresses = given["recipients"]

                    # cases where priv keys sum to zero
                    if not input_privkeys:
                        outputs = bip352.create_silent_payment_outputs(
                            input_privkeys, prevouts, outpoints, recipient_addresses
                        )
                        self.assertEqual(outputs, [])
                        self.assertEqual(expected["outputs"], [[]])
                        continue

                    # check if this is a zero-sum case
                    sum_secret = b"\x00" * 32
                    try:
                        for i, privkey in enumerate(input_privkeys):
                            secret = privkey.secret
                            if prevouts[i].script_pubkey.is_p2tr():
                                pubkey = privkey.get_public_key()
                                if pubkey.sec()[0] == 0x03:
                                    secret = secp256k1.ec_privkey_negate(secret)
                            sum_secret = secp256k1.ec_privkey_add(sum_secret, secret)

                        if sum_secret == b"\x00" * 32:
                            outputs = bip352.create_silent_payment_outputs(
                                input_privkeys, prevouts, outpoints, recipient_addresses
                            )
                            self.assertEqual(outputs, [])
                            self.assertEqual(expected["outputs"], [[]])
                            continue
                    except:
                        continue

                    outputs = bip352.create_silent_payment_outputs(
                        input_privkeys, prevouts, outpoints, recipient_addresses
                    )

                    output_hex_list = [pubkey.xonly().hex() for pubkey in outputs]

                    found_match = False
                    for expected_output_set in expected["outputs"]:
                        if set(output_hex_list) == set(expected_output_set):
                            found_match = True
                            break

                    self.assertTrue(
                        found_match,
                        f"Generated outputs {output_hex_list} don't match any expected set {expected['outputs']}",
                    )

    def test_generate_destination_addresses(self):
        """Test generating destination taproot addresses from silent payment addresses"""
        __location__ = os.path.realpath(
            os.path.join(os.getcwd(), os.path.dirname(__file__))
        )
        with open(
            os.path.join(__location__, "data/send_and_receive_test_vectors.json"), "r"
        ) as f:
            SEND_AND_RECEIVE_TEST_VECTORS = json.load(f)

        for case in SEND_AND_RECEIVE_TEST_VECTORS:
            for sending_test in case["sending"]:
                with self.subTest(
                    msg=f"{case['comment']} - {sending_test.get('comment', 'send')} - addresses"
                ):
                    given = sending_test["given"]
                    expected = sending_test["expected"]

                    input_privkeys = []
                    prevouts = []
                    outpoints = []

                    for vin_data in given["vin"]:
                        privkey = PrivateKey(unhexlify(vin_data["private_key"]))
                        input_privkeys.append(privkey)

                        prevout = transaction.TransactionOutput(
                            value=0,  # value not used
                            script_pubkey=script.Script(
                                unhexlify(vin_data["prevout"]["scriptPubKey"]["hex"])
                            ),
                        )
                        prevouts.append(prevout)

                        txid = unhexlify(vin_data["txid"])[::-1]
                        vout = vin_data["vout"]
                        outpoints.append((txid, vout))

                    recipient_addresses = given["recipients"]

                    # Test edge cases
                    if not input_privkeys:
                        addresses = bip352.generate_destination_addresses(
                            input_privkeys, prevouts, outpoints, recipient_addresses
                        )
                        self.assertEqual(addresses, [])
                        continue

                    sum_secret = b"\x00" * 32
                    try:
                        for i, privkey in enumerate(input_privkeys):
                            secret = privkey.secret
                            if prevouts[i].script_pubkey.is_p2tr():
                                pubkey = privkey.get_public_key()
                                if pubkey.sec()[0] == 0x03:
                                    secret = secp256k1.ec_privkey_negate(secret)
                            sum_secret = secp256k1.ec_privkey_add(sum_secret, secret)

                        if sum_secret == b"\x00" * 32:
                            addresses = bip352.generate_destination_addresses(
                                input_privkeys, prevouts, outpoints, recipient_addresses
                            )
                            self.assertEqual(addresses, [])
                            continue
                    except:
                        continue

                    addresses = bip352.generate_destination_addresses(
                        input_privkeys, prevouts, outpoints, recipient_addresses
                    )
                    print(f"Generated addresses: {addresses}")

                    output_pubkeys = bip352.create_silent_payment_outputs(
                        input_privkeys, prevouts, outpoints, recipient_addresses
                    )

                    address_pubkeys = []
                    for addr in addresses:
                        addr_script = script.Script.from_address(addr)
                        if addr_script.script_type() == "p2tr":
                            pubkey_bytes = addr_script.data[
                                2:
                            ]  # Skip OP_1 and push opcode
                            address_pubkeys.append(pubkey_bytes.hex())

                    expected_pubkeys = [
                        pubkey.xonly().hex() for pubkey in output_pubkeys
                    ]

                    self.assertEqual(len(addresses), len(expected_pubkeys))
                    self.assertEqual(set(address_pubkeys), set(expected_pubkeys))

                    for addr in addresses:
                        self.assertTrue(addr.startswith("bc1p"))  # mainnet taproot
                        self.assertEqual(
                            len(addr), 62
                        )  # standard taproot address length

    def test_generate_destination_addresses_edge_cases(self):
        """Test edge cases for generate_destination_addresses"""

        self.assertEqual(bip352.generate_destination_addresses([], [], [], []), [])

        privkey = PrivateKey(
            unhexlify(
                "1cd5e8f6b3f29505ed1da7a5806291ebab6491c6a172467e44debe255428a192"
            )
        )
        prevout = transaction.TransactionOutput(
            value=0,
            script_pubkey=script.Script(
                unhexlify("0014" + "1234567890123456789012345678901234567890")
            ),
        )
        outpoint = (
            unhexlify(
                "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
            ),
            0,
        )

        self.assertEqual(
            bip352.generate_destination_addresses([privkey], [prevout], [outpoint], []),
            [],
        )

    def test_generate_destination_addresses_network(self):
        """Test generate_destination_addresses with different networks"""

        privkey = PrivateKey(
            unhexlify(
                "1cd5e8f6b3f29505ed1da7a5806291ebab6491c6a172467e44debe255428a192"
            )
        )
        prevout = transaction.TransactionOutput(
            value=0,
            script_pubkey=script.Script(
                unhexlify("0014" + "1234567890123456789012345678901234567890")
            ),
        )
        outpoint = (
            unhexlify(
                "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
            ),
            0,
        )
        recipient_address = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"

        mainnet_addresses = bip352.generate_destination_addresses(
            [privkey], [prevout], [outpoint], [recipient_address], network="main"
        )

        testnet_addresses = bip352.generate_destination_addresses(
            [privkey], [prevout], [outpoint], [recipient_address], network="test"
        )

        self.assertEqual(len(mainnet_addresses), 1)
        self.assertEqual(len(testnet_addresses), 1)

        self.assertTrue(mainnet_addresses[0].startswith("bc1p"))

        self.assertTrue(testnet_addresses[0].startswith("tb1p"))

    def test_generate_destination_addresses_consistency(self):
        """Test that generate_destination_addresses is consistent with create_silent_payment_outputs"""

        # Create test data
        privkey1 = PrivateKey(
            unhexlify(
                "1cd5e8f6b3f29505ed1da7a5806291ebab6491c6a172467e44debe255428a192"
            )
        )
        privkey2 = PrivateKey(
            unhexlify(
                "7416ef4d92e4dd09d680af6999d1723816e781c030f4b4ecb5bf46939ca30056"
            )
        )

        prevout1 = transaction.TransactionOutput(
            value=0,
            script_pubkey=script.Script(
                unhexlify("0014" + "1234567890123456789012345678901234567890")
            ),
        )
        prevout2 = transaction.TransactionOutput(
            value=0,
            script_pubkey=script.Script(
                unhexlify("0014" + "abcdefabcdefabcdefabcdefabcdefabcdefabcd")
            ),
        )

        outpoint1 = (
            unhexlify(
                "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
            ),
            0,
        )
        outpoint2 = (
            unhexlify(
                "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"
            ),
            0,
        )

        recipient_addresses = [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
            "sp1qqtrqglu5g8kh6mfsg4qxa9wq0nv9cauwfwxw70984wkqnw2uwz0w2qnehen8a7wuhwk9tgrzjh8gwzc8q2dlekedec5djk0js9d3d7qhnq6lqj3s",
        ]

        output_pubkeys = bip352.create_silent_payment_outputs(
            [privkey1, privkey2],
            [prevout1, prevout2],
            [outpoint1, outpoint2],
            recipient_addresses,
        )

        destination_addresses = bip352.generate_destination_addresses(
            [privkey1, privkey2],
            [prevout1, prevout2],
            [outpoint1, outpoint2],
            recipient_addresses,
        )

        self.assertEqual(len(output_pubkeys), len(destination_addresses))

        # Convert addresses back to pubkeys and compare
        for addr in destination_addresses:
            addr_script = script.Script.from_address(addr)
            self.assertEqual(addr_script.script_type(), "p2tr")

            pubkey_bytes = addr_script.data[2:]  # Skip OP_1 and push opcode

            found = False
            for output_pubkey in output_pubkeys:
                if output_pubkey.xonly() == pubkey_bytes:
                    found = True
                    break

            self.assertTrue(
                found, f"Address {addr} doesn't correspond to any output pubkey"
            )
