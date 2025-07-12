import unittest
from binascii import unhexlify
from embit import bip352, ec, script


class TestBIP352(unittest.TestCase):
    def test_simple_send(self):
        """
        Tests a simple send with two inputs based on BIP-352 test vectors.
        Comment: "Simple send: two inputs"
        """
        # Hardcoded values from the first test case in send_and_receive_test_vectors.json

        # --- Given ---

        # Input private keys and whether they are for x-only (taproot) outputs.
        # For this test case, inputs are P2PKH, so is_xonly is False.
        input_privkeys = [
            (
                ec.PrivateKey(
                    unhexlify(
                        "eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1"
                    )
                ),
                False,
            ),
            (
                ec.PrivateKey(
                    unhexlify(
                        "93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16"
                    )
                ),
                False,
            ),
        ]

        # Outpoints (txid, vout) for the inputs
        outpoints = [
            (
                unhexlify(
                    "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
                ),
                0,
            ),
            (
                unhexlify(
                    "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"
                ),
                0,
            ),
        ]

        # Recipient silent payment addresses
        recipient_addresses = [
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"
        ]

        # Amounts for each recipient
        # amounts = [100000]

        # --- Expected ---

        # Expected output x-only public key
        expected_output_pubkey = (
            "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"
        )

        # --- Action ---

        # Generate the destination outputs using create_outputs
        outputs = bip352.create_outputs(input_privkeys, outpoints, recipient_addresses)
        print(outputs)

        # --- Assertion ---
        self.assertEqual(len(outputs), 1)

        # The output object should have a pubkey attribute directly
        generated_pubkey_hex = outputs[0].pubkey.hex()
        print(f"Generated pubkey: {generated_pubkey_hex}")

        self.assertEqual(generated_pubkey_hex, expected_output_pubkey)


if __name__ == "__main__":
    unittest.main()
