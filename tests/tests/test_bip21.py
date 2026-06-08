from unittest import TestCase
from embit import bip21


# BIP21 and BIP321 test vectors
# https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki#examples
# https://github.com/bitcoin/bips/blob/master/bip-0321.mediawiki#examples

VECTORS_BIP21_VALID = [
    "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W",
    "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?label=Luke-Jr",
    "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=20.3&label=Luke-Jr",
    "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz",
    "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?somethingyoudontunderstand=50&somethingelseyoudontget=999",
]

VECTORS_BIP21_INVALID = [
    "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-somethingyoudontunderstand=50&req-somethingelseyoudontget=999",
    "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?label=Luke-Jr&label=Matt",
    "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=42&amount=10",
    "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=42&amount=42",
    "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?pop=callback%3a&req-pop=callback%3a",
]


class Bip21Test(TestCase):
    def test_bip21_valid_uris(self):
        """Test parsing of valid BIP21 URIs from the specification"""
        for i, uri_string in enumerate(VECTORS_BIP21_VALID):
            with self.subTest(i=i, uri=uri_string):
                # Should decode without raising an exception
                uri = bip21.BitcoinURI(uri_string)
                
                # Basic validation - all should have an address
                self.assertIsNotNone(uri.get_address())
                self.assertEqual(uri.get_address(), "175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W")

    def test_bip21_invalid_uris(self):
        """Test that invalid BIP21 URIs raise appropriate exceptions"""
        for i, uri_string in enumerate(VECTORS_BIP21_INVALID):
            with self.subTest(i=i, uri=uri_string):
                with self.assertRaises(bip21.BIP21Error):
                    bip21.BitcoinURI(uri_string)

    def test_multiple_segwit_addresses(self):
        """Test multiple segwit addresses (bc parameters) according to BIP21"""
        uri_string = "bitcoin:?bc=bc1qufgy354j3kmvuch987xe4s40836x3h0lg8f5n2&bc=bc1p5swkugezn97763tl0yty6556856uug0q6jflljvep9m4p7339x5qzyrh4g"
        uri = bip21.BitcoinURI(uri_string)
        
        # Should have no regular address in URI path
        self.assertIsNone(uri.get_address())
        
        # Should have exactly 2 bc addresses
        bc_addresses = uri.get_bc_addresses()
        self.assertEqual(len(bc_addresses), 2)
        self.assertEqual(bc_addresses[0], "bc1qufgy354j3kmvuch987xe4s40836x3h0lg8f5n2")
        self.assertEqual(bc_addresses[1], "bc1p5swkugezn97763tl0yty6556856uug0q6jflljvep9m4p7339x5qzyrh4g")
        
    def test_uppercase_uris(self):
        """Test uppercase URIs commonly used in QR codes"""
        # Test uppercase URI with address in path
        uri1 = bip21.BitcoinURI("BITCOIN:BC1QUFGY354J3KMVUCH987XE4S40836X3H0LG8F5N2?BC=BC1P5SWKUGEZN97763TL0YTY6556856UUG0Q6JFLLJVEP9M4P7339X5QZYRH4G")
        self.assertEqual(uri1.get_address(), "BC1QUFGY354J3KMVUCH987XE4S40836X3H0LG8F5N2")
        self.assertEqual(len(uri1.get_bc_addresses()), 1)
        # bc parameter should be normalized to lowercase
        self.assertEqual(uri1.get_bc_addresses()[0], "bc1p5swkugezn97763tl0yty6556856uug0q6jflljvep9m4p7339x5qzyrh4g")
        
        # Test uppercase URI with only bc parameters
        uri2 = bip21.BitcoinURI("BITCOIN:?BC=BC1QUFGY354J3KMVUCH987XE4S40836X3H0LG8F5N2&BC=BC1P5SWKUGEZN97763TL0YTY6556856UUG0Q6JFLLJVEP9M4P7339X5QZYRH4G")
        self.assertIsNone(uri2.get_address())
        self.assertEqual(len(uri2.get_bc_addresses()), 2)
        # bc parameters should be normalized to lowercase
        self.assertEqual(uri2.get_bc_addresses()[0], "bc1qufgy354j3kmvuch987xe4s40836x3h0lg8f5n2")
        self.assertEqual(uri2.get_bc_addresses()[1], "bc1p5swkugezn97763tl0yty6556856uug0q6jflljvep9m4p7339x5qzyrh4g")

    def test_silent_payment_addresses(self):
        """sp parameters are validated via BIP-352 (bech32m, version, keys)"""
        mainnet = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"

        # Single mainnet sp address
        uri = bip21.BitcoinURI("bitcoin:?sp=" + mainnet)
        self.assertIsNone(uri.get_address())
        self.assertEqual(uri.get_silent_payment_addresses(), [mainnet])

        # Multiple sp addresses are allowed (payment instruction field)
        uri = bip21.BitcoinURI("bitcoin:?sp={0}&sp={0}".format(mainnet))
        self.assertEqual(uri.get_silent_payment_addresses(), [mainnet, mainnet])

    def test_testnet_silent_payment_address(self):
        """Testnet sp addresses (tsp1) are now accepted via BIP-352 decoding"""
        testnet = "tsp1qqtxnkt3n7rrjxnz5mqtlrafnm50ghpljsnus4qy53dxmayc5kg48cq6zu25tt40wgf3yy6c7c32q68ensehyhf3jnsv4vcedj67xvyrn6uwh6pwr"
        uri = bip21.BitcoinURI("bitcoin:?sp=" + testnet)
        self.assertEqual(uri.get_silent_payment_addresses(), [testnet])

    def test_invalid_silent_payment_address(self):
        """Malformed sp addresses are rejected (not just a prefix check)"""
        # Valid prefix but corrupted bech32m checksum (last char flipped)
        bad_checksum = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwq"
        with self.assertRaises(bip21.BIP21Error):
            bip21.BitcoinURI("bitcoin:?sp=" + bad_checksum)

        # Right HRP, but not a real silent payment payload
        with self.assertRaises(bip21.BIP21Error):
            bip21.BitcoinURI("bitcoin:?sp=sp1qqqqqqqqqqqq")