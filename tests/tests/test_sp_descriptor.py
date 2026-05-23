from unittest import TestCase
from embit.descriptor import Descriptor, SilentPaymentDescriptor
from embit.descriptor.sp import SPScanKey, SPSpendKey
from embit.descriptor.errors import DescriptorError
from embit.descriptor.checksum import add_checksum
from embit import ec, bip32


def _make_keys():
    scan_secret = bytes([0x01] * 32)
    spend_secret = bytes([0x02] * 32)
    scan_priv = ec.PrivateKey(scan_secret)
    spend_priv = ec.PrivateKey(spend_secret)
    spend_pub = spend_priv.get_public_key()
    return scan_priv, spend_priv, spend_pub


class TestSPKeyExpressions(TestCase):
    def test_spscan_roundtrip(self):
        scan_priv, _, spend_pub = _make_keys()
        key = SPScanKey(scan_priv, spend_pub)
        encoded = key.encode()
        self.assertTrue(encoded.startswith("spscan1q"))
        decoded = SPScanKey.decode(encoded)
        self.assertEqual(decoded.scan_privkey.secret, scan_priv.secret)
        self.assertEqual(decoded.spend_pubkey.sec(), spend_pub.sec())
        self.assertTrue(decoded.is_watch_only)

    def test_spspend_roundtrip(self):
        scan_priv, spend_priv, _ = _make_keys()
        key = SPSpendKey(scan_priv, spend_priv)
        encoded = key.encode()
        self.assertTrue(encoded.startswith("spspend1q"))
        decoded = SPSpendKey.decode(encoded)
        self.assertEqual(decoded.scan_privkey.secret, scan_priv.secret)
        self.assertEqual(decoded.spend_privkey.secret, spend_priv.secret)
        self.assertFalse(decoded.is_watch_only)

    def test_spscan_testnet(self):
        scan_priv, _, spend_pub = _make_keys()
        key = SPScanKey(scan_priv, spend_pub, network="test")
        encoded = key.encode()
        self.assertTrue(encoded.startswith("tspscan1q"))
        decoded = SPScanKey.decode(encoded)
        self.assertEqual(decoded.network, "test")

    def test_spspend_testnet(self):
        scan_priv, spend_priv, _ = _make_keys()
        key = SPSpendKey(scan_priv, spend_priv, network="test")
        encoded = key.encode()
        self.assertTrue(encoded.startswith("tspspend1q"))
        decoded = SPSpendKey.decode(encoded)
        self.assertEqual(decoded.network, "test")

    def test_spscan_with_origin(self):
        from embit.descriptor.arguments import KeyOrigin
        from binascii import unhexlify

        scan_priv, _, spend_pub = _make_keys()
        origin = KeyOrigin(unhexlify("deadbeef"), bip32.parse_path("m/352h/0h/0h"))
        key = SPScanKey(scan_priv, spend_pub, origin=origin)
        s = str(key)
        self.assertTrue(s.startswith("[deadbeef/352h/0h/0h]spscan1q"))

    def test_spscan_invalid_payload_length(self):
        scan_priv, _, _ = _make_keys()
        from embit.descriptor.sp import _bech32m_encode_sp_key
        bad_encoded = _bech32m_encode_sp_key("spscan", scan_priv.secret)
        self.assertRaises(DescriptorError, SPScanKey.decode, bad_encoded)

    def test_spspend_invalid_payload_length(self):
        scan_priv, _, _ = _make_keys()
        from embit.descriptor.sp import _bech32m_encode_sp_key
        bad_encoded = _bech32m_encode_sp_key("spspend", scan_priv.secret)
        self.assertRaises(DescriptorError, SPSpendKey.decode, bad_encoded)


class TestSilentPaymentDescriptor(TestCase):
    def test_single_arg_spscan(self):
        scan_priv, _, spend_pub = _make_keys()
        spscan = SPScanKey(scan_priv, spend_pub)
        desc_str = "sp(%s)" % spscan.encode()
        desc = SilentPaymentDescriptor.from_string(desc_str)
        self.assertTrue(desc.is_single_arg)
        self.assertTrue(desc.is_watch_only)
        self.assertEqual(str(desc), desc_str)

    def test_single_arg_spspend(self):
        scan_priv, spend_priv, _ = _make_keys()
        spspend = SPSpendKey(scan_priv, spend_priv)
        desc_str = "sp(%s)" % spspend.encode()
        desc = SilentPaymentDescriptor.from_string(desc_str)
        self.assertTrue(desc.is_single_arg)
        self.assertFalse(desc.is_watch_only)
        self.assertEqual(str(desc), desc_str)

    def test_single_arg_with_origin(self):
        from embit.descriptor.arguments import KeyOrigin
        from binascii import unhexlify

        scan_priv, _, spend_pub = _make_keys()
        origin = KeyOrigin(unhexlify("deadbeef"), bip32.parse_path("m/352h/0h/0h"))
        spscan = SPScanKey(scan_priv, spend_pub, origin=origin)
        desc_str = "sp(%s)" % spscan
        desc = SilentPaymentDescriptor.from_string(desc_str)
        self.assertTrue(desc.is_single_arg)
        self.assertEqual(str(desc), desc_str)

    def test_two_arg_wif_and_pubkey(self):
        scan_priv, _, spend_pub = _make_keys()
        wif = scan_priv.wif()
        pub_hex = spend_pub.sec().hex()
        desc_str = "sp(%s,%s)" % (wif, pub_hex)
        desc = SilentPaymentDescriptor.from_string(desc_str)
        self.assertFalse(desc.is_single_arg)
        self.assertTrue(desc.is_watch_only)
        self.assertEqual(str(desc), desc_str)

    def test_two_arg_wif_and_wif(self):
        scan_priv, spend_priv, _ = _make_keys()
        desc_str = "sp(%s,%s)" % (scan_priv.wif(), spend_priv.wif())
        desc = SilentPaymentDescriptor.from_string(desc_str)
        self.assertFalse(desc.is_single_arg)
        self.assertFalse(desc.is_watch_only)
        self.assertEqual(str(desc), desc_str)

    def test_two_arg_xprv_and_xpub(self):
        seed = bytes(range(16))
        master = bip32.HDKey.from_seed(seed)
        scan_xprv = master.derive("m/352h/0h/0h/1h/0")
        spend_xpub = master.derive("m/352h/0h/0h/0h/0").to_public()
        desc_str = "sp(%s,%s)" % (scan_xprv.to_base58(), spend_xpub.to_base58())
        desc = SilentPaymentDescriptor.from_string(desc_str)
        self.assertFalse(desc.is_single_arg)
        self.assertTrue(desc.is_watch_only)

    def test_two_arg_xprv_and_xprv(self):
        seed = bytes(range(16))
        master = bip32.HDKey.from_seed(seed)
        scan_xprv = master.derive("m/352h/0h/0h/1h/0")
        spend_xprv = master.derive("m/352h/0h/0h/0h/0")
        desc_str = "sp(%s,%s)" % (scan_xprv.to_base58(), spend_xprv.to_base58())
        desc = SilentPaymentDescriptor.from_string(desc_str)
        self.assertFalse(desc.is_single_arg)
        self.assertFalse(desc.is_watch_only)

    def test_roundtrip_spscan(self):
        scan_priv, _, spend_pub = _make_keys()
        spscan = SPScanKey(scan_priv, spend_pub)
        desc_str = "sp(%s)" % spscan.encode()
        desc = SilentPaymentDescriptor.from_string(desc_str)
        self.assertEqual(SilentPaymentDescriptor.from_string(str(desc)).to_string(), desc_str)

    def test_roundtrip_spspend(self):
        scan_priv, spend_priv, _ = _make_keys()
        spspend = SPSpendKey(scan_priv, spend_priv)
        desc_str = "sp(%s)" % spspend.encode()
        desc = SilentPaymentDescriptor.from_string(desc_str)
        self.assertEqual(SilentPaymentDescriptor.from_string(str(desc)).to_string(), desc_str)

    def test_roundtrip_two_arg(self):
        scan_priv, _, spend_pub = _make_keys()
        desc_str = "sp(%s,%s)" % (scan_priv.wif(), spend_pub.sec().hex())
        desc = SilentPaymentDescriptor.from_string(desc_str)
        self.assertEqual(SilentPaymentDescriptor.from_string(str(desc)).to_string(), desc_str)

    def test_via_descriptor_from_string(self):
        scan_priv, _, spend_pub = _make_keys()
        spscan = SPScanKey(scan_priv, spend_pub)
        desc_str = "sp(%s)" % spscan.encode()
        desc = Descriptor.from_string(desc_str)
        self.assertIsInstance(desc, SilentPaymentDescriptor)

    def test_checksum_accepted(self):
        scan_priv, _, spend_pub = _make_keys()
        spscan = SPScanKey(scan_priv, spend_pub)
        desc_str = "sp(%s)" % spscan.encode()
        desc_with_checksum = add_checksum(desc_str)
        self.assertIn("#", desc_with_checksum)
        desc = SilentPaymentDescriptor.from_string(desc_with_checksum)
        self.assertEqual(str(desc), desc_str)

    def test_get_scan_privkey(self):
        scan_priv, _, spend_pub = _make_keys()
        spscan = SPScanKey(scan_priv, spend_pub)
        desc = SilentPaymentDescriptor.from_string("sp(%s)" % spscan.encode())
        self.assertEqual(desc.get_scan_privkey().secret, scan_priv.secret)

    def test_get_spend_pubkey(self):
        scan_priv, _, spend_pub = _make_keys()
        spscan = SPScanKey(scan_priv, spend_pub)
        desc = SilentPaymentDescriptor.from_string("sp(%s)" % spscan.encode())
        self.assertEqual(desc.get_spend_pubkey().sec(), spend_pub.sec())


class TestSPDescriptorInvalid(TestCase):
    def test_empty_sp(self):
        self.assertRaises(Exception, SilentPaymentDescriptor.from_string, "sp()")

    def test_bare_xpub_single_arg(self):
        seed = bytes(range(16))
        master = bip32.HDKey.from_seed(seed)
        xpub = master.to_public().to_base58()
        self.assertRaises(
            DescriptorError, SilentPaymentDescriptor.from_string, "sp(%s)" % xpub
        )

    def test_public_scan_key_two_arg(self):
        scan_priv, _, spend_pub = _make_keys()
        scan_pub = scan_priv.get_public_key()
        desc_str = "sp(%s,%s)" % (scan_pub.sec().hex(), spend_pub.sec().hex())
        self.assertRaises(
            DescriptorError, SilentPaymentDescriptor.from_string, desc_str
        )

    def test_spscan_in_two_arg_form(self):
        scan_priv, spend_priv, spend_pub = _make_keys()
        spscan = SPScanKey(scan_priv, spend_pub)
        desc_str = "sp(%s,%s)" % (scan_priv.wif(), spscan.encode())
        self.assertRaises(
            DescriptorError, SilentPaymentDescriptor.from_string, desc_str
        )

    def test_nested_in_sh(self):
        scan_priv, _, spend_pub = _make_keys()
        spscan = SPScanKey(scan_priv, spend_pub)
        desc_str = "sh(sp(%s))" % spscan.encode()
        self.assertRaises(Exception, Descriptor.from_string, desc_str)

    def test_nested_in_wsh(self):
        scan_priv, _, spend_pub = _make_keys()
        spscan = SPScanKey(scan_priv, spend_pub)
        desc_str = "wsh(sp(%s))" % spscan.encode()
        self.assertRaises(Exception, Descriptor.from_string, desc_str)

    def test_uncompressed_wif_scan(self):
        scan_priv = ec.PrivateKey(bytes([0x01] * 32), compressed=False)
        spend_pub = ec.PrivateKey(bytes([0x02] * 32)).get_public_key()
        desc_str = "sp(%s,%s)" % (scan_priv.wif(), spend_pub.sec().hex())
        self.assertRaises(
            DescriptorError, SilentPaymentDescriptor.from_string, desc_str
        )

    def test_trailing_junk(self):
        scan_priv, _, spend_pub = _make_keys()
        spscan = SPScanKey(scan_priv, spend_pub)
        desc_str = "sp(%s)junk" % spscan.encode()
        self.assertRaises(
            DescriptorError, SilentPaymentDescriptor.from_string, desc_str
        )

    def test_two_spscan_args(self):
        scan_priv, _, spend_pub = _make_keys()
        spscan = SPScanKey(scan_priv, spend_pub)
        desc_str = "sp(%s,%s)" % (spscan.encode(), spscan.encode())
        self.assertRaises(
            DescriptorError, SilentPaymentDescriptor.from_string, desc_str
        )
