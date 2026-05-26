from unittest import TestCase
from embit.descriptor import SilentPaymentDescriptor
from embit.descriptor.sp import SPScanKey, SPSpendKey
from embit.descriptor.arguments import KeyOrigin
from embit import bip32, bip39

# TODO: add more test vectors
VECTORS = [
    {
        "mnemonic": "initial tilt corn easily leave weather strategy return topple gesture sad day",
        "coin_type": 1,
        "spscan": "tspscan1q09zrmaz09cdzs5jxm552qpv3f2gxd9vxhs0yady09jdd6aqt5e7s9fue8565hmue30u47mvc6rqwwwh0zw6ptjtqzwq7kr6h27sa09f5g6x977",
        "spspend": "tspspend1q09zrmaz09cdzs5jxm552qpv3f2gxd9vxhs0yady09jdd6aqt5e772yf8kwpa7shfhuw9esasvgn8lh7e6ufea60fpvfx9dk7m3klg6sa90au8",
    },
    {
        "mnemonic": "tongue vanish post gentle fever figure kangaroo select infant blur phrase relief",
        "coin_type": 0,
        "spscan": "spscan1qnd95fpg2587jn73qg98pq8uk20y09v5c20u0e4kynsc4m2qmkrrs9cahrrlzln5nreangzkja2mj8pnwrfwudqws4vl3at3zyw2tslxtryq7pn",
        "spspend": "spspend1qnd95fpg2587jn73qg98pq8uk20y09v5c20u0e4kynsc4m2qmkrrmd9tyggwt47773rhumkklet4g2us7c3x0gul65za8fg32nansdesukdqr2",
    },
    {
        "mnemonic": "index today witness obscure ugly curtain symbol pumpkin pelican child maple struggle arctic water tiny pizza harbor below violin eight tennis frost clown hood",
        "coin_type": 1,
        "spscan": "tspscan1q0z4tkwaar4ww77qgesalgzw0c40q89zh7p7hmp3qn73yrdw9jpvs9yjn9d7puunttpfjuale84erzh2z636fqgy63gp7m52v5hcnmmrrlrxnur",
        "spspend": "tspspend1q0z4tkwaar4ww77qgesalgzw0c40q89zh7p7hmp3qn73yrdw9jpvnadsvv7qqcd8ytmdtzn6r5ywvccgzpw2386spvymglmszzep0svg39qpev",
    },
    {
        "mnemonic": "fold cotton pipe robust eagle rabbit coach average orient utility minor absurd fine claim artist rabbit kingdom original lobster cruise march city vibrant resemble",
        "coin_type": 0,
        "spscan": "spscan1q79q4zljllyehszny72w5zfptzpxnp96esg0n2fwecgzd2v7fr6fsy54qq8jfr6mm3pgrze8hln43my7epsfkg98wtl77ch6r5lz6pedd2jcnxk",
        "spspend": "spspend1q79q4zljllyehszny72w5zfptzpxnp96esg0n2fwecgzd2v7fr6fs8y6dg3fu9jp5rhrycnuhtd555t6904x4xs7cklka8z5tk5p9xwq82pf6k",
    },
]


def _derive_sp_keys(mnemonic, coin_type):
    seed = bip39.mnemonic_to_seed(mnemonic)
    master = bip32.HDKey.from_seed(seed)
    scan_priv = master.derive("m/352h/%dh/0h/1h/0" % coin_type).key
    spend_priv = master.derive("m/352h/%dh/0h/0h/0" % coin_type).key
    return scan_priv, spend_priv


class TestMnemonicVectors(TestCase):
    def _keys(self, v):
        network = "test" if v["coin_type"] == 1 else "main"
        scan_priv, spend_priv = _derive_sp_keys(v["mnemonic"], v["coin_type"])
        return network, scan_priv, spend_priv, spend_priv.get_public_key()

    def test_spscan_encoding(self):
        for v in VECTORS:
            net, scan_priv, _, spend_pub = self._keys(v)
            self.assertEqual(
                SPScanKey(scan_priv, spend_pub, network=net).encode(), v["spscan"]
            )

    def test_spspend_encoding(self):
        for v in VECTORS:
            net, scan_priv, spend_priv, _ = self._keys(v)
            self.assertEqual(
                SPSpendKey(scan_priv, spend_priv, network=net).encode(), v["spspend"]
            )

    def test_descriptor_roundtrip_spscan(self):
        for v in VECTORS:
            net, scan_priv, _, spend_pub = self._keys(v)
            desc_str = "sp(%s)" % SPScanKey(scan_priv, spend_pub, network=net).encode()
            desc = SilentPaymentDescriptor.from_string(desc_str)
            self.assertEqual(str(desc), desc_str)
            self.assertTrue(desc.is_watch_only)

    def test_descriptor_roundtrip_spspend(self):
        for v in VECTORS:
            net, scan_priv, spend_priv, _ = self._keys(v)
            desc_str = (
                "sp(%s)" % SPSpendKey(scan_priv, spend_priv, network=net).encode()
            )
            desc = SilentPaymentDescriptor.from_string(desc_str)
            self.assertEqual(str(desc), desc_str)
            self.assertFalse(desc.is_watch_only)

    def test_keys_extractable_from_descriptor(self):
        for v in VECTORS:
            net, scan_priv, _, spend_pub = self._keys(v)
            spscan = SPScanKey(scan_priv, spend_pub, network=net)
            desc = SilentPaymentDescriptor.from_string("sp(%s)" % spscan.encode())
            self.assertEqual(desc.get_scan_privkey().secret, scan_priv.secret)
            self.assertEqual(desc.get_spend_pubkey().sec(), spend_pub.sec())


class TestKeyOrigin(TestCase):
    """Key origin prefix [fingerprint/path] is parsed and preserved in SP descriptors."""

    def test_spscan_with_origin_roundtrip(self):
        for v in VECTORS:
            net = "test" if v["coin_type"] == 1 else "main"
            scan_priv, spend_priv = _derive_sp_keys(v["mnemonic"], v["coin_type"])
            spend_pub = spend_priv.get_public_key()
            origin = KeyOrigin.from_string("deadbeef/352h/%dh/0h" % v["coin_type"])
            spscan = SPScanKey(scan_priv, spend_pub, origin=origin, network=net)
            desc_str = "sp(%s)" % str(spscan)
            desc = SilentPaymentDescriptor.from_string(desc_str)
            self.assertEqual(str(desc), desc_str)
            self.assertTrue(desc.is_watch_only)

    def test_spspend_with_origin_roundtrip(self):
        for v in VECTORS:
            net = "test" if v["coin_type"] == 1 else "main"
            scan_priv, spend_priv = _derive_sp_keys(v["mnemonic"], v["coin_type"])
            origin = KeyOrigin.from_string("cafebabe/352h/%dh/0h" % v["coin_type"])
            spspend = SPSpendKey(scan_priv, spend_priv, origin=origin, network=net)
            desc_str = "sp(%s)" % str(spspend)
            desc = SilentPaymentDescriptor.from_string(desc_str)
            self.assertEqual(str(desc), desc_str)
            self.assertFalse(desc.is_watch_only)

    def test_parsed_key_retains_origin_fingerprint(self):
        v = VECTORS[0]
        net = "test"
        scan_priv, spend_priv = _derive_sp_keys(v["mnemonic"], v["coin_type"])
        spend_pub = spend_priv.get_public_key()
        origin = KeyOrigin.from_string("deadbeef/352h/1h/0h")
        spscan = SPScanKey(scan_priv, spend_pub, origin=origin, network=net)
        desc = SilentPaymentDescriptor.from_string("sp(%s)" % str(spscan))
        self.assertIsNotNone(desc.sp_key.origin)
        self.assertEqual(desc.sp_key.origin.fingerprint, bytes.fromhex("deadbeef"))

    def test_origin_does_not_affect_key_content(self):
        """Origin prefix doesn't change the encoded key bytes."""
        v = VECTORS[1]
        net = "main"
        scan_priv, spend_priv = _derive_sp_keys(v["mnemonic"], v["coin_type"])
        spend_pub = spend_priv.get_public_key()
        origin = KeyOrigin.from_string("cafebabe/352h/0h/0h")
        spscan = SPScanKey(scan_priv, spend_pub, origin=origin, network=net)
        desc = SilentPaymentDescriptor.from_string("sp(%s)" % str(spscan))
        self.assertEqual(desc.get_scan_privkey().secret, scan_priv.secret)
        self.assertEqual(desc.get_spend_pubkey().sec(), spend_pub.sec())


class TestTwoArgDescriptor(TestCase):
    """sp(scan_key, spend_key) two-argument descriptor form."""

    def _leaf_hdkeys(self, v):
        seed = bip39.mnemonic_to_seed(v["mnemonic"])
        master = bip32.HDKey.from_seed(seed)
        ct = v["coin_type"]
        scan_hd = master.derive("m/352h/%dh/0h/1h/0" % ct)
        spend_hd_priv = master.derive("m/352h/%dh/0h/0h/0" % ct)
        spend_hd_pub = spend_hd_priv.to_public()
        return scan_hd, spend_hd_priv, spend_hd_pub

    def test_xprv_xpub_is_watch_only(self):
        for v in VECTORS:
            scan_hd, _, spend_hd_pub = self._leaf_hdkeys(v)
            desc_str = "sp(%s,%s)" % (scan_hd.to_base58(), spend_hd_pub.to_base58())
            desc = SilentPaymentDescriptor.from_string(desc_str)
            self.assertFalse(desc.is_single_arg)
            self.assertTrue(desc.is_watch_only)

    def test_xprv_xprv_is_not_watch_only(self):
        for v in VECTORS:
            scan_hd, spend_hd_priv, _ = self._leaf_hdkeys(v)
            desc_str = "sp(%s,%s)" % (scan_hd.to_base58(), spend_hd_priv.to_base58())
            desc = SilentPaymentDescriptor.from_string(desc_str)
            self.assertFalse(desc.is_single_arg)
            self.assertFalse(desc.is_watch_only)

    def test_two_arg_roundtrip(self):
        for v in VECTORS:
            scan_hd, _, spend_hd_pub = self._leaf_hdkeys(v)
            desc_str = "sp(%s,%s)" % (scan_hd.to_base58(), spend_hd_pub.to_base58())
            desc = SilentPaymentDescriptor.from_string(desc_str)
            self.assertEqual(str(desc), desc_str)

    def test_two_arg_keys_match_direct_derivation(self):
        """Two-arg form with leaf-level keys produces the same scan/spend keys as direct derivation."""
        for v in VECTORS:
            scan_priv, spend_priv = _derive_sp_keys(v["mnemonic"], v["coin_type"])
            spend_pub = spend_priv.get_public_key()
            scan_hd, _, spend_hd_pub = self._leaf_hdkeys(v)
            desc_str = "sp(%s,%s)" % (scan_hd.to_base58(), spend_hd_pub.to_base58())
            desc = SilentPaymentDescriptor.from_string(desc_str)
            self.assertEqual(desc.get_scan_privkey().secret, scan_priv.secret)
            self.assertEqual(desc.get_spend_pubkey().sec(), spend_pub.sec())


class TestChecksumHandling(TestCase):
    """Descriptor #checksum suffix is stripped during parsing."""

    def test_checksum_suffix_stripped(self):
        for v in VECTORS:
            net = "test" if v["coin_type"] == 1 else "main"
            scan_priv, spend_priv = _derive_sp_keys(v["mnemonic"], v["coin_type"])
            spend_pub = spend_priv.get_public_key()
            desc_str = "sp(%s)" % SPScanKey(scan_priv, spend_pub, network=net).encode()
            desc = SilentPaymentDescriptor.from_string(desc_str + "#aaaaaaaa")
            self.assertEqual(str(desc), desc_str)

    def test_no_checksum_parses_normally(self):
        v = VECTORS[0]
        net = "test"
        scan_priv, spend_priv = _derive_sp_keys(v["mnemonic"], v["coin_type"])
        spend_pub = spend_priv.get_public_key()
        desc_str = "sp(%s)" % SPScanKey(scan_priv, spend_pub, network=net).encode()
        desc = SilentPaymentDescriptor.from_string(desc_str)
        self.assertTrue(desc.is_watch_only)
        self.assertTrue(desc.is_single_arg)