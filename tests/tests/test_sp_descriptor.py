from unittest import TestCase
from embit.descriptor import Descriptor, SilentPaymentDescriptor
from embit.descriptor.sp import SPScanKey, SPSpendKey
from embit.descriptor.errors import DescriptorError
from embit.descriptor.checksum import add_checksum
from embit import ec, bip32, bip39
from embit.silent_payments import bip352


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


MNEMONIC_VECTORS = [
    {
        "mnemonic": "initial tilt corn easily leave weather strategy return topple gesture sad day",
        "coin_type": 1,
        "payment_addr": "tsp1qqfvn9pmvmz0ewpnp7w302lxqmnue2kgtpne2p38nuunun883sw36yq48ny7n2jl0nx9ljhmdnrgvpee6aufmg9wfvqfcr6c02at6r4u4xsegph7a",
        "payment_addr0": "tsp1qqfvn9pmvmz0ewpnp7w302lxqmnue2kgtpne2p38nuunun883sw36yqu9e9gaqt04w3svwy8v6plfevlar572y5hmj6unex9xdagzu5426gkhqm4q",
        "payment_addr1": "tsp1qqfvn9pmvmz0ewpnp7w302lxqmnue2kgtpne2p38nuunun883sw36yq7frtfktpq0ae6lsk2v32qmpm6tdu2p5at7w8grvcrtkn5ap0727uu2vl8e",
        "payment_addr2": "tsp1qqfvn9pmvmz0ewpnp7w302lxqmnue2kgtpne2p38nuunun883sw36yqk0pvxs9zd7gezdv6ctt69c72h2pjmmfj0hz0m0n8mfrg0zwfz9d583wcee",
        "spscan": "tspscan1q09zrmaz09cdzs5jxm552qpv3f2gxd9vxhs0yady09jdd6aqt5e7s9fue8565hmue30u47mvc6rqwwwh0zw6ptjtqzwq7kr6h27sa09f5g6x977",
        "spspend": "tspspend1q09zrmaz09cdzs5jxm552qpv3f2gxd9vxhs0yady09jdd6aqt5e772yf8kwpa7shfhuw9esasvgn8lh7e6ufea60fpvfx9dk7m3klg6sa90au8",
    },
    {
        "mnemonic": "tongue vanish post gentle fever figure kangaroo select infant blur phrase relief",
        "coin_type": 0,
        "payment_addr": "sp1qq2c4jvrju33tmm9ll0560vm0rflfxkhd8zj74pka8s53dyaztzwlqqhrkuv0ut7wjv08kdq26t4twguxdcd9m35p6z4n784wyg3efwruevxty23x",
        "payment_addr0": "sp1qq2c4jvrju33tmm9ll0560vm0rflfxkhd8zj74pka8s53dyaztzwlqq3nh20szx3lkpttrpx9u56ae6z7r7ejeyyh623vkdeupud385wzxczvd2xe",
        "payment_addr1": "sp1qq2c4jvrju33tmm9ll0560vm0rflfxkhd8zj74pka8s53dyaztzwlqq59wqj4cckjsq6a7wh9kj2t9extk0f0c93lsd4ewgzy7uwh953ngswzrweq",
        "payment_addr2": "sp1qq2c4jvrju33tmm9ll0560vm0rflfxkhd8zj74pka8s53dyaztzwlqqer5xely65uhjr4sqh88q2jajapej43c8x8yt4xxd99y2qq5thrfuer8j5u",
        "spscan": "spscan1qnd95fpg2587jn73qg98pq8uk20y09v5c20u0e4kynsc4m2qmkrrs9cahrrlzln5nreangzkja2mj8pnwrfwudqws4vl3at3zyw2tslxtryq7pn",
        "spspend": "spspend1qnd95fpg2587jn73qg98pq8uk20y09v5c20u0e4kynsc4m2qmkrrmd9tyggwt47773rhumkklet4g2us7c3x0gul65za8fg32nansdesukdqr2",
    },
    {
        "mnemonic": "index today witness obscure ugly curtain symbol pumpkin pelican child maple struggle arctic water tiny pizza harbor below violin eight tennis frost clown hood",
        "coin_type": 1,
        "payment_addr": "tsp1qqvdcq76j5kul4s6t52d07ssq8l96k49jur0kytua36k9qzj4m5xyxq5j2v4hc8njddv9xtnhly7hyv2agt28fypqn29q8mw3fjjlz00vvv824hd6",
        "payment_addr0": "tsp1qqvdcq76j5kul4s6t52d07ssq8l96k49jur0kytua36k9qzj4m5xyxqnk5r88uv3459esc08x5hvkq9yy2chyz7cy4y6knp6xn42chm9p5u6afswf",
        "payment_addr1": "tsp1qqvdcq76j5kul4s6t52d07ssq8l96k49jur0kytua36k9qzj4m5xyxq6twmpszhkyxf44tjp4s6eh6dmvtckp4fh3t6zl80e0fwd47uyfzgy94nw2",
        "payment_addr2": "tsp1qqvdcq76j5kul4s6t52d07ssq8l96k49jur0kytua36k9qzj4m5xyxq6rphuf7ghxzqnz9ul2x4zshtsh0e73kgaau430au2uhc9cvnw0wqhtzpp2",
        "spscan": "tspscan1q0z4tkwaar4ww77qgesalgzw0c40q89zh7p7hmp3qn73yrdw9jpvs9yjn9d7puunttpfjuale84erzh2z636fqgy63gp7m52v5hcnmmrrlrxnur",
        "spspend": "tspspend1q0z4tkwaar4ww77qgesalgzw0c40q89zh7p7hmp3qn73yrdw9jpvnadsvv7qqcd8ytmdtzn6r5ywvccgzpw2386spvymglmszzep0svg39qpev",
    },
    {
        "mnemonic": "fold cotton pipe robust eagle rabbit coach average orient utility minor absurd fine claim artist rabbit kingdom original lobster cruise march city vibrant resemble",
        "coin_type": 0,
        "payment_addr": "sp1qq25f3laffnhpl69ytaxzz5gjnkrm2a2jr3mfz0ff6wuesg4j9e5lcqjj5qq7fy0t0wy9qvty7l7wk8vnmyxpxeq5ae0lmmzlgwnutg8945k2w7lh",
        "payment_addr0": "sp1qq25f3laffnhpl69ytaxzz5gjnkrm2a2jr3mfz0ff6wuesg4j9e5lcqjwf576ajhswcnu4qut3u0nmxf9tq5czttwmukfhk25xe00jl9yacfm9g7u",
        "payment_addr1": "sp1qq25f3laffnhpl69ytaxzz5gjnkrm2a2jr3mfz0ff6wuesg4j9e5lcql6jj65qatvpd0wcdxeya4akdl90c5p7t98f3rh6tmdyyzq0kds3cxqcurj",
        "payment_addr2": "sp1qq25f3laffnhpl69ytaxzz5gjnkrm2a2jr3mfz0ff6wuesg4j9e5lcq4k94apnmyu0f42n625vwdejmg36ca56ly8rsan600muk22sz2yqu9r8k63",
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
    def test_payment_addresses(self):
        for v in MNEMONIC_VECTORS:
            network = "test" if v["coin_type"] == 1 else "main"
            scan_priv, spend_priv = _derive_sp_keys(v["mnemonic"], v["coin_type"])
            spend_pub = spend_priv.get_public_key()
            self.assertEqual(
                bip352.generate_silent_payment_address(scan_priv, spend_pub, network=network),
                v["payment_addr"],
            )
            self.assertEqual(
                bip352.generate_silent_payment_address(scan_priv, spend_pub, label=0, network=network),
                v["payment_addr0"],
            )
            self.assertEqual(
                bip352.generate_silent_payment_address(scan_priv, spend_pub, label=1, network=network),
                v["payment_addr1"],
            )
            self.assertEqual(
                bip352.generate_silent_payment_address(scan_priv, spend_pub, label=2, network=network),
                v["payment_addr2"],
            )

    def test_spscan_encoding(self):
        for v in MNEMONIC_VECTORS:
            network = "test" if v["coin_type"] == 1 else "main"
            scan_priv, spend_priv = _derive_sp_keys(v["mnemonic"], v["coin_type"])
            spend_pub = spend_priv.get_public_key()
            key = SPScanKey(scan_priv, spend_pub, network=network)
            self.assertEqual(key.encode(), v["spscan"])

    def test_spspend_encoding(self):
        for v in MNEMONIC_VECTORS:
            network = "test" if v["coin_type"] == 1 else "main"
            scan_priv, spend_priv = _derive_sp_keys(v["mnemonic"], v["coin_type"])
            key = SPSpendKey(scan_priv, spend_priv, network=network)
            self.assertEqual(key.encode(), v["spspend"])

    def test_descriptor_roundtrip_spscan(self):
        for v in MNEMONIC_VECTORS:
            network = "test" if v["coin_type"] == 1 else "main"
            scan_priv, spend_priv = _derive_sp_keys(v["mnemonic"], v["coin_type"])
            spend_pub = spend_priv.get_public_key()
            spscan = SPScanKey(scan_priv, spend_pub, network=network)
            desc_str = "sp(%s)" % spscan.encode()
            desc = SilentPaymentDescriptor.from_string(desc_str)
            self.assertEqual(str(desc), desc_str)
            self.assertTrue(desc.is_watch_only)

    def test_descriptor_roundtrip_spspend(self):
        for v in MNEMONIC_VECTORS:
            network = "test" if v["coin_type"] == 1 else "main"
            scan_priv, spend_priv = _derive_sp_keys(v["mnemonic"], v["coin_type"])
            spspend = SPSpendKey(scan_priv, spend_priv, network=network)
            desc_str = "sp(%s)" % spspend.encode()
            desc = SilentPaymentDescriptor.from_string(desc_str)
            self.assertEqual(str(desc), desc_str)
            self.assertFalse(desc.is_watch_only)

    def test_keys_extractable_from_descriptor(self):
        for v in MNEMONIC_VECTORS:
            network = "test" if v["coin_type"] == 1 else "main"
            scan_priv, spend_priv = _derive_sp_keys(v["mnemonic"], v["coin_type"])
            spend_pub = spend_priv.get_public_key()
            spscan = SPScanKey(scan_priv, spend_pub, network=network)
            desc = SilentPaymentDescriptor.from_string("sp(%s)" % spscan.encode())
            self.assertEqual(desc.get_scan_privkey().secret, scan_priv.secret)
            self.assertEqual(desc.get_spend_pubkey().sec(), spend_pub.sec())
