import unittest
from util import *

FLAG_ECDSA, FLAG_SCHNORR = 1, 2
EX_PRIV_KEY_LEN, EC_PUBIC_KEY_LEN, EC_PUBIC_KEY_UNCOMPRESSED_LEN = 32, 33, 65
EC_SIGNATURE_LEN, EC_SIGNATURE_DER_MAX_LEN = 64, 72
BITCOIN_MESSAGE_SERIALIZED_FLAG, BITCOIN_MESSAGE_HASH_FLAG = 0, 1

class SignTests(unittest.TestCase):

    def get_sign_cases(self):
        lines = []
        with open(root_dir + 'src/data/ecdsa_secp256k1_vectors.txt', 'r') as f:
            for l in f.readlines():
                if len(l.strip()) and not l.startswith('#'):
                    lines.append(self.cbufferize(l.strip().split(',')))
        return lines

    def cbufferize(self, values):
        conv = lambda v: make_cbuffer(v)[0] if type(v) is str else v
        return [conv(v) for v in values]

    def sign(self, priv_key, msg, flags, out_buf, out_len=None):
        blen = lambda b: 0 if b is None else len(b)
        if out_len is None:
            out_len = blen(out_buf)
        return wally_ec_sig_from_bytes(priv_key, blen(priv_key),
                                       msg, blen(msg), flags, out_buf, out_len)


    def test_sign_and_verify(self):
        sig, sig2 = self.cbufferize(['00' * EC_SIGNATURE_LEN] * 2)
        der, der_len = make_cbuffer('00' * EC_SIGNATURE_DER_MAX_LEN)

        for case in self.get_sign_cases():
            priv_key, msg, nonce, r, s = case

            if wally_ec_private_key_verify(priv_key, len(priv_key)) != WALLY_OK:
                # Some test vectors have invalid private keys which other
                # libraries allow. secp fails these keys so don't test them.
                continue

            # Sign
            set_fake_ec_nonce(nonce)
            ret = self.sign(priv_key, msg, FLAG_ECDSA, sig)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(h(r), h(sig[0:32]))
            self.assertEqual(h(s), h(sig[32:64]))

            # Check signature conversions
            ret, written = wally_ec_sig_to_der(sig, len(sig), der, der_len)
            self.assertEqual(ret, WALLY_OK)
            ret = wally_ec_sig_from_der(der, written, sig2, len(sig2))
            self.assertEqual((ret, h(sig)), (WALLY_OK, h(sig2)))
            ret = wally_ec_sig_normalize(sig2, len(sig2), sig, len(sig))
            self.assertEqual((ret, h(sig)), (WALLY_OK, h(sig2))) # All sigs low-s

            # Verify
            pub_key, _ = make_cbuffer('00' * 33)
            ret = wally_ec_public_key_from_private_key(priv_key, len(priv_key),
                                                       pub_key, len(pub_key))
            self.assertEqual(ret, WALLY_OK)
            ret = wally_ec_sig_verify(pub_key, len(pub_key), msg, len(msg),
                                      FLAG_ECDSA, sig, len(sig))
            self.assertEqual(ret, WALLY_OK)


        set_fake_ec_nonce(None)


    def test_invalid_inputs(self):
        out_buf, out_len = make_cbuffer('00' * EC_SIGNATURE_LEN)

        priv_key, msg = self.cbufferize(['11' * 32, '22' * 32])
        priv_bad, msg_bad = self.cbufferize(['FF' * 32, '22' * 33])
        FLAGS_BOTH = FLAG_ECDSA | FLAG_SCHNORR

        # Signing
        cases = [(None,         msg,     FLAG_ECDSA),   # Null priv_key
                 (('11' * 33),  msg,     FLAG_ECDSA),   # Wrong priv_key len
                 (priv_bad,     msg,     FLAG_ECDSA),   # Bad private key
                 (priv_key,     None,    FLAG_ECDSA),   # Null message
                 (priv_key,     msg_bad, FLAG_ECDSA),   # Wrong message len
                 (priv_key,     msg,     0),            # No flags set
                 (priv_key,     msg,     FLAGS_BOTH),   # Mutually exclusive
                 (priv_key,     msg,     0x4)]          # Unknown flag

        for priv_key, msg, flags in cases:
            ret = self.sign(priv_key, msg, flags, out_buf)
            self.assertEqual(ret, WALLY_EINVAL)

        for o, o_len in [(None, 32), (out_buf, -1)]: # Null out, Wrong out len
            ret = self.sign(priv_key, msg, FLAG_ECDSA, o, o_len)
            self.assertEqual(ret, WALLY_EINVAL)

        # wally_ec_private_key_verify
        for pk, pk_len in  [(None,     len(priv_key)),  # Null priv_key
                            (priv_key, 10),             # Wrong priv_key len
                            (priv_bad, len(priv_key))]: # Bad private key
            self.assertEqual(wally_ec_private_key_verify(pk, pk_len), WALLY_EINVAL)

        # wally_ec_public_key_decompress
        sig, _ = make_cbuffer('13' * EC_SIGNATURE_LEN)
        out_buf, out_len = make_cbuffer('00' * EC_PUBIC_KEY_UNCOMPRESSED_LEN)

        cases = [(None, len(sig), out_buf, out_len), # Null sig
                 (sig,  15,       out_buf, out_len), # Wrong sig len
                 (sig,  len(sig), None, out_len),    # Null out
                 (sig,  len(sig), out_buf, 15)]      # Wrong out len

        for s, s_len, o, o_len in cases:
            ret, written = wally_ec_sig_to_der(s, s_len, o, o_len)
            self.assertEqual((ret, written), (WALLY_EINVAL, 0))

        # wally_ec_sig_to_der
        sig, _ = make_cbuffer('13' * EC_SIGNATURE_LEN)
        out_buf, out_len = make_cbuffer('00' * EC_SIGNATURE_DER_MAX_LEN)

        cases = [(None, len(sig), out_buf, out_len), # Null sig
                 (sig,  15,       out_buf, out_len), # Wrong sig len
                 (sig,  len(sig), None, out_len),    # Null out
                 (sig,  len(sig), out_buf, 15)]      # Wrong out len

        for s, s_len, o, o_len in cases:
            ret, written = wally_ec_sig_to_der(s, s_len, o, o_len)
            self.assertEqual((ret, written), (WALLY_EINVAL, 0))

        # wally_ec_public_key_from_private_key
        out_buf, out_len = make_cbuffer('00' * EC_PUBIC_KEY_LEN)
        cases = [(None,     len(priv_key),   out_buf, len(out_buf)), # Null priv_key
                 (priv_key, 10,              out_buf, len(out_buf)), # Wrong priv_key len
                 (priv_bad, len(priv_key),   out_buf, len(out_buf)), # Bad private key
                 (priv_key, len(priv_key),   None,    len(out_buf)), # Null out
                 (priv_key, len(priv_key),   out_buf, 10)]           # Wrong out len

        for pk, pk_len, o, o_len in cases:
            ret = wally_ec_public_key_from_private_key(pk, pk_len, o, o_len);
            self.assertEqual(ret, WALLY_EINVAL)

    def test_format_message_invalid(self):
        flags = BITCOIN_MESSAGE_SERIALIZED_FLAG
        small_max_length = 30
        bytes_in, len_in = make_cbuffer('13' * small_max_length)
        bytes_out, len_out = make_cbuffer('00' * small_max_length)

        ret, written = wally_format_bitcoin_message(bytes_in, len(bytes_in), flags, bytes_out, 15)
        self.assertEqual((ret, written), (WALLY_OK, len_in + 26)) # Small out len

        cases = [
            (None, len_in, bytes_out, len_out), # Null bytes_in
            (bytes_in, 0, bytes_out, len_out),  # Wrong input len
            (bytes_in, len_in, None, len_out),  # Null output
        ]
        for msg, msg_len, o, o_len in cases:
            ret, written = wally_format_bitcoin_message(msg, msg_len, flags, o, o_len)
            self.assertEqual(ret, WALLY_EINVAL)

    def hex_buf_from_string(self, msg_str):
        msg_ascii = msg_str #.encode('ascii')
        ret, msg_hex = wally_hex_from_bytes((msg_ascii), len(msg_ascii))
        self.assertEqual(ret, WALLY_OK)
        return make_cbuffer(str(msg_hex))

    def single_hex_test(self, msg, msg_len, flags, expected_msg, expected_msg_len):
        bytes_out, len_out = make_cbuffer('00' * (expected_msg_len))
        ret, written = wally_format_bitcoin_message(msg, msg_len, flags, bytes_out, len_out)
        self.assertEqual((ret, bytes_out, written), (WALLY_OK, expected_msg, expected_msg_len))

    def test_format_message(self):
        self.maxDiff = None
        flags = BITCOIN_MESSAGE_SERIALIZED_FLAG
        cases = [
            ['aaa', '\x18Bitcoin Signed Message:\n\x03aaa'],
            ['bbbb', '\x18Bitcoin Signed Message:\n\x04bbbb'],
            ['a\nb\n', '\x18Bitcoin Signed Message:\n\x04a\nb\n'],
            ['\0a\nb\0cc', '\x18Bitcoin Signed Message:\n\x07\0a\nb\0cc'],
            ['a\0b\nc\n\0', '\x18Bitcoin Signed Message:\n\x07a\0b\nc\n\0'],
            ['a' * 200, '\x18Bitcoin Signed Message:\n\xc8' + 'a' * 200],
            ['b' * 253, '\x18Bitcoin Signed Message:\n\xfd\xfd\x00' + 'b' * 253],
            ['c' * 256, '\x18Bitcoin Signed Message:\n\xfd\x00\x01' + 'c' * 256],
            ['d' * 65534, '\x18Bitcoin Signed Message:\n\xfd\xfe\xff' + 'd' * 65534],
            ['e' * 65535, '\x18Bitcoin Signed Message:\n\xfd\xff\xff' + 'e' * 65535],
            ['f' * 65536, '\x18Bitcoin Signed Message:\n\xfe\x00\x00\x01\x00' + 'f' * 65536],
            # TODO Find a better way to tests bigger messages
            # ['g' * 4294967296, '\x18Bitcoin Signed Message:\n\xfe\x00\x00\x00\x00\x01\x00\x00\x00' + 'g' * 4294967296],
        ]
        for msg_str, expected_out in cases:
            msg, msg_len = self.hex_buf_from_string(msg_str)
            expected_msg, expected_msg_len = self.hex_buf_from_string(expected_out)
            self.single_hex_test(msg, msg_len, flags, expected_msg, expected_msg_len)

        # expected_msg, expected_msg_len = self.hex_buf_from_string('Bitcoin Signed Message:\n')
        # # bytes_out, len_out = make_cbuffer(b'Bitcoin Signed Message:\n')
        # bytes_out, len_out = make_cbuffer('00' * (expected_msg_len))
        # print(expected_msg_len)
        # print(expected_msg + bytes_out)
        # print(expected_msg_len + len_out)
        # # self.assertEqual(expected_msg, bytes_out)
        # # self.single_hex_test(msg, msg_len, flags, expected_msg, expected_msg_len)

if __name__ == '__main__':
    unittest.main()
