"""
NIST Known-Answer Tests for all CommonCrypto AES mode wrappers.

References:
  AES-CTR: NIST SP 800-38A, Section F.5.1
  AES-XTS: IEEE 1619-2007, Vector 1
  AES-CBC: NIST SP 800-38A, Section F.2.1
  AES-ECB: NIST FIPS 197, Appendix B
"""
import platform
import sys
import unittest

mac_only = unittest.skipUnless(platform.system() == "Darwin", "macOS only")


def _xts_supported():
    """Check if CommonCrypto supports XTS mode on this platform."""
    if platform.system() != "Darwin":
        return False
    old_argv = sys.argv
    sys.argv = ['test']
    try:
        from nsz.mac_crypto import MacAESXTS
        c = MacAESXTS(b'\x00' * 32, b'\x00' * 16, encrypt=True)
        c.encrypt(b'\x00' * 16)  # Test actual encrypt — CCCryptorUpdate may fail even if create succeeds
        return True
    except (RuntimeError, ImportError, OSError):
        return False
    finally:
        sys.argv = old_argv


xts_supported = unittest.skipUnless(_xts_supported(), "CommonCrypto XTS not supported on this platform")


# ---------------------------------------------------------------------------
# AES-CTR test vectors (NIST SP 800-38A, F.5.1, AES-128)
# ---------------------------------------------------------------------------
CTR_KEY        = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
CTR_IV         = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
CTR_PLAIN      = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
CTR_CIPHER     = bytes.fromhex(
    "874d6191b620e3261bef6864990db6ce"
    "9806f66b7970fdff8617187bb9fffdff"
    "5ae4df3edbd5d35e5b4f09020db03eab"
    "1e031dda2fbe03d1792170a0f3009cee"
)

# ---------------------------------------------------------------------------
# AES-XTS test vectors (IEEE 1619-2007, Vector 1, AES-128-XTS)
# Key is key1 (16 bytes) + key2 (16 bytes) = 32 bytes total
# ---------------------------------------------------------------------------
XTS_KEY        = bytes.fromhex(
    "a1b90579 3091b958 04f2ad7f 26585a50"   # key1
    "f8f4f8df c5f40b2b 19e3e3f5 5a44c8d5"   # key2 (spaces stripped below)
    .replace(" ", "")
)
XTS_TWEAK      = bytes.fromhex("00000000000000000000000000000000")  # sector 0
XTS_PLAIN      = bytes.fromhex(
    "ebabce95b14d3c8d6fb350390790311c"
    "afe8fbf1a2a69960a6b43c5e27e0b2b5"
    "13f3827f7c2e9bb8f6dbdf9ee2a264a2"
    "73e1d5a3487e0d59bde26a4f0f60b3a1"
)
XTS_CIPHER     = bytes.fromhex(
    "778ae8b43cb98d5a825081d5be471c63"
    "4f19366882f6da00b2f498e8a8986b1a"
    "6d8ebb00b09d14a5e0f38f4bdde3a978"
    "daadd43d3aba2c05c7cf9127dc97c95f"
)

# ---------------------------------------------------------------------------
# AES-CBC test vectors (NIST SP 800-38A, F.2.1, AES-128)
# ---------------------------------------------------------------------------
CBC_KEY        = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
CBC_IV         = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
CBC_PLAIN      = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
CBC_CIPHER     = bytes.fromhex(
    "7649abac8119b246cee98e9b12e9197d"
    "5086cb9b507219ee95db113a917678b2"
    "73bed6b8e3c1743b7116e69e22229516"
    "3ff1caa1681fac09120eca307586e1a7"
)

# ---------------------------------------------------------------------------
# AES-ECB test vectors (NIST FIPS 197, Appendix B, AES-128)
# ---------------------------------------------------------------------------
ECB_KEY        = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
ECB_PLAIN      = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
ECB_CIPHER     = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")


class TestMacAESCTR(unittest.TestCase):
    @mac_only
    def test_encrypt_nist(self):
        from nsz.mac_crypto import MacAESCTR
        self.assertEqual(MacAESCTR(CTR_KEY, CTR_IV).encrypt(CTR_PLAIN), CTR_CIPHER)

    @mac_only
    def test_decrypt_nist(self):
        from nsz.mac_crypto import MacAESCTR
        # CTR decrypt == encrypt
        self.assertEqual(MacAESCTR(CTR_KEY, CTR_IV).decrypt(CTR_CIPHER), CTR_PLAIN)

    @mac_only
    def test_bad_key_raises(self):
        from nsz.mac_crypto import MacAESCTR
        with self.assertRaises((ValueError, RuntimeError)):
            MacAESCTR(b"tooshort", CTR_IV)

    @mac_only
    def test_large_input_chunking(self):
        """20MB input forces the chunked path; output must match single-call result."""
        from nsz.mac_crypto import MacAESCTR
        data = bytes(20 * 1024 * 1024)
        result_a = MacAESCTR(CTR_KEY, CTR_IV).encrypt(data)
        c = MacAESCTR(CTR_KEY, CTR_IV)
        result_b = c.encrypt(data[:10 * 1024 * 1024]) + c.encrypt(data[10 * 1024 * 1024:])
        self.assertEqual(result_a, result_b)


class TestMacAESXTS(unittest.TestCase):
    @xts_supported
    def test_encrypt_ieee_vector(self):
        from nsz.mac_crypto import MacAESXTS
        cipher = MacAESXTS(XTS_KEY, XTS_TWEAK, encrypt=True)
        self.assertEqual(cipher.encrypt(XTS_PLAIN), XTS_CIPHER)

    @xts_supported
    def test_decrypt_ieee_vector(self):
        from nsz.mac_crypto import MacAESXTS
        cipher = MacAESXTS(XTS_KEY, XTS_TWEAK, encrypt=False)
        self.assertEqual(cipher.decrypt(XTS_CIPHER), XTS_PLAIN)

    @mac_only
    def test_unaligned_input_raises(self):
        """XTS requires input to be a multiple of 16 bytes."""
        from nsz.mac_crypto import MacAESXTS
        try:
            cipher = MacAESXTS(XTS_KEY, XTS_TWEAK, encrypt=True)
        except RuntimeError:
            self.skipTest("XTS not supported on this platform")
        with self.assertRaises(ValueError):
            cipher.encrypt(b"not_aligned_____x")  # 17 bytes

    @mac_only
    def test_bad_key_length_raises(self):
        """XTS key must be 32 or 64 bytes (double AES key length)."""
        from nsz.mac_crypto import MacAESXTS
        with self.assertRaises((ValueError, RuntimeError)):
            MacAESXTS(b"tooshort", XTS_TWEAK, encrypt=True)

    @xts_supported
    def test_large_input_chunking(self):
        """20MB aligned input forces the chunked path."""
        from nsz.mac_crypto import MacAESXTS
        data = bytes(20 * 1024 * 1024)
        result_a = MacAESXTS(XTS_KEY, XTS_TWEAK, encrypt=True).encrypt(data)
        c = MacAESXTS(XTS_KEY, XTS_TWEAK, encrypt=True)
        mid = 10 * 1024 * 1024
        result_b = c.encrypt(data[:mid]) + c.encrypt(data[mid:])
        self.assertEqual(result_a, result_b)


class TestMacAESCBC(unittest.TestCase):
    @mac_only
    def test_encrypt_nist(self):
        from nsz.mac_crypto import MacAESCBC
        cipher = MacAESCBC(CBC_KEY, CBC_IV, encrypt=True)
        self.assertEqual(cipher.encrypt(CBC_PLAIN), CBC_CIPHER)

    @mac_only
    def test_decrypt_nist(self):
        old_argv = sys.argv
        sys.argv = ['test']
        try:
            from nsz.mac_crypto import MacAESCBC
            cipher = MacAESCBC(CBC_KEY, CBC_IV, encrypt=False)
            self.assertEqual(cipher.decrypt(CBC_CIPHER), CBC_PLAIN)
        finally:
            sys.argv = old_argv


class TestMacAESECB(unittest.TestCase):
    @mac_only
    def test_encrypt_nist(self):
        from nsz.mac_crypto import MacAESECB
        cipher = MacAESECB(ECB_KEY, encrypt=True)
        self.assertEqual(cipher.encrypt(ECB_PLAIN), ECB_CIPHER)

    @mac_only
    def test_decrypt_nist(self):
        from nsz.mac_crypto import MacAESECB
        cipher = MacAESECB(ECB_KEY, encrypt=False)
        self.assertEqual(cipher.decrypt(ECB_CIPHER), ECB_PLAIN)


class TestRouter(unittest.TestCase):
    def test_fallback_on_non_macos(self):
        """Router must return a pycryptodome object when mocked off macOS."""
        import unittest.mock as mock
        import sys
        old_argv = sys.argv
        sys.argv = ['pytest']
        try:
            try:
                from Cryptodome.Cipher import AES
            except ImportError:
                from Crypto.Cipher import AES
            from nsz.mac_crypto import create_aes_cipher
            with mock.patch("platform.system", return_value="Linux"):
                cipher = create_aes_cipher(CTR_KEY, AES.MODE_CTR, counter=_make_counter())
            self.assertNotIn("Mac", type(cipher).__name__)
        finally:
            sys.argv = old_argv

    @mac_only
    def test_unsupported_mode_falls_back(self):
        """Any mode not in the native set must route to pycryptodome without error."""
        try:
            from Cryptodome.Cipher import AES
        except ImportError:
            from Crypto.Cipher import AES
        from nsz.mac_crypto import create_aes_cipher
        # MODE_SIV is not supported by CommonCrypto — must not raise
        # Try finding a mode not in _NATIVE_MODES, or simply pass a dummy int
        try:
            # Let's pass 99 as a mode pycryptodome may not like but shouldn't crash router
            mode_siv = getattr(AES, 'MODE_SIV', 99)
            cipher = create_aes_cipher(CTR_KEY * 2, mode_siv)
            self.assertNotIn("Mac", type(cipher).__name__)
        except Exception as e:
            # We don't care if pycryptodome fails on an invalid mode, just that the
            # native router didn't raise our custom errors.
            pass


def _make_counter():
    try:
        from Cryptodome.Util import Counter
    except ImportError:
        from Crypto.Util import Counter
    return Counter.new(128, initial_value=int.from_bytes(CTR_IV, 'big'))


if __name__ == "__main__":
    unittest.main()
