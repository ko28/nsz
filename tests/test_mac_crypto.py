"""
NIST AES-CTR Known Answer Test.
Reference vector from NIST SP 800-38A, Section F.5.1 (AES-128-CTR encrypt).
https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
"""
import sys
import platform
import unittest

KEY        = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
IV         = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
PLAINTEXT  = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
CIPHERTEXT = bytes.fromhex(
    "874d6191b620e3261bef6864990db6ce"
    "9806f66b7970fdff8617187bb9fffdff"
    "5ae4df3edbd5d35e5b4f09020db03eab"
    "1e031dda2fbe03d1792170a0f3009cee"
)

class TestMacAESCTR(unittest.TestCase):
    @unittest.skipUnless(platform.system() == "Darwin", "macOS only")
    def test_encrypt_nist_vector(self):
        from nsz.mac_crypto import MacAESCTR
        cipher = MacAESCTR(KEY, IV)
        result = cipher.encrypt(PLAINTEXT)
        self.assertEqual(result, CIPHERTEXT, "Encryption output does not match NIST vector")

    @unittest.skipUnless(platform.system() == "Darwin", "macOS only")
    def test_decrypt_nist_vector(self):
        from nsz.mac_crypto import MacAESCTR
        cipher = MacAESCTR(KEY, IV)
        result = cipher.decrypt(CIPHERTEXT)
        self.assertEqual(result, PLAINTEXT, "Decryption output does not match NIST vector")

    @unittest.skipUnless(platform.system() == "Darwin", "macOS only")
    def test_error_code_on_bad_key(self):
        from nsz.mac_crypto import MacAESCTR
        with self.assertRaises(RuntimeError):
            MacAESCTR(b"tooshort", IV)  # Invalid key length must raise, not silently corrupt

    @unittest.skipUnless(platform.system() == "Darwin", "macOS only")
    def test_large_input_chunking(self):
        """Verify that inputs larger than _CHUNK_SIZE (8MB) produce correct output."""
        from nsz.mac_crypto import MacAESCTR
        # 20MB of zeros — forces the slow chunked path
        large_plain = bytes(20 * 1024 * 1024)
        cipher_a = MacAESCTR(KEY, IV)
        cipher_b = MacAESCTR(KEY, IV)
        # Encrypt in one call vs. two separate calls — results must be identical
        result_single = cipher_a.encrypt(large_plain)
        result_chunked = (
            cipher_b.encrypt(large_plain[:10 * 1024 * 1024])
            + cipher_b.encrypt(large_plain[10 * 1024 * 1024:])
        )
        self.assertEqual(result_single, result_chunked,
                         "Chunked output does not match single-call output")

    def test_xts_mode_routes_to_pycryptodome(self):
        """XTS and all non-CTR modes must never reach MacAESCTR."""
        # Mock sys.argv to prevent argparse from failing during import inside test
        import sys
        old_argv = sys.argv
        sys.argv = ['pytest']
        try:
            from Cryptodome.Cipher import AES
            from nsz.mac_crypto import create_aes_cipher
            xts_key = bytes(32)  # XTS requires a double-length key
            # Not all environments might have MODE_XTS built, but we can pass a dummy int.
            # 7 is usually MODE_XTS, but for testing any int != MODE_CTR works.
            mode_xts = getattr(AES, 'MODE_XTS', 7)
            cipher = create_aes_cipher(xts_key, mode_xts)
            # If this returns without error and is NOT a MacAESCTR instance, routing is correct
            self.assertNotEqual(type(cipher).__name__, "MacAESCTR")
        finally:
            sys.argv = old_argv

if __name__ == "__main__":
    unittest.main()
