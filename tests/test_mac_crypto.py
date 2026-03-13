import contextlib
import ctypes
import importlib
import platform
import random
import sys
import types
import unittest
import warnings
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
AES128_PATH = ROOT / "nsz" / "nut" / "aes128.py"
MAC_CRYPTO_PATH = ROOT / "nsz" / "nut" / "mac_crypto.py"
PARSE_ARGUMENTS_PATH = ROOT / "nsz" / "ParseArguments.py"


def _load_source_module(path, name, platform_name=None, argv=None):
    source = path.read_text(encoding="utf-8")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    platform_patch = (
        mock.patch("platform.system", return_value=platform_name)
        if platform_name is not None
        else contextlib.nullcontext()
    )
    argv_patch = (
        mock.patch.object(sys, "argv", ["nsz"] + list(argv))
        if argv is not None
        else contextlib.nullcontext()
    )
    with platform_patch, argv_patch:
        exec(compile(source, str(path), "exec"), module.__dict__)
    return module


def _load_pure_aes128():
    return _load_source_module(AES128_PATH, "test_aes128_pure", platform_name="Linux")


def _load_mac_crypto():
    return _load_source_module(MAC_CRYPTO_PATH, "test_mac_crypto")


def _build_wrappers():
    pure = _load_pure_aes128()
    mac_crypto = _load_mac_crypto()
    wrappers = mac_crypto.build_darwin_overrides(
        pure.AESCBC,
        pure.AESCTR,
        pure.AESXTS,
        pure.AESXTSN,
        pure.AESECB,
        pure.Counter.new,
        pure.uhx,
    )
    return pure, mac_crypto, wrappers


class ImportHookTests(unittest.TestCase):
    def test_darwin_overrides_are_disabled_by_default(self):
        aes128 = _load_source_module(
            AES128_PATH,
            "test_aes128_darwin_default",
            platform_name="Darwin",
        )
        self.assertFalse(aes128.darwin_overrides_enabled())

    def test_enable_darwin_overrides_applies_overrides(self):
        aes128 = _load_source_module(
            AES128_PATH,
            "test_aes128_darwin_enable",
            platform_name="Darwin",
        )

        class SentinelAESCBC:
            pass

        class SentinelAESCTR:
            pass

        class SentinelAESXTS:
            pass

        class SentinelAESXTSN:
            pass

        class SentinelAESECB:
            pass

        with mock.patch.object(
            aes128,
            "_load_darwin_overrides",
            return_value=(
                SentinelAESCBC,
                SentinelAESCTR,
                SentinelAESXTS,
                SentinelAESXTSN,
                SentinelAESECB,
            ),
        ):
            self.assertTrue(aes128.enable_darwin_overrides())

        self.assertTrue(aes128.darwin_overrides_enabled())
        self.assertIs(aes128.AESECB, SentinelAESECB)

    def test_mac_crypto_import_converts_missing_symbols_into_importerror(self):
        fake_cdll = types.SimpleNamespace()

        with mock.patch("ctypes.util.find_library", return_value="/usr/lib/libSystem.B.dylib"):
            with mock.patch("ctypes.CDLL", return_value=fake_cdll):
                with self.assertRaisesRegex(ImportError, "Required CommonCrypto APIs are unavailable"):
                    _load_source_module(MAC_CRYPTO_PATH, "test_mac_crypto_missing_symbols", platform_name="Darwin")

    def test_mac_crypto_uses_typed_commoncrypto_pointers(self):
        class FakeFunc:
            pass

        fake_cdll = types.SimpleNamespace(
            CCCryptorCreateWithMode=FakeFunc(),
            CCCryptorUpdate=FakeFunc(),
            CCCryptorRelease=FakeFunc(),
        )

        with mock.patch("ctypes.util.find_library", return_value="/usr/lib/libSystem.B.dylib"):
            with mock.patch("ctypes.CDLL", return_value=fake_cdll):
                mac_crypto = _load_source_module(
                    MAC_CRYPTO_PATH,
                    "test_mac_crypto_typed_pointers",
                    platform_name="Darwin",
                )

        self.assertEqual(
            mac_crypto._cc.CCCryptorCreateWithMode.argtypes[-1],
            ctypes.POINTER(ctypes.c_void_p),
        )
        self.assertEqual(
            mac_crypto._cc.CCCryptorUpdate.argtypes[-1],
            ctypes.POINTER(ctypes.c_size_t),
        )

    def test_load_darwin_overrides_warns_on_expected_import_failures(self):
        aes128 = _load_pure_aes128()

        for error in (ImportError("missing backend"), OSError("dlopen failed")):
            with self.subTest(error=type(error).__name__):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    overrides = aes128._load_darwin_overrides(
                        import_module=lambda _: (_ for _ in ()).throw(error)
                    )

                self.assertIsNone(overrides)
                self.assertEqual(len(caught), 1)
                self.assertIn("Failed to load Darwin crypto backend", str(caught[0].message))

    def test_load_darwin_overrides_does_not_swallow_unexpected_errors(self):
        aes128 = _load_pure_aes128()

        with self.assertRaisesRegex(ValueError, "boom"):
            aes128._load_darwin_overrides(
                import_module=lambda _: (_ for _ in ()).throw(ValueError("boom"))
            )


class ContractTests(unittest.TestCase):
    def test_ecb_decrypt_block_rejects_wrong_size(self):
        _, _, wrappers = _build_wrappers()
        AESECB = wrappers[4]
        cipher = AESECB(b"k" * 16)

        with self.assertRaisesRegex(ValueError, "block must be exactly 16 bytes"):
            cipher.decrypt_block_ecb(b"x" * 15)

    def test_configure_darwin_native_crypto_uses_parsed_flag(self):
        with mock.patch.object(sys, "argv", ["nsz"]):
            nsz = importlib.import_module("nsz")

        with mock.patch.object(nsz.aes128, "enable_darwin_overrides") as enable:
            nsz._configure_darwin_native_crypto(types.SimpleNamespace(darwin_native_crypto=True))

        enable.assert_called_once_with()

    def test_ecb_pad_block_rejects_oversized_blocks(self):
        _, _, wrappers = _build_wrappers()
        AESECB = wrappers[4]
        cipher = AESECB(b"k" * 16)

        with self.assertRaisesRegex(ValueError, "Block must be at most 10 bytes!"):
            cipher.pad_block(b"x" * 17)

    def test_parse_arguments_accepts_darwin_crypto_flag(self):
        parse_arguments = _load_source_module(
            PARSE_ARGUMENTS_PATH,
            "test_parse_arguments",
            argv=["--darwin-native-crypto"],
        )

        with mock.patch.object(sys, "argv", ["nsz", "--darwin-native-crypto"]):
            args = parse_arguments.ParseArguments.parse()
        self.assertTrue(args.darwin_native_crypto)

    def test_key_validation_matches_aes128_contract(self):
        pure, _, wrappers = _build_wrappers()
        AESCBC, _, AESXTS, AESXTSN, AESECB = wrappers

        for key_len in (24, 32):
            with self.subTest(mode="AESECB", key_len=key_len):
                with self.assertRaisesRegex(ValueError, "Key must be of size 10!"):
                    AESECB(b"k" * key_len)
            with self.subTest(mode="AESCBC", key_len=key_len):
                with self.assertRaisesRegex(ValueError, "Key must be of size 10!"):
                    AESCBC(b"k" * key_len, b"i" * 16)

        with self.subTest(mode="AESXTS", key_len=64):
            with self.assertRaisesRegex(ValueError, "Key must be of size 10!"):
                AESXTS(b"k" * 64)

        with self.subTest(mode="AESXTSN", key_len=24):
            with self.assertRaisesRegex(ValueError, "Key must be of size 10!"):
                AESXTSN((b"a" * 24, b"b" * 16))

        # CTR already supports AES-192/AES-256 in the original implementation.
        pure_ctr = pure.AESCTR(b"k" * 24, b"n" * 16)
        _, _, current_wrappers = _build_wrappers()
        current_ctr = current_wrappers[1](b"k" * 24, b"n" * 16)
        self.assertEqual(type(pure_ctr).__name__, "AESCTR")
        self.assertEqual(type(current_ctr).__name__, "AESCTR")

    def test_xtsn_sector_size_must_be_positive_integer(self):
        _, _, wrappers = _build_wrappers()
        AESXTSN = wrappers[3]
        keys = (b"a" * 16, b"b" * 16)

        for bad_value, error_type in ((0, ValueError), (-1, ValueError), ("512", TypeError), (False, TypeError)):
            with self.subTest(bad_value=bad_value):
                with self.assertRaisesRegex(error_type, "sector_size must be a positive integer"):
                    AESXTSN(keys, sector_size=bad_value)

    def test_xtsn_set_sector_size_rejects_invalid_values(self):
        _, _, wrappers = _build_wrappers()
        AESXTSN = wrappers[3]
        cipher = AESXTSN((b"a" * 16, b"b" * 16), sector_size=0x200)

        with self.assertRaisesRegex(ValueError, "sector_size must be a positive integer"):
            cipher.set_sector_size(0)

    def test_dead_factory_helpers_were_removed(self):
        _, mac_crypto, _ = _build_wrappers()
        self.assertFalse(hasattr(mac_crypto, "create_aes_cipher"))
        self.assertFalse(hasattr(mac_crypto, "extract_iv_from_counter"))


class FallbackTests(unittest.TestCase):
    def test_update_chunks_large_buffers(self):
        mac_crypto = _load_mac_crypto()

        class DummyCipher(mac_crypto._MacAESBase):
            def __init__(self):
                super().__init__()
                self._cryptor_ref = ctypes.c_void_p(1)
                self.chunks = []

            def _update_chunk(self, data):
                self.chunks.append(bytes(data))
                return bytes(data)

            def _release(self):
                self._cryptor_ref = None

        cipher = DummyCipher()
        data = b"abcdefghijklmnopqrstuvwxyz"

        with mock.patch.object(mac_crypto, "_CHUNK_SIZE", 8):
            self.assertEqual(cipher._update(data), data)

        self.assertEqual(cipher.chunks, [b"abcdefgh", b"ijklmnop", b"qrstuvwx", b"yz"])

    def test_non_darwin_module_builds_wrappers_that_fall_back_cleanly(self):
        pure = _load_pure_aes128()
        mac_crypto = _load_source_module(
            MAC_CRYPTO_PATH,
            "test_mac_crypto_non_darwin",
            platform_name="Linux",
        )
        wrappers = mac_crypto.build_darwin_overrides(
            pure.AESCBC,
            pure.AESCTR,
            pure.AESXTS,
            pure.AESXTSN,
            pure.AESECB,
            pure.Counter.new,
            pure.uhx,
        )
        AESECB = wrappers[4]
        key = b"k" * 16
        data = b"d" * 32

        cipher = AESECB(key)

        self.assertIsNotNone(cipher._fallback)
        self.assertEqual(cipher.encrypt(data), pure.AESECB(key).encrypt(data))

    def test_cbc_probe_results_are_cached(self):
        _, mac_crypto, wrappers = _build_wrappers()
        AESCBC = wrappers[0]
        init_calls = []

        class FakeMacAESCBC:
            def __init__(self, key, iv, encrypt):
                init_calls.append((len(key), len(iv), encrypt))

            def encrypt(self, data):
                return data

            def decrypt(self, data):
                return data

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

        with mock.patch.object(mac_crypto, "MacAESCBC", FakeMacAESCBC):
            AESCBC(b"k" * 16, b"i" * 16)
            AESCBC(b"z" * 16, b"j" * 16)

        self.assertEqual(
            init_calls,
            [(16, 16, True), (16, 16, False)],
        )

    def test_cbc_falls_back_only_for_backend_init_failures(self):
        pure, mac_crypto, wrappers = _build_wrappers()
        AESCBC = wrappers[0]
        key = b"k" * 16
        iv = b"i" * 16
        data = b"d" * 32

        class BackendUnavailable:
            def __init__(self, *args, **kwargs):
                raise RuntimeError("unsupported on this macOS")

        with mock.patch.object(mac_crypto, "MacAESCBC", BackendUnavailable):
            cipher = AESCBC(key, iv)

        self.assertIsNotNone(cipher._fallback)
        self.assertEqual(cipher.encrypt(data), pure.AESCBC(key, iv).encrypt(data))
        self.assertEqual(cipher.decrypt(data), pure.AESCBC(key, iv).decrypt(data))

    def test_ctr_falls_back_only_for_backend_init_failures(self):
        pure, mac_crypto, wrappers = _build_wrappers()
        AESCTR = wrappers[1]
        key = b"k" * 16
        nonce = b"n" * 16
        data = b"d" * 32

        class BackendUnavailable:
            def __init__(self, *args, **kwargs):
                raise RuntimeError("unsupported on this macOS")

        with mock.patch.object(mac_crypto, "MacAESCTR", BackendUnavailable):
            cipher = AESCTR(key, nonce, 0x40)

        self.assertIsNotNone(cipher._fallback)
        self.assertEqual(cipher.encrypt(data), pure.AESCTR(key, nonce, 0x40).encrypt(data))
        cipher.bktrSeek(0x80, 7)
        pure_cipher = pure.AESCTR(key, nonce, 0x40)
        pure_cipher.bktrSeek(0x80, 7)
        self.assertEqual(cipher.encrypt(data), pure_cipher.encrypt(data))

    def test_ctr_seek_releases_replaced_native_contexts(self):
        _, mac_crypto, wrappers = _build_wrappers()
        AESCTR = wrappers[1]
        instances = []

        class FakeMacAESCTR:
            def __init__(self, key, iv):
                self.released = 0
                instances.append(self)

            def encrypt(self, data):
                return data

            def decrypt(self, data):
                return data

            def _release(self):
                self.released += 1

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self._release()

        with mock.patch.object(mac_crypto, "MacAESCTR", FakeMacAESCTR):
            cipher = AESCTR(b"k" * 16, b"n" * 16, 0)
            self.assertEqual(len(instances), 2)
            self.assertEqual(instances[1].released, 0)

            cipher.seek(0x40)
            self.assertEqual(instances[1].released, 1)
            self.assertEqual(instances[2].released, 0)

            cipher.bktrSeek(0x80, 7)
            self.assertEqual(instances[2].released, 1)
            self.assertEqual(instances[3].released, 0)

    def test_ecb_falls_back_only_for_backend_init_failures(self):
        pure, mac_crypto, wrappers = _build_wrappers()
        AESECB = wrappers[4]
        key = b"k" * 16
        data = b"d" * 32

        class BackendUnavailable:
            def __init__(self, *args, **kwargs):
                raise OSError("no backend")

        with mock.patch.object(mac_crypto, "MacAESECB", BackendUnavailable):
            cipher = AESECB(key)

        self.assertIsNotNone(cipher._fallback)
        self.assertEqual(cipher.encrypt(data), pure.AESECB(key).encrypt(data))

    def test_ecb_does_not_swallow_programmer_errors(self):
        _, mac_crypto, wrappers = _build_wrappers()
        AESECB = wrappers[4]

        class BrokenBackend:
            def __init__(self, *args, **kwargs):
                raise ValueError("boom")

        with mock.patch.object(mac_crypto, "MacAESECB", BrokenBackend):
            with self.assertRaisesRegex(ValueError, "boom"):
                AESECB(b"k" * 16)

    def test_xts_falls_back_only_for_backend_init_failures(self):
        pure, mac_crypto, wrappers = _build_wrappers()
        AESXTS = wrappers[2]
        key = b"k" * 32
        data = b"d" * 512

        class BackendUnavailable:
            def __init__(self, *args, **kwargs):
                raise OSError("no backend")

        with mock.patch.object(mac_crypto, "MacAESXTS", BackendUnavailable):
            cipher = AESXTS(key)

        self.assertIsNotNone(cipher._fallback)
        self.assertEqual(cipher.encrypt(data), pure.AESXTS(key).encrypt(data))

    def test_xtsn_falls_back_only_for_backend_init_failures(self):
        pure, mac_crypto, wrappers = _build_wrappers()
        AESXTSN = wrappers[3]
        keys = (b"a" * 16, b"b" * 16)
        data = b"d" * 512

        class BackendUnavailable:
            def __init__(self, *args, **kwargs):
                raise RuntimeError("unsupported on this macOS")

        with mock.patch.object(mac_crypto, "MacAESXTS", BackendUnavailable):
            cipher = AESXTSN(keys, sector_size=0x200, sector=3)

        self.assertIsNotNone(cipher._fallback)
        self.assertEqual(cipher.encrypt(data), pure.AESXTSN(keys, sector_size=0x200, sector=3).encrypt(data))

    def test_xts_does_not_swallow_programmer_errors(self):
        _, mac_crypto, wrappers = _build_wrappers()
        AESXTS = wrappers[2]

        class BrokenBackend:
            def __init__(self, *args, **kwargs):
                raise ValueError("boom")

        with mock.patch.object(mac_crypto, "MacAESXTS", BrokenBackend):
            with self.assertRaisesRegex(ValueError, "boom"):
                AESXTS(b"k" * 32)


@unittest.skipUnless(platform.system() == "Darwin", "CommonCrypto parity checks require macOS")
class DarwinParityTests(unittest.TestCase):
    def test_ecb_wrapper_matches_pure_across_repeated_calls(self):
        pure, _, wrappers = _build_wrappers()
        AESECB = wrappers[4]
        rng = random.Random(4321)

        def rb(size):
            return bytes(rng.getrandbits(8) for _ in range(size))

        key = rb(16)
        pure_cipher = pure.AESECB(key)
        wrapped_cipher = AESECB(key)

        for size in (32, 17, 0, 16, 5, 48):
            data = rb(size)
            with self.subTest(size=size):
                self.assertEqual(pure_cipher.encrypt(data), wrapped_cipher.encrypt(data))

    def test_wrappers_match_pure_outputs(self):
        pure, _, wrappers = _build_wrappers()
        AESCBC, AESCTR, AESXTS, AESXTSN, AESECB = wrappers
        rng = random.Random(1234)

        def rb(size):
            return bytes(rng.getrandbits(8) for _ in range(size))

        for size in (0, 1, 15, 16, 17, 32, 48):
            key = rb(16)
            data = rb(size)
            with self.subTest(mode="AESECB.encrypt", size=size):
                self.assertEqual(pure.AESECB(key).encrypt(data), AESECB(key).encrypt(data))
            if size % 16 == 0:
                with self.subTest(mode="AESECB.decrypt", size=size):
                    self.assertEqual(pure.AESECB(key).decrypt(data), AESECB(key).decrypt(data))

        for size in (0, 16, 32, 48):
            key = rb(16)
            iv = rb(16)
            data = rb(size)
            with self.subTest(mode="AESCBC.encrypt", size=size):
                self.assertEqual(pure.AESCBC(key, iv).encrypt(data), AESCBC(key, iv).encrypt(data))
            with self.subTest(mode="AESCBC.decrypt", size=size):
                self.assertEqual(pure.AESCBC(key, iv).decrypt(data), AESCBC(key, iv).decrypt(data))

        for offset in (0, 16, 32, 0x100, 0x1230):
            key = rb(16)
            nonce = rb(16)
            data = rb(64)
            with self.subTest(mode="AESCTR.encrypt", offset=offset):
                self.assertEqual(
                    pure.AESCTR(key, nonce, offset).encrypt(data),
                    AESCTR(key, nonce, offset).encrypt(data),
                )
            with self.subTest(mode="AESCTR.decrypt", offset=offset):
                self.assertEqual(
                    pure.AESCTR(key, nonce, offset).decrypt(data),
                    AESCTR(key, nonce, offset).decrypt(data),
                )

        for sector in (0, 1, 7, 128):
            key = rb(32)
            for size in (16, 32, 512, 1024):
                data = rb(size)
                with self.subTest(mode="AESXTS.encrypt", sector=sector, size=size):
                    self.assertEqual(pure.AESXTS(key, sector).encrypt(data), AESXTS(key, sector).encrypt(data))
                with self.subTest(mode="AESXTS.decrypt", sector=sector, size=size):
                    self.assertEqual(pure.AESXTS(key, sector).decrypt(data), AESXTS(key, sector).decrypt(data))

        for sector in (0, 1, 7, 128):
            keys = (rb(16), rb(16))
            for sector_size in (0x200, 0x400):
                for size in (16, 32, sector_size, sector_size * 2):
                    data = rb(size)
                    with self.subTest(mode="AESXTSN.encrypt", sector=sector, sector_size=sector_size, size=size):
                        self.assertEqual(
                            pure.AESXTSN(keys, sector_size, sector).encrypt(data),
                            AESXTSN(keys, sector_size, sector).encrypt(data),
                        )
                    with self.subTest(mode="AESXTSN.decrypt", sector=sector, sector_size=sector_size, size=size):
                        self.assertEqual(
                            pure.AESXTSN(keys, sector_size, sector).decrypt(data),
                            AESXTSN(keys, sector_size, sector).decrypt(data),
                        )

    def test_ctr_seek_and_bktrseek_match_pure_outputs(self):
        pure, _, wrappers = _build_wrappers()
        AESCTR = wrappers[1]
        rng = random.Random(9876)

        def rb(size):
            return bytes(rng.getrandbits(8) for _ in range(size))

        key = rb(16)
        nonce = rb(16)
        data = rb(64)
        pure_cipher = pure.AESCTR(key, nonce, 0)
        wrapped_cipher = AESCTR(key, nonce, 0)

        for offset in (0, 16, 32, 0x100, 0x1230):
            with self.subTest(mode="seek", offset=offset):
                pure_cipher.seek(offset)
                wrapped_cipher.seek(offset)
                self.assertEqual(pure_cipher.encrypt(data), wrapped_cipher.encrypt(data))

        for offset, ctr_val, virtual_offset in ((0, 7, 0), (0x80, 7, 0), (0x20, 3, 0x100)):
            with self.subTest(mode="bktrSeek", offset=offset, ctr_val=ctr_val, virtual_offset=virtual_offset):
                pure_cipher.bktrSeek(offset, ctr_val, virtual_offset)
                wrapped_cipher.bktrSeek(offset, ctr_val, virtual_offset)
                self.assertEqual(pure_cipher.encrypt(data), wrapped_cipher.encrypt(data))
