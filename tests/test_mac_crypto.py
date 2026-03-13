import contextlib
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
    """
    Load and execute a Python source file into a new module object, optionally patching platform.system() and sys.argv for the duration of execution.
    
    Parameters:
        path (pathlib.Path): Path to the Python source file to load.
        name (str): Name to assign to the created module.
        platform_name (str | None): If provided, temporarily patch platform.system() to return this value while the module is executed.
        argv (iterable[str] | None): If provided, temporarily set sys.argv to ["nsz"] + list(argv) while the module is executed.
    
    Returns:
        types.ModuleType: A module object whose namespace contains the executed source and whose __file__ is set to the given path.
    """
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
    """
    Load the pure-Python AES128 implementation into a fresh module configured for Linux.
    
    Returns:
        module: The imported aes128 module object loaded from AES128_PATH with its platform simulated as "Linux".
    """
    return _load_source_module(AES128_PATH, "test_aes128_pure", platform_name="Linux")


def _load_mac_crypto():
    """
    Load the mac_crypto source module for tests.
    
    Returns:
        module: The imported mac_crypto module object loaded from MAC_CRYPTO_PATH and named "test_mac_crypto".
    """
    return _load_source_module(MAC_CRYPTO_PATH, "test_mac_crypto")


def _build_wrappers():
    """
    Load the pure AES128 implementation and the mac_crypto module, then construct Darwin override wrappers.
    
    Returns:
        tuple: A 3-tuple (pure_module, mac_crypto_module, wrappers) where
            - pure_module: the loaded pure AES128 module,
            - mac_crypto_module: the loaded mac_crypto module,
            - wrappers: the tuple of wrapper constructors returned by mac_crypto.build_darwin_overrides.
    """
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
    def test_darwin_crypto_flag_defaults_disabled(self):
        sentinel = types.ModuleType("nsz.nut.mac_crypto")

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

        sentinel.build_darwin_overrides = lambda *args: (
            SentinelAESCBC,
            SentinelAESCTR,
            SentinelAESXTS,
            SentinelAESXTSN,
            SentinelAESECB,
        )

        with mock.patch.dict(sys.modules, {"nsz.nut.mac_crypto": sentinel}):
            aes128 = _load_source_module(
                AES128_PATH,
                "test_aes128_darwin_without_flag",
                platform_name="Darwin",
                argv=[],
            )

        self.assertFalse(aes128._darwin_crypto_enabled([]))
        self.assertNotEqual(aes128.AESECB, SentinelAESECB)

    def test_darwin_crypto_flag_enables_overrides(self):
        sentinel = types.ModuleType("nsz.nut.mac_crypto")

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

        sentinel.build_darwin_overrides = lambda *args: (
            SentinelAESCBC,
            SentinelAESCTR,
            SentinelAESXTS,
            SentinelAESXTSN,
            SentinelAESECB,
        )

        with mock.patch.dict(sys.modules, {"nsz.nut.mac_crypto": sentinel}):
            aes128 = _load_source_module(
                AES128_PATH,
                "test_aes128_darwin_with_flag",
                platform_name="Darwin",
                argv=["--darwin-native-crypto"],
            )

        self.assertTrue(aes128._darwin_crypto_enabled(["--darwin-native-crypto"]))
        self.assertIs(aes128.AESECB, SentinelAESECB)

    def test_mac_crypto_import_converts_missing_symbols_into_importerror(self):
        fake_cdll = types.SimpleNamespace()

        with mock.patch("ctypes.util.find_library", return_value="/usr/lib/libSystem.B.dylib"):
            with mock.patch("ctypes.CDLL", return_value=fake_cdll):
                with self.assertRaisesRegex(ImportError, "Required CommonCrypto APIs are unavailable"):
                    _load_source_module(MAC_CRYPTO_PATH, "test_mac_crypto_missing_symbols", platform_name="Darwin")

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

    def test_dead_factory_helpers_were_removed(self):
        _, mac_crypto, _ = _build_wrappers()
        self.assertFalse(hasattr(mac_crypto, "create_aes_cipher"))
        self.assertFalse(hasattr(mac_crypto, "extract_iv_from_counter"))


class FallbackTests(unittest.TestCase):
    def test_non_darwin_module_builds_wrappers_that_fall_back_cleanly(self):
        """
        Verify that building Darwin overrides on a non-Darwin platform produces wrappers that fall back to the pure-Python implementations and yield identical outputs.
        
        Loads the pure AES implementation and constructs mac_crypto wrappers with a simulated Linux platform, then checks that the AESECB wrapper uses a fallback implementation and that its encryption output matches the pure AESECB encryption for the same key and data.
        """
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
                """
                Record this constructor call by appending a tuple of (key length, IV length, encrypt flag) to the module-level `init_calls` list.
                
                Parameters:
                    key (bytes-like): Cipher key whose length will be recorded.
                    iv (bytes-like): Initialization vector whose length will be recorded.
                    encrypt (bool): Indicates whether the instance is for encryption (`True`) or decryption (`False`).
                """
                init_calls.append((len(key), len(iv), encrypt))

            def encrypt(self, data):
                """
                Return the input data unchanged (no encryption performed).
                
                Parameters:
                    data (bytes-like): Data to be returned as-is.
                
                Returns:
                    bytes-like: The same `data` value passed to the function.
                """
                return data

            def decrypt(self, data):
                """
                Return the input data unchanged.
                
                Parameters:
                    data (bytes | bytearray | memoryview): Data provided for decryption; not modified.
                
                Returns:
                    bytes | bytearray | memoryview: The same object passed in `data`.
                """
                return data

            def __enter__(self):
                """
                Enter the context manager and provide the instance for use inside the with-statement.
                
                Returns:
                    self: The context manager instance.
                """
                return self

            def __exit__(self, *args):
                """
                No-op context manager exit that does not suppress exceptions.
                
                Returns:
                    None: Indicates that exceptions raised inside the with-block are not suppressed and should propagate.
                """
                return None

        with mock.patch.object(mac_crypto, "MacAESCBC", FakeMacAESCBC):
            AESCBC(b"k" * 16, b"i" * 16)
            AESCBC(b"z" * 16, b"j" * 16)

        self.assertEqual(
            init_calls,
            [(16, 16, True), (16, 16, False)],
        )

    def test_cbc_falls_back_only_for_backend_init_failures(self):
        """
        Verify the CBC wrapper falls back to the pure-Python implementation when the native backend fails to initialize.
        
        Patches the native MacAESCBC backend to raise during construction, constructs the wrapped AESCBC cipher, and asserts that a fallback implementation is set and that encrypt/decrypt produce the same outputs as the pure implementation.
        """
        pure, mac_crypto, wrappers = _build_wrappers()
        AESCBC = wrappers[0]
        key = b"k" * 16
        iv = b"i" * 16
        data = b"d" * 32

        class BackendUnavailable:
            def __init__(self, *args, **kwargs):
                """
                Constructor disabled on macOS.
                
                This initializer is unsupported on macOS and will always raise an error when invoked.
                
                Raises:
                    RuntimeError: always raised with message "unsupported on this macOS".
                """
                raise RuntimeError("unsupported on this macOS")

        with mock.patch.object(mac_crypto, "MacAESCBC", BackendUnavailable):
            cipher = AESCBC(key, iv)

        self.assertIsNotNone(cipher._fallback)
        self.assertEqual(cipher.encrypt(data), pure.AESCBC(key, iv).encrypt(data))
        self.assertEqual(cipher.decrypt(data), pure.AESCBC(key, iv).decrypt(data))

    def test_ctr_falls_back_only_for_backend_init_failures(self):
        """
        Verifies the CTR wrapper falls back to the pure implementation only when native backend initialization fails.
        
        Creates a wrapper using a backend that raises on construction, ensures the wrapper records a fallback backend, and asserts that encrypt and seek (bktrSeek) behaviors produce the same outputs as the pure AESCTR implementation.
        """
        pure, mac_crypto, wrappers = _build_wrappers()
        AESCTR = wrappers[1]
        key = b"k" * 16
        nonce = b"n" * 16
        data = b"d" * 32

        class BackendUnavailable:
            def __init__(self, *args, **kwargs):
                """
                Constructor disabled on macOS.
                
                This initializer is unsupported on macOS and will always raise an error when invoked.
                
                Raises:
                    RuntimeError: always raised with message "unsupported on this macOS".
                """
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
                """
                Initialize the context with the provided key and IV and register the instance.
                
                Parameters:
                    key (bytes): Encryption key material.
                    iv (bytes): Initialization vector or counter value for the cipher.
                
                Notes:
                    Sets the `released` attribute to 0 and appends the instance to the module-level `instances` list.
                """
                self.released = 0
                instances.append(self)

            def encrypt(self, data):
                """
                Return the input data unchanged (no encryption performed).
                
                Parameters:
                    data (bytes-like): Data to be returned as-is.
                
                Returns:
                    bytes-like: The same `data` value passed to the function.
                """
                return data

            def decrypt(self, data):
                """
                Return the input data unchanged.
                
                Parameters:
                    data (bytes | bytearray | memoryview): Data provided for decryption; not modified.
                
                Returns:
                    bytes | bytearray | memoryview: The same object passed in `data`.
                """
                return data

            def _release(self):
                """
                Increment the instance's released counter.
                
                Increments the `released` attribute by one to record that a release action occurred.
                """
                self.released += 1

            def __enter__(self):
                """
                Enter the context manager and provide the instance for use inside the with-statement.
                
                Returns:
                    self: The context manager instance.
                """
                return self

            def __exit__(self, *args):
                """
                Release held resources when exiting a context manager.
                
                If the context is exited due to an exception, the exception info is passed as (exc_type, exc_value, traceback) via *args; this method always releases internal resources and does not suppress exceptions (does not return True).
                """
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
        """
        Verifies the ECB wrapper falls back to the pure implementation only when backend initialization fails.
        
        Patches the native ECB backend to raise on construction, asserts the wrapper records a fallback, and confirms encryption output matches the pure AESECB implementation.
        """
        pure, mac_crypto, wrappers = _build_wrappers()
        AESECB = wrappers[4]
        key = b"k" * 16
        data = b"d" * 32

        class BackendUnavailable:
            def __init__(self, *args, **kwargs):
                """
                Initialize instance but always raises an OSError indicating no backend is available.
                
                Raises:
                    OSError: Always raised with message "no backend".
                """
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
                """
                Initialize the object and immediately raise a ValueError.
                
                Raises:
                    ValueError: always raised with the message "boom".
                """
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
                """
                Initialize instance but always raises an OSError indicating no backend is available.
                
                Raises:
                    OSError: Always raised with message "no backend".
                """
                raise OSError("no backend")

        with mock.patch.object(mac_crypto, "MacAESXTS", BackendUnavailable):
            cipher = AESXTS(key)

        self.assertIsNotNone(cipher._fallback)
        self.assertEqual(cipher.encrypt(data), pure.AESXTS(key).encrypt(data))

    def test_xtsn_falls_back_only_for_backend_init_failures(self):
        """
        Verifies that the AES XTSN wrapper falls back to the pure implementation when backend initialization fails.
        
        Patches the native XTS backend to raise during construction, constructs an AESXTSN wrapper with given keys and sector parameters, and asserts that a fallback implementation is present and that encryption output matches the pure AESXTSN implementation.
        """
        pure, mac_crypto, wrappers = _build_wrappers()
        AESXTSN = wrappers[3]
        keys = (b"a" * 16, b"b" * 16)
        data = b"d" * 512

        class BackendUnavailable:
            def __init__(self, *args, **kwargs):
                """
                Constructor disabled on macOS.
                
                This initializer is unsupported on macOS and will always raise an error when invoked.
                
                Raises:
                    RuntimeError: always raised with message "unsupported on this macOS".
                """
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
                """
                Initialize the object and immediately raise a ValueError.
                
                Raises:
                    ValueError: always raised with the message "boom".
                """
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
            """
            Produce random bytes of the given length.
            
            Parameters:
                size (int): Number of bytes to generate.
            
            Returns:
                bytes: A bytes object of length `size` containing random byte values.
            """
            return bytes(rng.getrandbits(8) for _ in range(size))

        key = rb(16)
        pure_cipher = pure.AESECB(key)
        wrapped_cipher = AESECB(key)

        for size in (32, 17, 0, 16, 5, 48):
            data = rb(size)
            with self.subTest(size=size):
                self.assertEqual(pure_cipher.encrypt(data), wrapped_cipher.encrypt(data))

    def test_wrappers_match_pure_outputs(self):
        """
        Verify that wrapped cipher implementations produce outputs identical to the pure (reference) implementations.
        
        Exercises multiple modes and input variations: AESECB (encrypt and aligned decrypt across several sizes), AESCBC (encrypt/decrypt with different block lengths and IVs), AESCTR (encrypt/decrypt with various counter offsets), AESXTS (encrypt/decrypt across sectors and sizes), and AESXTSN (encrypt/decrypt with two-key XTS using different sector sizes). Ensures parity for both encryption and decryption where applicable.
        """
        pure, _, wrappers = _build_wrappers()
        AESCBC, AESCTR, AESXTS, AESXTSN, AESECB = wrappers
        rng = random.Random(1234)

        def rb(size):
            """
            Produce random bytes of the given length.
            
            Parameters:
                size (int): Number of bytes to generate.
            
            Returns:
                bytes: A bytes object of length `size` containing random byte values.
            """
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
