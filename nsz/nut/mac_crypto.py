import ctypes
import ctypes.util
import platform

# Phase 2: Hardcoded Constants
kCCAlgorithmAES      = 0
kCCModeECB           = 1
kCCModeCBC           = 2
kCCModeCTR           = 4
kCCModeXTS           = 8

kCCEncrypt           = 0
kCCDecrypt           = 1
kCCSuccess           = 0
kCCModeOptionCTR_BE  = 0x0001

_AES128_KEY_SIZE_ERROR = "Key must be of size %X!" % 0x10
_NATIVE_INIT_FALLBACK_EXCEPTIONS = (OSError, RuntimeError)
_cc = None

# Phase 3: ctypes Bindings
if platform.system() == "Darwin":
    _lib_path = ctypes.util.find_library("System")
    if _lib_path is None:
        raise ImportError("Could not locate macOS System library — are you on macOS?")
    _cc = ctypes.CDLL(_lib_path)
    try:
        _cc.CCCryptorCreateWithMode
        _cc.CCCryptorUpdate
        _cc.CCCryptorRelease
    except AttributeError as exc:
        raise ImportError("Required CommonCrypto APIs are unavailable on this macOS version") from exc

    _cc.CCCryptorCreateWithMode.restype  = ctypes.c_int
    _cc.CCCryptorCreateWithMode.argtypes = [
        ctypes.c_uint,    # op
        ctypes.c_uint,    # mode
        ctypes.c_uint,    # algorithm
        ctypes.c_int,     # padding
        ctypes.c_char_p,  # iv
        ctypes.c_char_p,  # key
        ctypes.c_size_t,  # keyLength
        ctypes.c_char_p,  # tweak
        ctypes.c_size_t,  # tweakLength
        ctypes.c_int,     # numRounds
        ctypes.c_uint,    # options
        ctypes.c_void_p,  # out: CCCryptorRef*
    ]

    _cc.CCCryptorUpdate.restype  = ctypes.c_int
    _cc.CCCryptorUpdate.argtypes = [
        ctypes.c_void_p,  # cryptorRef
        ctypes.c_char_p,  # dataIn
        ctypes.c_size_t,  # dataInLength
        ctypes.c_void_p,  # dataOut
        ctypes.c_size_t,  # dataOutAvailable
        ctypes.c_void_p,  # out: dataOutMoved
    ]

    _cc.CCCryptorRelease.restype  = ctypes.c_int
    _cc.CCCryptorRelease.argtypes = [ctypes.c_void_p]


# Phase 4: Shared Base Class
_CHUNK_SIZE = 8 * 1024 * 1024

class _MacAESBase:
    def __init__(self):
        """
        Initialize the instance, setting a null native cryptor reference and AES block size.
        
        Sets self._cryptor_ref to a null ctypes void pointer (placeholder for a CCCryptorRef) and self.block_size to 16 bytes.
        """
        self._cryptor_ref = ctypes.c_void_p(None)
        self.block_size = 16

    def _init_cryptor(self, op, mode, key, iv, tweak, tweak_len, options):
        """
        Initialize a CommonCrypto CCCryptor context for the instance.
        
        Parameters:
            op (int): Operation constant (encrypt/decrypt).
            mode (int): Cipher mode constant (e.g., CBC, CTR, XTS, ECB).
            key (bytes): AES key bytes; length must match the desired AES key size.
            iv (bytes or None): Initialization vector or None when not used by the mode.
            tweak (bytes or None): Tweak bytes for XTS mode or None otherwise.
            tweak_len (int): Length of the tweak in bytes.
            options (int): Option flags passed to CCCryptorCreateWithMode.
        
        Raises:
            RuntimeError: If the CommonCrypto backend is not available on the platform.
            RuntimeError: If CCCryptorCreateWithMode returns a non-success status.
        """
        try:
            status = _cc.CCCryptorCreateWithMode(
                op, mode, kCCAlgorithmAES,
                0,
                iv,
                key, len(key),
                tweak, tweak_len,
                0,
                options,
                ctypes.byref(self._cryptor_ref),
            )
        except AttributeError as exc:
            raise RuntimeError("CommonCrypto backend is unavailable on this platform") from exc
        if status != kCCSuccess:
            raise RuntimeError(
                f"CCCryptorCreateWithMode failed (status={status}). "
                f"mode={mode}, keylen={len(key)}, op={op}"
            )

    def _update(self, data: bytes) -> bytes:
        """
        Process the given bytes through the active cryptor and return the produced output bytes.
        
        Parameters:
            data (bytes): Input data to be processed by the cryptor.
        
        Returns:
            bytes: The resulting ciphertext or plaintext produced from the input.
        
        Raises:
            RuntimeError: If the cipher context has already been released.
        """
        if self._cryptor_ref is None or self._cryptor_ref.value is None:
            raise RuntimeError("Cipher context has been released")
        if len(data) <= _CHUNK_SIZE:
            return self._update_chunk(data)
        out = bytearray()
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + _CHUNK_SIZE]
            out += self._update_chunk(chunk)
            offset += len(chunk)
        return bytes(out)

    def _update_chunk(self, data: bytes) -> bytes:
        """
        Process a single chunk of input through the active CommonCrypto cryptor and return the produced output bytes.
        
        Returns:
            bytes: The cryptor output for the provided input; on success the returned length equals the input length.
        """
        out_buf   = ctypes.create_string_buffer(len(data))
        out_moved = ctypes.c_size_t(0)
        status = _cc.CCCryptorUpdate(
            self._cryptor_ref,
            data, len(data),
            out_buf, len(data),
            ctypes.byref(out_moved),
        )
        if status != kCCSuccess:
            raise RuntimeError(f"CCCryptorUpdate failed (status={status})")
        if out_moved.value != len(data):
            raise RuntimeError(
                f"CCCryptorUpdate wrote {out_moved.value} bytes, expected {len(data)}"
            )
        return out_buf.raw

    def _release(self):
        """
        Release the underlying native cryptor and clear its reference.
        
        If a native cryptor exists, attempts to release it via the native API and ignores any exception raised; in all cases the internal cryptor reference is set to None.
        """
        if self._cryptor_ref is not None and self._cryptor_ref.value is not None:
            try:
                _cc.CCCryptorRelease(self._cryptor_ref)
            except Exception:
                pass
            finally:
                self._cryptor_ref = None

    def __enter__(self):  """
Enter the context and return the context manager instance.

Returns:
    The context manager instance (`self`).
"""
return self
    def __exit__(self, *a): """
Exit the context manager and release any underlying CommonCrypto cryptor resources.

Parameters:
    *a: Ignored context-manager exception arguments (exc_type, exc_value, traceback).
"""
self._release()
    def __del__(self):      """
Release any native cryptor resources held by the instance when it is garbage-collected.

This ensures the underlying cryptor context is freed if not already released.
"""
self._release()

# Phase 5: Mode-Specific Wrapper Classes
class MacAESCTR(_MacAESBase):
    def __init__(self, key: bytes, iv: bytes):
        """
        Initialize a CommonCrypto-backed AES CTR-mode cryptor.
        
        Parameters:
        	key (bytes): AES key (must be 16, 24, or 32 bytes).
        	iv (bytes): Initialization vector (must be 16 bytes).
        
        Raises:
        	ValueError: If `key` length is not 16, 24, or 32 bytes, or if `iv` length is not 16 bytes.
        """
        super().__init__()
        self.key = key
        if len(key) not in (16, 24, 32):
            raise ValueError(f"CTR key must be 16, 24, or 32 bytes (got {len(key)})")
        if len(iv) != 16:
            raise ValueError(f"CTR IV must be 16 bytes (got {len(iv)})")
        self._init_cryptor(
            op=kCCEncrypt, mode=kCCModeCTR, key=key,
            iv=iv, tweak=None, tweak_len=0, options=kCCModeOptionCTR_BE,
        )
    def encrypt(self, data: bytes) -> bytes: """
Encrypt the given plaintext and return the resulting ciphertext.

Parameters:
    data (bytes): Plaintext to encrypt.

Returns:
    bytes: Ciphertext produced by encrypting `data`.
"""
return self._update(data)
    def decrypt(self, data: bytes) -> bytes: """
Decrypts the given bytes using the instance's cryptor and returns the resulting plaintext.

Parameters:
    data (bytes): Ciphertext to decrypt.

Returns:
    bytes: Decrypted plaintext.
"""
return self._update(data)

class MacAESXTS(_MacAESBase):
    def __init__(self, key: bytes, tweak: bytes, encrypt: bool):
        """
        Initialize an AES-XTS cryptor with the given 32-byte key, 16-byte tweak, and direction.
        
        Parameters:
            key (bytes): 32-byte XTS key (concatenation of two 16-byte AES keys).
            tweak (bytes): 16-byte tweak value used as the XTS tweak.
            encrypt (bool): True to initialize for encryption, False for decryption.
        
        Raises:
            ValueError: If `key` is not 32 bytes or `tweak` is not 16 bytes.
        """
        super().__init__()
        self.key = key
        if len(key) != 32:
            raise ValueError("XTS key must be 32 bytes (two 16-byte AES-128 keys)")
        if len(tweak) != 16:
            raise ValueError(f"XTS tweak must be 16 bytes (got {len(tweak)})")
        op = kCCEncrypt if encrypt else kCCDecrypt
        self._init_cryptor(
            op=op, mode=kCCModeXTS, key=key,
            iv=None, tweak=tweak, tweak_len=16, options=0,
        )
    def _check_alignment(self, data: bytes):
        """
        Ensure the provided data length is a multiple of 16 bytes for XTS operations.
        
        Parameters:
            data (bytes): Input data to validate.
        
        Raises:
            ValueError: If the length of `data` is not a multiple of 16 bytes.
        """
        if len(data) % 16 != 0:
            raise ValueError(
                f"XTS input must be a multiple of 16 bytes (got {len(data)}). "
                "CommonCrypto XTS does not support partial blocks."
            )
    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypts data using the configured AES cryptor; requires data length be a multiple of 16 bytes.
        
        Parameters:
            data (bytes): Plaintext to encrypt; length must be a multiple of 16.
        
        Returns:
            bytes: Ciphertext produced from the input data.
        
        Raises:
            ValueError: If `data` length is not a multiple of 16.
        """
        self._check_alignment(data)
        return self._update(data)
    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypts the given CBC-mode ciphertext; the input length must be a multiple of the AES block size (16 bytes).
        
        Parameters:
            data (bytes): Ciphertext to decrypt; length must be a multiple of 16.
        
        Returns:
            bytes: Decrypted plaintext.
        
        Raises:
            ValueError: If `data` length is not a multiple of 16.
        """
        self._check_alignment(data)
        return self._update(data)

class MacAESCBC(_MacAESBase):
    def __init__(self, key: bytes, iv: bytes, encrypt: bool):
        """
        Initialize a macOS-backed AES-CBC cipher context using the provided key and IV and set it to encrypt or decrypt mode.
        
        Parameters:
            key (bytes): AES key; must be 16, 24, or 32 bytes long.
            iv (bytes): Initialization vector; must be 16 bytes long.
            encrypt (bool): If True, the context is initialized for encryption; if False, for decryption.
        
        Raises:
            ValueError: If `key` is not 16, 24, or 32 bytes, or if `iv` is not 16 bytes.
        """
        super().__init__()
        self.key = key
        if len(key) not in (16, 24, 32):
            raise ValueError(f"CBC key must be 16, 24, or 32 bytes (got {len(key)})")
        if len(iv) != 16:
            raise ValueError(f"CBC IV must be 16 bytes (got {len(iv)})")
        op = kCCEncrypt if encrypt else kCCDecrypt
        self._init_cryptor(
            op=op, mode=kCCModeCBC, key=key,
            iv=iv, tweak=None, tweak_len=0, options=0,
        )
    def _check_alignment(self, data: bytes):
        """
        Ensure the input length is a multiple of 16 bytes for CBC-mode operations.
        
        Parameters:
            data (bytes): Input data to validate.
        
        Raises:
            ValueError: If the length of `data` is not a multiple of 16; the exception message includes the actual length.
        """
        if len(data) % 16 != 0:
            raise ValueError(f"CBC input must be a multiple of 16 bytes (got {len(data)})")
    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypts data using the configured AES cryptor; requires data length be a multiple of 16 bytes.
        
        Parameters:
            data (bytes): Plaintext to encrypt; length must be a multiple of 16.
        
        Returns:
            bytes: Ciphertext produced from the input data.
        
        Raises:
            ValueError: If `data` length is not a multiple of 16.
        """
        self._check_alignment(data)
        return self._update(data)
    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypts the given CBC-mode ciphertext; the input length must be a multiple of the AES block size (16 bytes).
        
        Parameters:
            data (bytes): Ciphertext to decrypt; length must be a multiple of 16.
        
        Returns:
            bytes: Decrypted plaintext.
        
        Raises:
            ValueError: If `data` length is not a multiple of 16.
        """
        self._check_alignment(data)
        return self._update(data)

class MacAESECB(_MacAESBase):
    def __init__(self, key: bytes, encrypt: bool):
        """
        Initialize the ECB-mode AES cryptor and validate the provided key.
        
        Parameters:
            key (bytes): AES key; must be 16, 24, or 32 bytes.
            encrypt (bool): If True, set up for encryption; if False, set up for decryption.
        
        Raises:
            ValueError: If `key` length is not 16, 24, or 32 bytes.
        """
        super().__init__()
        self.key = key
        if len(key) not in (16, 24, 32):
            raise ValueError(f"ECB key must be 16, 24, or 32 bytes (got {len(key)})")
        op = kCCEncrypt if encrypt else kCCDecrypt
        self._init_cryptor(
            op=op, mode=kCCModeECB, key=key,
            iv=None, tweak=None, tweak_len=0, options=0,
        )
    def _check_alignment(self, data: bytes):
        """
        Ensure the input length is a multiple of 16 bytes.
        
        Parameters:
            data (bytes): Input data whose length is validated.
        
        Raises:
            ValueError: If len(data) is not a multiple of 16.
        """
        if len(data) % 16 != 0:
            raise ValueError(f"ECB input must be a multiple of 16 bytes (got {len(data)})")
    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypts data using the configured AES cryptor; requires data length be a multiple of 16 bytes.
        
        Parameters:
            data (bytes): Plaintext to encrypt; length must be a multiple of 16.
        
        Returns:
            bytes: Ciphertext produced from the input data.
        
        Raises:
            ValueError: If `data` length is not a multiple of 16.
        """
        self._check_alignment(data)
        return self._update(data)
    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypts the given CBC-mode ciphertext; the input length must be a multiple of the AES block size (16 bytes).
        
        Parameters:
            data (bytes): Ciphertext to decrypt; length must be a multiple of 16.
        
        Returns:
            bytes: Decrypted plaintext.
        
        Raises:
            ValueError: If `data` length is not a multiple of 16.
        """
        self._check_alignment(data)
        return self._update(data)


def build_darwin_overrides(pure_aescbc, pure_aesctr, pure_aesxts, pure_aesxtsn, pure_aesecb, counter_new, uhx_fn):
    """
    Build macOS-native AES mode wrapper classes that prefer CommonCrypto and fall back to provided pure-Python implementations.
    
    Parameters:
        pure_aescbc: Fallback CBC implementation constructor accepting (key, iv).
        pure_aesctr: Fallback CTR implementation constructor accepting (key, nonce, offset).
        pure_aesxts: Fallback XTS implementation constructor accepting (key, sector).
        pure_aesxtsn: Fallback Nintendo-style XTS constructor accepting (keys_tuple, sector_size, sector).
        pure_aesecb: Fallback ECB implementation constructor accepting (key).
        counter_new: Factory to create a seekable counter (bits, prefix, initial_value).
        uhx_fn: Helper converting hex-formatted tweak strings to 16-byte tweak values.
    
    Returns:
        tuple: (AESCBC, AESCTR, AESXTS, AESXTSN, AESECB) — five classes providing AES CBC, CTR, XTS, Nintendo XTS, and ECB modes.
    """
    _cbc_backend_probe_cache = {}

    def validate_aes128_key(key):
        """
        Validate and return a 16-byte AES-128 key.
        
        Parameters:
            key (bytes-like): Input key to convert and validate.
        
        Returns:
            bytes: The input converted to bytes.
        
        Raises:
            ValueError: If the key length is not 16 bytes.
        """
        key = bytes(key)
        if len(key) != 16:
            raise ValueError(_AES128_KEY_SIZE_ERROR)
        return key

    def probe_ecb_backend(key):
        """
        Probe whether the native macOS ECB backend can create working encrypt and decrypt contexts for the given AES key.
        
        Parameters:
            key (bytes-like): AES key (expected length 16, 24, or 32 bytes).
        
        Raises:
            ValueError: If `key` has an invalid length.
            RuntimeError: If the native ECB cryptor cannot be created or an encrypt/decrypt operation fails.
        """
        with MacAESECB(key, encrypt=True) as encrypt_cipher:
            encrypt_cipher.encrypt(b"\0" * 16)
        with MacAESECB(key, encrypt=False) as decrypt_cipher:
            decrypt_cipher.decrypt(b"\0" * 16)

    def probe_cbc_backend(key, iv):
        """
        Attempt to use the macOS CommonCrypto CBC cryptor to encrypt and decrypt a single 16-byte block with the provided key and IV.
        
        Parameters:
            key (bytes): AES key (16, 24, or 32 bytes).
            iv (bytes): Initialization vector (16 bytes).
        
        Raises:
            ValueError: If the key or IV length is invalid.
            RuntimeError: If the native CBC cryptor cannot be created or processing fails.
        """
        with MacAESCBC(key, iv, encrypt=True) as encrypt_cipher:
            encrypt_cipher.encrypt(b"\0" * 16)
        with MacAESCBC(key, iv, encrypt=False) as decrypt_cipher:
            decrypt_cipher.decrypt(b"\0" * 16)

    def cbc_backend_available(key, iv):
        """
        Check whether the native macOS AES-CBC backend is usable for the given key and IV.
        
        Performs a probe of the native CBC implementation for the provided key and IV and caches the result by (key length, IV length).
        
        Parameters:
            key (bytes-like): AES key bytes.
            iv (bytes-like): Initialization vector bytes.
        
        Returns:
            bool: `True` if the native CBC backend appears usable for the given key/IV, `False` otherwise.
        """
        cache_key = (len(key), len(iv))
        if cache_key in _cbc_backend_probe_cache:
            return _cbc_backend_probe_cache[cache_key]
        try:
            probe_cbc_backend(key, iv)
        except _NATIVE_INIT_FALLBACK_EXCEPTIONS:
            _cbc_backend_probe_cache[cache_key] = False
        else:
            _cbc_backend_probe_cache[cache_key] = True
        return _cbc_backend_probe_cache[cache_key]

    def probe_ctr_backend(key, iv):
        """
        Probe whether the macOS native CTR AES backend can be initialized and used with the given key and IV.
        
        Parameters:
            key (bytes): AES key; must be 16, 24, or 32 bytes long.
            iv (bytes): Initialization vector; must be 16 bytes long.
        
        Raises:
            RuntimeError: If the native CTR backend cannot be initialized or fails during a test encryption.
        """
        with MacAESCTR(key, iv) as cipher:
            cipher.encrypt(b"\0" * 16)

    def probe_xts_backend(key, tweak):
        """
        Verify native XTS support by performing a single-block encrypt and decrypt with the given key and tweak.
        
        Parameters:
            key (bytes): 32-byte XTS key (concatenation of two 16-byte AES keys).
            tweak (bytes): 16-byte tweak value used for XTS operations.
        """
        with MacAESXTS(key, tweak, encrypt=True) as encrypt_cipher:
            encrypt_cipher.encrypt(b"\0" * 16)
        with MacAESXTS(key, tweak, encrypt=False) as decrypt_cipher:
            decrypt_cipher.decrypt(b"\0" * 16)

    class AESECB:
        """macOS-backed AES ECB cipher with aes128.py compatibility helpers."""

        def __init__(self, key):
            """
            Initialize an AESECB wrapper using a native macOS ECB backend when available; otherwise fall back to the provided pure-Python ECB implementation.
            
            Parameters:
                key: AES key to use; must be 16 bytes and will be validated/normalized by validate_aes128_key.
            
            Detailed behavior:
                - Validates and stores the AES-128 key and sets block_size to 16.
                - Attempts to probe and instantiate native MacAESECB encrypt/decrypt ciphers.
                - If native initialization fails with known fallback exceptions, instantiates the pure_aesecb fallback and disables native cipher fields.
            """
            self.key = validate_aes128_key(key)
            self.block_size = 0x10
            self._fallback = None
            try:
                probe_ecb_backend(self.key)
                self._encrypt_cipher = MacAESECB(self.key, encrypt=True)
                self._decrypt_cipher = MacAESECB(self.key, encrypt=False)
            except _NATIVE_INIT_FALLBACK_EXCEPTIONS:
                self._fallback = pure_aesecb(self.key)
                self._encrypt_cipher = None
                self._decrypt_cipher = None

        def encrypt(self, data):
            """
            Encrypt plaintext using ECB semantics, handling a final partial block without padding.
            
            Parameters:
                data (bytes): Plaintext to encrypt; may be any length (including zero).
            
            Returns:
                bytes: Ciphertext where all complete blocks (multiples of the block size) are encrypted with the main ECB cipher and a trailing partial block, if present, is encrypted with the class's block-level ECB routine; returns b"" for empty input.
            """
            if self._fallback is not None:
                return self._fallback.encrypt(data)
            if not data:
                return b""
            aligned_len = len(data) - (len(data) % self.block_size)
            if aligned_len == len(data):
                return self._encrypt_cipher.encrypt(data)

            out = []
            if aligned_len:
                out.append(self._encrypt_cipher.encrypt(data[:aligned_len]))
            out.append(self.encrypt_block_ecb(data[aligned_len:]))
            return b"".join(out)

        def decrypt(self, data):
            """
            Decrypts block-aligned ciphertext and returns the plaintext.
            
            If a fallback backend is configured, decryption is delegated to that backend.
            Parameters:
                data (bytes): Ciphertext to decrypt; length must be a multiple of the instance's block size. An empty input returns b"".
            
            Returns:
                bytes: Decrypted plaintext.
            
            Raises:
                ValueError: If `data` length is not a multiple of the block size.
            """
            if self._fallback is not None:
                return self._fallback.decrypt(data)
            if len(data) % self.block_size:
                raise ValueError("Data is not aligned to block size!")
            if not data:
                return b""
            return self._decrypt_cipher.decrypt(data)

        def encrypt_block_ecb(self, block):
            """
            Encrypts a single AES ECB block, padding inputs shorter than 16 bytes to a full block.
            
            Parameters:
                block (bytes): Plaintext block to encrypt; if shorter than 16 bytes it will be padded to 16 bytes.
            
            Returns:
                bytes: The 16-byte ciphertext block.
            """
            if self._fallback is not None:
                return self._fallback.encrypt_block_ecb(block)
            return self._encrypt_cipher.encrypt(self.pad_block(block))

        def decrypt_block_ecb(self, block):
            """
            Decrypt a single block using ECB mode.
            
            Parameters:
                block (bytes): Ciphertext block; must be exactly self.block_size bytes.
            
            Returns:
                bytes: The decrypted block, length equal to self.block_size.
            """
            if self._fallback is not None:
                return self._fallback.decrypt_block_ecb(block)
            assert len(block) == self.block_size
            return self._decrypt_cipher.decrypt(block)

        def pad_block(self, block):
            """
            Pad a partial block to the instance's block_size using PKCS#7-style padding.
            
            Parameters:
                block (bytes): Input byte string whose length must be less than or equal to the instance's block_size.
            
            Returns:
                bytes: The input block followed by N padding bytes, each with the byte value N, where N = block_size - len(block).
            
            Raises:
                ValueError: If len(block) is greater than the instance's block_size.
            """
            if len(block) > self.block_size:
                raise ValueError("Block must be at most %X bytes!" % self.block_size)
            num_pad = self.block_size - len(block)
            right = (chr(num_pad) * num_pad).encode()
            return block + right

    class AESCBC:
        """macOS-backed AES CBC cipher preserving the existing aes128.py API."""

        def __init__(self, key, iv):
            """
            Initialize a macOS-backed CBC cipher wrapper with the provided AES key and IV.
            
            Parameters:
                key (bytes-like): AES key; converted to bytes and validated to be 16 bytes long.
                iv (bytes-like): Initialization vector; must be 16 bytes and is stored as bytes.
            
            Description:
                Stores the validated key and IV and prepares a native CBC backend. If a native
                CBC backend is not available for the given key and IV, a pure-Python CBC
                fallback is created and stored in self._fallback.
            """
            self.key = validate_aes128_key(key)
            self.block_size = 0x10
            if len(iv) != self.block_size:
                raise ValueError("IV must be of size %X!" % self.block_size)
            self.iv = bytes(iv)
            self._fallback = None
            if not cbc_backend_available(self.key, self.iv):
                self._fallback = pure_aescbc(self.key, self.iv)

        def encrypt(self, data, iv=None):
            """
            Encrypts plaintext using AES in CBC mode, preferring the native macOS backend and falling back to the provided pure-Python implementation.
            
            Parameters:
                data (bytes-like): Plaintext to encrypt.
                iv (bytes, optional): 16-byte initialization vector to use; if omitted, the instance's stored IV is used.
            
            Returns:
                bytes: Ciphertext bytes; returns b"" if `data` is empty.
            """
            if self._fallback is not None:
                return self._fallback.encrypt(data, iv)
            if not data:
                return b""
            if iv is None:
                iv = self.iv
            with MacAESCBC(self.key, bytes(iv), encrypt=True) as cipher:
                return cipher.encrypt(data)

        def decrypt(self, data, iv=None):
            """
            Decrypts ciphertext using AES-CBC with the instance key, optionally overriding the stored IV.
            
            If a fallback implementation is configured on the instance, this delegates to that fallback. If `data` is empty, returns b"". If `iv` is provided, it must be a 16-byte initialization vector; otherwise the instance's stored IV is used.
            
            Parameters:
                data (bytes): Ciphertext to decrypt.
                iv (bytes | None): Optional 16-byte IV to use for this operation.
            
            Returns:
                bytes: Decrypted plaintext.
            """
            if self._fallback is not None:
                return self._fallback.decrypt(data, iv)
            if not data:
                return b""
            if iv is None:
                iv = self.iv
            with MacAESCBC(self.key, bytes(iv), encrypt=False) as cipher:
                return cipher.decrypt(data)

        def set_iv(self, iv):
            """
            Set the initialization vector (IV) for the cipher instance and propagate it to any fallback implementation.
            
            Parameters:
                iv (bytes-like): New IV whose length must equal the instance's block_size.
            
            Raises:
                ValueError: If `iv` length is not equal to `block_size`.
            """
            if len(iv) != self.block_size:
                raise ValueError("IV must be of size %X!" % self.block_size)
            self.iv = bytes(iv)
            if self._fallback is not None:
                self._fallback.set_iv(self.iv)

    class AESCTR:
        """macOS-backed AES CTR cipher preserving seek-based counter resets."""

        def __init__(self, key, nonce, offset=0):
            """
            Initialize a CTR-mode AES object, preferring the macOS native backend and falling back to the provided pure-Python CTR implementation if native initialization fails.
            
            Parameters:
                key (bytes-like): AES key (accepted lengths: 16, 24, or 32 bytes).
                nonce (bytes-like): Nonce/IV used to seed the counter (expects at least 8 bytes).
                offset (int, optional): Initial byte offset into the keystream; defaults to 0.
            
            Behavior:
                - Attempts to create and use a native macOS CTR AES instance; if that fails with a native-init fallback exception, constructs a pure-Python CTR backend instead.
                - On success, the instance attribute `aes` references the native backend; on fallback, `aes` references the fallback's AES object and `_fallback` holds the fallback instance.
            """
            self.key = bytes(key)
            self.nonce = bytes(nonce)
            self.ctr = None
            self.aes = None
            self._fallback = None
            self._set_ctr_state(self.nonce[0:8], offset)
            try:
                probe_ctr_backend(self.key, self._iv_from_prefix(self.nonce[0:8], offset))
                self.aes = MacAESCTR(self.key, self._iv_from_prefix(self.nonce[0:8], offset))
            except _NATIVE_INIT_FALLBACK_EXCEPTIONS:
                self._fallback = pure_aesctr(self.key, self.nonce, offset)
                self.aes = self._fallback.aes

        def _set_ctr_state(self, prefix, offset):
            """
            Set the internal CTR counter state from a prefix and a byte offset.
            
            Updates self.ctr to a new 64-bit counter created with the given prefix and an initial block index computed as offset divided by 16 (offset >> 4).
            
            Parameters:
                prefix (bytes): Counter prefix (prefix bytes used as the high-order part of the counter).
                offset (int): Byte offset into the stream; used to compute the initial block index as offset // 16.
            """
            self.ctr = counter_new(64, prefix=prefix, initial_value=(offset >> 4))

        def _replace_native_aes(self, prefix, offset):
            """
            Replace the current native AES-CTR instance with a new one derived from the given IV prefix and offset and release the previous instance if possible.
            
            Parameters:
            	prefix (bytes): IV prefix used to derive the new IV.
            	offset (int): Byte offset within the stream used together with `prefix` to compute the IV.
            """
            new_aes = MacAESCTR(self.key, self._iv_from_prefix(prefix, offset))
            old_aes = self.aes
            self.aes = new_aes
            if hasattr(old_aes, "_release"):
                old_aes._release()

        def encrypt(self, data, ctr=None):
            """
            Process data with AES in CTR mode using an optional counter state.
            
            Parameters:
                data (bytes): Input plaintext or ciphertext to process.
                ctr (optional): Counter object or state to use for this operation; if omitted, the instance's current counter state is used.
            
            Returns:
                bytes: The data after AES-CTR processing.
            """
            if self._fallback is not None:
                return self._fallback.encrypt(data, ctr)
            return self.aes.encrypt(data)

        def decrypt(self, data, ctr=None):
            """
            Perform CTR-mode decryption of `data` using the instance's counter state or an overridden counter.
            
            Parameters:
                data (bytes): Input ciphertext to decrypt.
                ctr (optional): Counter state or counter-like object to use instead of the instance's current counter.
            
            Returns:
                bytes: The resulting plaintext bytes.
            """
            if self._fallback is not None:
                return self._fallback.decrypt(data, ctr)
            return self.encrypt(data, ctr)

        def seek(self, offset):
            """
            Set the CTR position for subsequent encryption/decryption to the given byte offset.
            
            Updates the internal counter state derived from the instance nonce so that future
            operations start at `offset`. If a pure-Python fallback is active, delegate the
            seek to it and synchronize the `aes` attribute; otherwise replace the native
            AES counter state to reflect the new position.
            
            Parameters:
                offset (int): Byte offset within the stream to seek to.
            """
            self._set_ctr_state(self.nonce[0:8], offset)
            if self._fallback is not None:
                self._fallback.seek(offset)
                self.aes = self._fallback.aes
                return
            self._replace_native_aes(self.nonce[0:8], offset)

        def bktrPrefix(self, ctr_val):
            """
            Builds an 8-byte counter prefix by combining the first 4 bytes of the instance nonce with the given counter value.
            
            Parameters:
                ctr_val (int): Counter value to encode as a 4-byte big-endian integer.
            
            Returns:
                bytes: 8-byte prefix: nonce[0:4] followed by `ctr_val` encoded in big-endian.
            """
            return self.nonce[0:4] + ctr_val.to_bytes(4, "big")

        def bktrSeek(self, offset, ctr_val, virtualOffset=0):
            """
            Seek the internal CTR stream to a specified byte offset for a given counter value.
            
            Adjusts the current counter state to point at (offset + virtualOffset) using the IV prefix derived from `ctr_val`. If a pure-Python fallback backend is active, delegate the seek to it and adopt its AES instance; otherwise replace the native AES cryptor to reflect the new counter state.
            
            Parameters:
                offset (int): Byte offset to seek to.
                ctr_val (int | bytes): Counter value used to derive the IV prefix for CTR state.
                virtualOffset (int, optional): Additional offset to add to `offset` before seeking. Default is 0.
            """
            offset += virtualOffset
            prefix = self.bktrPrefix(ctr_val)
            self._set_ctr_state(prefix, offset)
            if self._fallback is not None:
                self._fallback.bktrSeek(offset, ctr_val)
                self.aes = self._fallback.aes
                return
            self._replace_native_aes(prefix, offset)

        def _iv_from_prefix(self, prefix, offset):
            """
            Constructs an IV by appending the 64-bit sector index derived from a byte offset to a prefix.
            
            Parameters:
                prefix (bytes-like): IV prefix bytes to prepend.
                offset (int): Byte offset; the sector index is computed as offset divided by 16 (floor).
            
            Returns:
                bytes: The IV consisting of prefix + 8-byte big-endian representation of (offset // 16).
            """
            return bytes(prefix) + (offset >> 4).to_bytes(8, "big")

    class AESXTS:
        """macOS-backed AES XTS cipher preserving sector-based helpers."""

        def __init__(self, keys, sector=0):
            """
            Initialize an XTS-mode AES instance using a 32-byte concatenated key and a starting sector.
            
            Parameters:
                keys (bytes-like): 32-byte key formed by concatenating two 16-byte AES keys (key1 || key2).
                sector (int): Initial sector index used to derive the XTS tweak (defaults to 0).
            
            Behavior:
                - Validates `keys` is 32 bytes, splits it into two 16-byte AES keys, and stores them as a tuple in `self.keys`.
                - Builds `self._native_key` by concatenating the two validated 16-byte keys.
                - Sets `self.sector`, `self.block_size` (16), and `self.sector_size` (512).
                - Attempts to probe and initialize the native macOS XTS backend using the tweak derived from `sector`; if native initialization fails, creates and stores a pure-Python fallback implementation in `self._fallback`.
            """
            keys = bytes(keys)
            if len(keys) != 32:
                raise ValueError(_AES128_KEY_SIZE_ERROR)
            half = len(keys) // 2
            self.keys = validate_aes128_key(keys[:half]), validate_aes128_key(keys[half:])
            self._native_key = self.keys[0] + self.keys[1]
            self.sector = sector
            self.block_size = 0x10
            self.sector_size = 0x200
            self._fallback = None
            try:
                tweak = self._tweak_bytes(self.get_tweak(self.sector))
                probe_xts_backend(self._native_key, tweak)
            except _NATIVE_INIT_FALLBACK_EXCEPTIONS:
                self._fallback = pure_aesxts(self._native_key, self.sector)

        def encrypt(self, data, sector=None):
            """
            Encrypts the provided data in sector-sized XTS units starting at the given sector.
            
            Parameters:
                data (bytes): Plaintext whose length must be a multiple of the instance block size.
                sector (int, optional): Starting sector index; if omitted, uses the instance's current sector.
            
            Returns:
                bytes: Concatenated ciphertext for all processed sectors.
            
            Raises:
                ValueError: If `data` length is not aligned to the block size.
            """
            if self._fallback is not None:
                return self._fallback.encrypt(data, sector)
            if sector is None:
                sector = self.sector
            if len(data) % self.block_size:
                raise ValueError("Data is not aligned to block size!")
            out = []
            while data:
                tweak = self.get_tweak(sector)
                out.append(self.encrypt_sector(data[:self.sector_size], tweak))
                data = data[self.sector_size:]
                sector += 1
            return b"".join(out)

        def encrypt_sector(self, data, tweak):
            """
            Encrypt a single XTS sector using the instance's native key and the provided tweak.
            
            Parameters:
                data (bytes): Sector plaintext; length must be a multiple of the instance block size.
                tweak (int | bytes): Sector tweak (sector index as int or a 16-byte tweak); it will be converted to the 16-byte tweak used by the native cipher.
            
            Returns:
                bytes: Ciphertext for the provided sector, same length as `data`.
            
            Raises:
                ValueError: If `data` length is not aligned to the block size.
            """
            if self._fallback is not None:
                return self._fallback.encrypt_sector(data, tweak)
            if len(data) % self.block_size:
                raise ValueError("Data is not aligned to block size!")
            with MacAESXTS(self._native_key, self._tweak_bytes(tweak), encrypt=True) as cipher:
                return cipher.encrypt(data)

        def decrypt(self, data, sector=None):
            """
            Decrypts XTS-encrypted data across one or more sectors starting at the specified sector.
            
            Parameters:
                data (bytes): Ciphertext to decrypt; length must be a multiple of the AES block size and is processed in chunks of `self.sector_size`.
                sector (int, optional): Starting sector index to use for tweaks. If omitted, `self.sector` is used.
            
            Returns:
                bytes: The plaintext resulting from decrypting `data`.
            
            Raises:
                ValueError: If `data` length is not aligned to the AES block size.
            """
            if self._fallback is not None:
                return self._fallback.decrypt(data, sector)
            if sector is None:
                sector = self.sector
            if len(data) % self.block_size:
                raise ValueError("Data is not aligned to block size!")
            out = []
            while data:
                tweak = self.get_tweak(sector)
                out.append(self.decrypt_sector(data[:self.sector_size], tweak))
                data = data[self.sector_size:]
                sector += 1
            return b"".join(out)

        def decrypt_sector(self, data, tweak):
            """
            Decrypt a single XTS-formatted sector using the provided tweak.
            
            Parameters:
                data (bytes): Ciphertext for one sector; length must be a multiple of the AES block size.
                tweak (int or bytes): Sector tweak value used to derive the XTS tweak.
            
            Returns:
                bytes: The decrypted plaintext for the sector.
            
            Raises:
                ValueError: If `data` length is not a multiple of the AES block size.
            """
            if self._fallback is not None:
                return self._fallback.decrypt_sector(data, tweak)
            if len(data) % self.block_size:
                raise ValueError("Data is not aligned to block size!")
            with MacAESXTS(self._native_key, self._tweak_bytes(tweak), encrypt=False) as cipher:
                return cipher.decrypt(data)

        def get_tweak(self, sector=None):
            """
            Compute the XTS tweak value for a sector.
            
            If `sector` is omitted, uses the instance's current `self.sector`. The returned tweak is an integer whose bytes are the low-order bytes of `sector` packed in little-endian order across `self.block_size` bytes.
            
            Parameters:
                sector (int, optional): Sector index to derive the tweak from; defaults to `self.sector`.
            
            Returns:
                int: Tweak value with `self.block_size` bytes containing the sector index in little-endian order.
            """
            if sector is None:
                sector = self.sector
            tweak = 0
            for i in range(self.block_size):
                tweak |= (sector & 0xFF) << (i * 8)
                sector >>= 8
            return tweak

        def set_sector(self, sector):
            """
            Set the current sector index used for XTS tweaks and propagate it to any fallback implementation.
            
            Parameters:
                sector (int): Sector index to use for subsequent encrypt/decrypt operations; must be non-negative.
            """
            self.sector = sector
            if self._fallback is not None:
                self._fallback.set_sector(sector)

        def _tweak_bytes(self, tweak):
            """
            Convert a tweak value to the 16-byte tweak representation used by XTS.
            
            Parameters:
                tweak (int or bytes-like): If an int, interpreted as a big-endian integer and converted to 16 bytes. If bytes-like, converted directly via bytes(tweak).
            
            Returns:
                bytes: A 16-byte sequence suitable for use as an XTS tweak.
            """
            if isinstance(tweak, int):
                return uhx_fn("%032X" % tweak)
            return bytes(tweak)

    class AESXTSN:
        """macOS-backed Nintendo AES XTS cipher preserving tuple-key input."""

        def __init__(self, keys, sector_size=0x200, sector=0):
            """
            Initialize the XTS mode wrapper with two AES-128 keys and sector parameters.
            
            Parameters:
                keys (tuple): Two AES keys; each must be 16 bytes. A TypeError is raised if `keys` is not a 2-tuple.
                sector_size (int): Size of a sector in bytes (default 0x200).
                sector (int): Starting sector index.
            
            Behavior:
                - Validates each provided key is 16 bytes and stores them as `self.keys`.
                - Concatenates the two keys into `self._native_key`.
                - Sets `self.sector`, `self.sector_size`, and `self.block_size` (16).
                - Attempts to probe and initialize the native XTS backend for the current sector tweak; if native initialization fails with a known fallback exception, sets `self._fallback` to a pure-Python XTS implementation configured with the same keys, sector_size, and sector.
            
            Raises:
                TypeError: If `keys` is not a tuple of two elements.
            """
            if not (type(keys) is tuple and len(keys) == 2):
                raise TypeError("XTS mode requires a tuple of two keys.")
            self.keys = (validate_aes128_key(keys[0]), validate_aes128_key(keys[1]))
            self._native_key = self.keys[0] + self.keys[1]
            self.sector = sector
            self.sector_size = sector_size
            self.block_size = 0x10
            self._fallback = None
            try:
                tweak = self._tweak_bytes(self.get_tweak(self.sector))
                probe_xts_backend(self._native_key, tweak)
            except _NATIVE_INIT_FALLBACK_EXCEPTIONS:
                self._fallback = pure_aesxtsn(self.keys, self.sector_size, self.sector)

        def encrypt(self, data, sector=None):
            """
            Encrypts the provided data in sector-sized XTS units starting at the given sector.
            
            Parameters:
                data (bytes): Plaintext whose length must be a multiple of the instance block size.
                sector (int, optional): Starting sector index; if omitted, uses the instance's current sector.
            
            Returns:
                bytes: Concatenated ciphertext for all processed sectors.
            
            Raises:
                ValueError: If `data` length is not aligned to the block size.
            """
            if self._fallback is not None:
                return self._fallback.encrypt(data, sector)
            if sector is None:
                sector = self.sector
            if len(data) % self.block_size:
                raise ValueError("Data is not aligned to block size!")
            out = []
            while data:
                tweak = self.get_tweak(sector)
                out.append(self.encrypt_sector(data[:self.sector_size], tweak))
                data = data[self.sector_size:]
                sector += 1
            return b"".join(out)

        def encrypt_sector(self, data, tweak):
            """
            Encrypt a single XTS sector using the instance's native key and the provided tweak.
            
            Parameters:
                data (bytes): Sector plaintext; length must be a multiple of the instance block size.
                tweak (int | bytes): Sector tweak (sector index as int or a 16-byte tweak); it will be converted to the 16-byte tweak used by the native cipher.
            
            Returns:
                bytes: Ciphertext for the provided sector, same length as `data`.
            
            Raises:
                ValueError: If `data` length is not aligned to the block size.
            """
            if self._fallback is not None:
                return self._fallback.encrypt_sector(data, tweak)
            if len(data) % self.block_size:
                raise ValueError("Data is not aligned to block size!")
            with MacAESXTS(self._native_key, self._tweak_bytes(tweak), encrypt=True) as cipher:
                return cipher.encrypt(data)

        def decrypt(self, data, sector=None):
            """
            Decrypts XTS-encrypted data across one or more sectors starting at the specified sector.
            
            Parameters:
                data (bytes): Ciphertext to decrypt; length must be a multiple of the AES block size and is processed in chunks of `self.sector_size`.
                sector (int, optional): Starting sector index to use for tweaks. If omitted, `self.sector` is used.
            
            Returns:
                bytes: The plaintext resulting from decrypting `data`.
            
            Raises:
                ValueError: If `data` length is not aligned to the AES block size.
            """
            if self._fallback is not None:
                return self._fallback.decrypt(data, sector)
            if sector is None:
                sector = self.sector
            if len(data) % self.block_size:
                raise ValueError("Data is not aligned to block size!")
            out = []
            while data:
                tweak = self.get_tweak(sector)
                out.append(self.decrypt_sector(data[:self.sector_size], tweak))
                data = data[self.sector_size:]
                sector += 1
            return b"".join(out)

        def decrypt_sector(self, data, tweak):
            """
            Decrypt a single XTS-formatted sector using the provided tweak.
            
            Parameters:
                data (bytes): Ciphertext for one sector; length must be a multiple of the AES block size.
                tweak (int or bytes): Sector tweak value used to derive the XTS tweak.
            
            Returns:
                bytes: The decrypted plaintext for the sector.
            
            Raises:
                ValueError: If `data` length is not a multiple of the AES block size.
            """
            if self._fallback is not None:
                return self._fallback.decrypt_sector(data, tweak)
            if len(data) % self.block_size:
                raise ValueError("Data is not aligned to block size!")
            with MacAESXTS(self._native_key, self._tweak_bytes(tweak), encrypt=False) as cipher:
                return cipher.decrypt(data)

        def get_tweak(self, sector=None):
            """
            Compute the XTS tweak value for a sector.
            
            If `sector` is omitted, uses the instance's current `self.sector`. The returned tweak is an integer whose bytes are the low-order bytes of `sector` packed in little-endian order across `self.block_size` bytes.
            
            Parameters:
                sector (int, optional): Sector index to derive the tweak from; defaults to `self.sector`.
            
            Returns:
                int: Tweak value with `self.block_size` bytes containing the sector index in little-endian order.
            """
            if sector is None:
                sector = self.sector
            tweak = 0
            for i in range(self.block_size):
                tweak |= (sector & 0xFF) << (i * 8)
                sector >>= 8
            return tweak

        def set_sector(self, sector):
            """
            Set the current sector index used for XTS tweaks and propagate it to any fallback implementation.
            
            Parameters:
                sector (int): Sector index to use for subsequent encrypt/decrypt operations; must be non-negative.
            """
            self.sector = sector
            if self._fallback is not None:
                self._fallback.set_sector(sector)

        def set_sector_size(self, sector_size):
            """
            Set the sector size used for XTS operations.
            
            Updates the instance's sector_size and propagates the new value to an underlying fallback implementation if present.
            
            Parameters:
                sector_size (int): Sector size in bytes used to divide data for XTS processing.
            """
            self.sector_size = sector_size
            if self._fallback is not None:
                self._fallback.set_sector_size(sector_size)

        def _tweak_bytes(self, tweak):
            """
            Convert a tweak value to the 16-byte tweak representation used by XTS.
            
            Parameters:
                tweak (int or bytes-like): If an int, interpreted as a big-endian integer and converted to 16 bytes. If bytes-like, converted directly via bytes(tweak).
            
            Returns:
                bytes: A 16-byte sequence suitable for use as an XTS tweak.
            """
            if isinstance(tweak, int):
                return uhx_fn("%032X" % tweak)
            return bytes(tweak)

    return AESCBC, AESCTR, AESXTS, AESXTSN, AESECB
