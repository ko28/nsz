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
        self._cryptor_ref = ctypes.c_void_p(None)
        self.block_size = 16

    def _init_cryptor(self, op, mode, key, iv, tweak, tweak_len, options):
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
        if status != kCCSuccess:
            raise RuntimeError(
                f"CCCryptorCreateWithMode failed (status={status}). "
                f"mode={mode}, keylen={len(key)}, op={op}"
            )

    def _update(self, data: bytes) -> bytes:
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
        if self._cryptor_ref is not None and self._cryptor_ref.value is not None:
            try:
                _cc.CCCryptorRelease(self._cryptor_ref)
            except Exception:
                pass
            finally:
                self._cryptor_ref = None

    def __enter__(self):  return self
    def __exit__(self, *a): self._release()
    def __del__(self):      self._release()

# Phase 5: Mode-Specific Wrapper Classes
class MacAESCTR(_MacAESBase):
    def __init__(self, key: bytes, iv: bytes):
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
    def encrypt(self, data: bytes) -> bytes: return self._update(data)
    def decrypt(self, data: bytes) -> bytes: return self._update(data)

class MacAESXTS(_MacAESBase):
    def __init__(self, key: bytes, tweak: bytes, encrypt: bool):
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
        if len(data) % 16 != 0:
            raise ValueError(
                f"XTS input must be a multiple of 16 bytes (got {len(data)}). "
                "CommonCrypto XTS does not support partial blocks."
            )
    def encrypt(self, data: bytes) -> bytes:
        self._check_alignment(data)
        return self._update(data)
    def decrypt(self, data: bytes) -> bytes:
        self._check_alignment(data)
        return self._update(data)

class MacAESCBC(_MacAESBase):
    def __init__(self, key: bytes, iv: bytes, encrypt: bool):
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
        if len(data) % 16 != 0:
            raise ValueError(f"CBC input must be a multiple of 16 bytes (got {len(data)})")
    def encrypt(self, data: bytes) -> bytes:
        self._check_alignment(data)
        return self._update(data)
    def decrypt(self, data: bytes) -> bytes:
        self._check_alignment(data)
        return self._update(data)

class MacAESECB(_MacAESBase):
    def __init__(self, key: bytes, encrypt: bool):
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
        if len(data) % 16 != 0:
            raise ValueError(f"ECB input must be a multiple of 16 bytes (got {len(data)})")
    def encrypt(self, data: bytes) -> bytes:
        self._check_alignment(data)
        return self._update(data)
    def decrypt(self, data: bytes) -> bytes:
        self._check_alignment(data)
        return self._update(data)


def build_darwin_overrides(pure_aescbc, pure_aesctr, pure_aesxts, pure_aesxtsn, pure_aesecb, counter_new, uhx_fn):
    def validate_aes128_key(key):
        key = bytes(key)
        if len(key) != 16:
            raise ValueError(_AES128_KEY_SIZE_ERROR)
        return key

    def probe_ecb_backend(key):
        with MacAESECB(key, encrypt=True) as encrypt_cipher:
            encrypt_cipher.encrypt(b"\0" * 16)
        with MacAESECB(key, encrypt=False) as decrypt_cipher:
            decrypt_cipher.decrypt(b"\0" * 16)

    def probe_cbc_backend(key, iv):
        with MacAESCBC(key, iv, encrypt=True) as encrypt_cipher:
            encrypt_cipher.encrypt(b"\0" * 16)
        with MacAESCBC(key, iv, encrypt=False) as decrypt_cipher:
            decrypt_cipher.decrypt(b"\0" * 16)

    def probe_ctr_backend(key, iv):
        with MacAESCTR(key, iv) as cipher:
            cipher.encrypt(b"\0" * 16)

    def probe_xts_backend(key, tweak):
        with MacAESXTS(key, tweak, encrypt=True) as encrypt_cipher:
            encrypt_cipher.encrypt(b"\0" * 16)
        with MacAESXTS(key, tweak, encrypt=False) as decrypt_cipher:
            decrypt_cipher.decrypt(b"\0" * 16)

    class AESECB:
        """macOS-backed AES ECB cipher with aes128.py compatibility helpers."""

        def __init__(self, key):
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
            if self._fallback is not None:
                return self._fallback.decrypt(data)
            if len(data) % self.block_size:
                raise ValueError("Data is not aligned to block size!")
            if not data:
                return b""
            return self._decrypt_cipher.decrypt(data)

        def encrypt_block_ecb(self, block):
            if self._fallback is not None:
                return self._fallback.encrypt_block_ecb(block)
            return self._encrypt_cipher.encrypt(self.pad_block(block))

        def decrypt_block_ecb(self, block):
            if self._fallback is not None:
                return self._fallback.decrypt_block_ecb(block)
            assert len(block) == self.block_size
            return self._decrypt_cipher.decrypt(block)

        def pad_block(self, block):
            assert len(block) <= self.block_size
            num_pad = self.block_size - len(block)
            right = (chr(num_pad) * num_pad).encode()
            return block + right

    class AESCBC:
        """macOS-backed AES CBC cipher preserving the existing aes128.py API."""

        def __init__(self, key, iv):
            self.key = validate_aes128_key(key)
            self.block_size = 0x10
            if len(iv) != self.block_size:
                raise ValueError("IV must be of size %X!" % self.block_size)
            self.iv = bytes(iv)
            self._fallback = None
            try:
                probe_cbc_backend(self.key, self.iv)
            except _NATIVE_INIT_FALLBACK_EXCEPTIONS:
                self._fallback = pure_aescbc(self.key, self.iv)

        def encrypt(self, data, iv=None):
            if self._fallback is not None:
                return self._fallback.encrypt(data, iv)
            if not data:
                return b""
            if iv is None:
                iv = self.iv
            with MacAESCBC(self.key, bytes(iv), encrypt=True) as cipher:
                return cipher.encrypt(data)

        def decrypt(self, data, iv=None):
            if self._fallback is not None:
                return self._fallback.decrypt(data, iv)
            if not data:
                return b""
            if iv is None:
                iv = self.iv
            with MacAESCBC(self.key, bytes(iv), encrypt=False) as cipher:
                return cipher.decrypt(data)

        def set_iv(self, iv):
            if len(iv) != self.block_size:
                raise ValueError("IV must be of size %X!" % self.block_size)
            self.iv = bytes(iv)
            if self._fallback is not None:
                self._fallback.set_iv(self.iv)

    class AESCTR:
        """macOS-backed AES CTR cipher preserving seek-based counter resets."""

        def __init__(self, key, nonce, offset=0):
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
            self.ctr = counter_new(64, prefix=prefix, initial_value=(offset >> 4))

        def encrypt(self, data, ctr=None):
            if self._fallback is not None:
                return self._fallback.encrypt(data, ctr)
            return self.aes.encrypt(data)

        def decrypt(self, data, ctr=None):
            if self._fallback is not None:
                return self._fallback.decrypt(data, ctr)
            return self.encrypt(data, ctr)

        def seek(self, offset):
            self._set_ctr_state(self.nonce[0:8], offset)
            if self._fallback is not None:
                self._fallback.seek(offset)
                self.aes = self._fallback.aes
                return
            self.aes = MacAESCTR(self.key, self._iv_from_prefix(self.nonce[0:8], offset))

        def bktrPrefix(self, ctr_val):
            return self.nonce[0:4] + ctr_val.to_bytes(4, "big")

        def bktrSeek(self, offset, ctr_val, virtualOffset=0):
            offset += virtualOffset
            prefix = self.bktrPrefix(ctr_val)
            self._set_ctr_state(prefix, offset)
            if self._fallback is not None:
                self._fallback.bktrSeek(offset, ctr_val)
                self.aes = self._fallback.aes
                return
            self.aes = MacAESCTR(self.key, self._iv_from_prefix(prefix, offset))

        def _iv_from_prefix(self, prefix, offset):
            return bytes(prefix) + (offset >> 4).to_bytes(8, "big")

    class AESXTS:
        """macOS-backed AES XTS cipher preserving sector-based helpers."""

        def __init__(self, keys, sector=0):
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
            if self._fallback is not None:
                return self._fallback.encrypt_sector(data, tweak)
            if len(data) % self.block_size:
                raise ValueError("Data is not aligned to block size!")
            with MacAESXTS(self._native_key, self._tweak_bytes(tweak), encrypt=True) as cipher:
                return cipher.encrypt(data)

        def decrypt(self, data, sector=None):
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
            if self._fallback is not None:
                return self._fallback.decrypt_sector(data, tweak)
            if len(data) % self.block_size:
                raise ValueError("Data is not aligned to block size!")
            with MacAESXTS(self._native_key, self._tweak_bytes(tweak), encrypt=False) as cipher:
                return cipher.decrypt(data)

        def get_tweak(self, sector=None):
            if sector is None:
                sector = self.sector
            tweak = 0
            for i in range(self.block_size):
                tweak |= (sector & 0xFF) << (i * 8)
                sector >>= 8
            return tweak

        def set_sector(self, sector):
            self.sector = sector
            if self._fallback is not None:
                self._fallback.set_sector(sector)

        def _tweak_bytes(self, tweak):
            if isinstance(tweak, int):
                return uhx_fn("%032X" % tweak)
            return bytes(tweak)

    class AESXTSN:
        """macOS-backed Nintendo AES XTS cipher preserving tuple-key input."""

        def __init__(self, keys, sector_size=0x200, sector=0):
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
            if self._fallback is not None:
                return self._fallback.encrypt_sector(data, tweak)
            if len(data) % self.block_size:
                raise ValueError("Data is not aligned to block size!")
            with MacAESXTS(self._native_key, self._tweak_bytes(tweak), encrypt=True) as cipher:
                return cipher.encrypt(data)

        def decrypt(self, data, sector=None):
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
            if self._fallback is not None:
                return self._fallback.decrypt_sector(data, tweak)
            if len(data) % self.block_size:
                raise ValueError("Data is not aligned to block size!")
            with MacAESXTS(self._native_key, self._tweak_bytes(tweak), encrypt=False) as cipher:
                return cipher.decrypt(data)

        def get_tweak(self, sector=None):
            if sector is None:
                sector = self.sector
            tweak = 0
            for i in range(self.block_size):
                tweak |= (sector & 0xFF) << (i * 8)
                sector >>= 8
            return tweak

        def set_sector(self, sector):
            self.sector = sector
            if self._fallback is not None:
                self._fallback.set_sector(sector)

        def set_sector_size(self, sector_size):
            self.sector_size = sector_size
            if self._fallback is not None:
                self._fallback.set_sector_size(sector_size)

        def _tweak_bytes(self, tweak):
            if isinstance(tweak, int):
                return uhx_fn("%032X" % tweak)
            return bytes(tweak)

    return AESCBC, AESCTR, AESXTS, AESXTSN, AESECB
