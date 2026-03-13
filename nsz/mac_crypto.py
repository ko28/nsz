import ctypes
import ctypes.util
import platform
try:
    from Cryptodome.Cipher import AES
except ImportError:
    from Crypto.Cipher import AES

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

# Phase 3: ctypes Bindings
if platform.system() == "Darwin":
    _lib_path = ctypes.util.find_library("System")
    if _lib_path is None:
        _lib_path = "/usr/lib/libSystem.B.dylib"
    try:
        _cc = ctypes.CDLL(_lib_path)
    except OSError:
        raise ImportError(
            f"Could not load macOS System library at {_lib_path} — are you on macOS?"
        )

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
        if len(key) not in (32, 64):
            raise ValueError(
                f"XTS key must be 32 bytes (AES-128-XTS) or 64 bytes (AES-256-XTS) "
                f"(got {len(key)}). XTS concatenates two equal subkeys."
            )
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

# Phase 6: CTR Counter Extraction Bridge
def extract_iv_from_counter(counter_obj) -> bytes:
    if isinstance(counter_obj, dict):
        prefix = counter_obj.get('prefix', b'')
        suffix = counter_obj.get('suffix', b'')
        counter_len = counter_obj.get('counter_len', 0)
        initial_value = counter_obj.get('initial_value', 0)
        little_endian = counter_obj.get('little_endian', False)
        counter_bytes = initial_value.to_bytes(counter_len, 'little' if little_endian else 'big')
        block_bytes = prefix + counter_bytes + suffix
        if len(block_bytes) == 16:
            return block_bytes
    if hasattr(counter_obj, '_initial_value'):
        return counter_obj._initial_value.to_bytes(16, byteorder='big')
    if callable(counter_obj):
        block = counter_obj()
        if isinstance(block, bytes) and len(block) == 16:
            return block
    raise RuntimeError(
        "Could not extract IV from pycryptodome Counter object."
    )

# Phase 7: The Unified Fallback Router
_NATIVE_MODES = {getattr(AES, 'MODE_CTR', 6), getattr(AES, 'MODE_XTS', 7), getattr(AES, 'MODE_CBC', 2), getattr(AES, 'MODE_ECB', 1)}

def create_aes_cipher(key: bytes, mode: int, counter=None, nonce=None, **kwargs):
    if platform.system() == "Darwin" and mode in _NATIVE_MODES:
        try:
            return _create_native_cipher(key, mode, counter=counter, nonce=nonce, **kwargs)
        except Exception as e:
            print(f"[nsz] Native Mac crypto failed for mode={mode}, falling back: {e}")

    return _create_pycryptodome_cipher(key, mode, counter=counter, nonce=nonce, **kwargs)

def _create_native_cipher(key, mode, counter=None, nonce=None, **kwargs):
    if mode == getattr(AES, 'MODE_CTR', 6):
        if counter is None:
            raise ValueError("MODE_CTR requires a counter argument")
        iv = extract_iv_from_counter(counter)
        return MacAESCTR(key, iv)

    elif mode == getattr(AES, 'MODE_XTS', 7):
        tweak = nonce
        if tweak is None:
            raise ValueError("MODE_XTS requires a nonce (sector tweak) argument")
        if isinstance(tweak, int):
            tweak = tweak.to_bytes(16, byteorder='little')
        encrypt = kwargs.pop('encrypt', True)
        return MacAESXTS(key, tweak, encrypt=encrypt)

    elif mode == getattr(AES, 'MODE_CBC', 2):
        iv = kwargs.pop('iv', None)
        if iv is None:
            raise ValueError("MODE_CBC requires an iv argument")
        encrypt = kwargs.pop('encrypt', True)
        return MacAESCBC(key, iv, encrypt=encrypt)

    elif mode == getattr(AES, 'MODE_ECB', 1):
        encrypt = kwargs.pop('encrypt', True)
        return MacAESECB(key, encrypt=encrypt)

    else:
        raise ValueError(f"Mode {mode} is not in the native set — should not reach here")

def _create_pycryptodome_cipher(key, mode, counter=None, nonce=None, **kwargs):
    if counter is not None:
        kwargs['counter'] = counter
    if nonce is not None:
        kwargs['nonce'] = nonce
    return AES.new(key, mode, **kwargs)
