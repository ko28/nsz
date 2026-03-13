import ctypes
import ctypes.util
import platform

# Phase 2: Hardcoded Constants
# CommonCrypto algorithm and mode constants
kCCAlgorithmAES       = 0
kCCModeCTR            = 4
kCCModeOptionCTR_BE   = 0x0001   # Big-Endian counter — required for standard AES-CTR
kCCEncrypt            = 0
kCCSuccess            = 0

# Phase 3: ctypes Bindings
if platform.system() == "Darwin":
    _lib_path = ctypes.util.find_library("System")
    if _lib_path is None:
        raise ImportError("Could not locate macOS System library")
    _cc = ctypes.CDLL(_lib_path)

    # CCCryptorCreateWithMode
    # Returns: CCCryptorStatus (int)
    # Out param: CCCryptorRef* (pointer to void pointer)
    _cc.CCCryptorCreateWithMode.restype  = ctypes.c_int
    _cc.CCCryptorCreateWithMode.argtypes = [
        ctypes.c_uint,     # op (encrypt/decrypt — same for CTR)
        ctypes.c_uint,     # mode
        ctypes.c_uint,     # algorithm
        ctypes.c_int,      # padding (0 = none)
        ctypes.c_char_p,   # iv (16 bytes)
        ctypes.c_char_p,   # key
        ctypes.c_size_t,   # keyLength
        ctypes.c_char_p,   # tweak (NULL for CTR)
        ctypes.c_size_t,   # tweakLength (0)
        ctypes.c_int,      # numRounds (0 = default)
        ctypes.c_uint,     # options (kCCModeOptionCTR_BE)
        ctypes.c_void_p,   # cryptorRef (out param — pointer to pointer)
    ]

    # CCCryptorUpdate
    # Returns: CCCryptorStatus (int)
    _cc.CCCryptorUpdate.restype  = ctypes.c_int
    _cc.CCCryptorUpdate.argtypes = [
        ctypes.c_void_p,   # cryptorRef
        ctypes.c_char_p,   # dataIn
        ctypes.c_size_t,   # dataInLength
        ctypes.c_void_p,   # dataOut (output buffer)
        ctypes.c_size_t,   # dataOutAvailable
        ctypes.c_void_p,   # dataOutMoved (out param — pointer to size_t)
    ]

    # CCCryptorRelease
    # Returns: CCCryptorStatus (int)
    _cc.CCCryptorRelease.restype  = ctypes.c_int
    _cc.CCCryptorRelease.argtypes = [ctypes.c_void_p]


# Phase 4: The MacAESCTR Wrapper Class
class MacAESCTR:
    """
    Hardware-accelerated AES-CTR cipher using Apple's CommonCrypto framework.
    Duck-typed to match the pycryptodome AES cipher interface used by nsz.

    NOT thread-safe. Each thread must instantiate its own MacAESCTR object.
    """

    def __init__(self, key: bytes, iv: bytes):
        if len(iv) != 16:
            raise ValueError(f"IV must be exactly 16 bytes, got {len(iv)}")
        if len(key) not in (16, 24, 32):
            raise ValueError(f"Key must be 16, 24, or 32 bytes, got {len(key)}")

        self._cryptor_ref = ctypes.c_void_p(None)

        status = _cc.CCCryptorCreateWithMode(
            kCCEncrypt,           # op — encrypt and decrypt are identical in CTR mode
            kCCModeCTR,           # mode
            kCCAlgorithmAES,      # algorithm
            0,                    # padding — none for CTR
            iv,                   # iv
            key,                  # key
            len(key),             # keyLength
            None,                 # tweak — MUST be NULL for CTR
            0,                    # tweakLength
            0,                    # numRounds — 0 means use default for key size
            kCCModeOptionCTR_BE,  # options
            ctypes.byref(self._cryptor_ref),
        )

        if status != kCCSuccess:
            raise RuntimeError(
                f"CCCryptorCreateWithMode failed with status {status}. "
                f"Check key length ({len(key)}) and IV length ({len(iv)})."
            )

    # Maximum bytes to allocate as a contiguous C buffer in a single CCCryptorUpdate call.
    # nsz can theoretically pass multi-gigabyte buffers if the user has not configured
    # explicit block sizes. Allocating a 2GB ctypes string buffer will cause a MemoryError
    # or kernel kill. We process in 8MB slices instead, which keeps peak RAM overhead
    # predictable regardless of input size. CommonCrypto's internal CTR counter advances
    # correctly across calls, so slicing is transparent to the caller.
    _CHUNK_SIZE = 8 * 1024 * 1024  # 8 MiB

    def encrypt(self, data: bytes) -> bytes:
        if self._cryptor_ref is None:
            raise RuntimeError("Cryptor has been released")

        # Fast path: small inputs that fit in a single allocation
        if len(data) <= self._CHUNK_SIZE:
            return self._update_chunk(data)

        # Slow path: large inputs processed in slices to avoid giant contiguous allocations
        out = bytearray()
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + self._CHUNK_SIZE]
            out += self._update_chunk(chunk)
            offset += len(chunk)
        return bytes(out)

    def _update_chunk(self, data: bytes) -> bytes:
        """Process a single chunk through CCCryptorUpdate. Must be <= _CHUNK_SIZE."""
        out_buf   = ctypes.create_string_buffer(len(data))
        out_moved = ctypes.c_size_t(0)

        status = _cc.CCCryptorUpdate(
            self._cryptor_ref,
            data,
            len(data),
            out_buf,
            len(data),
            ctypes.byref(out_moved),
        )

        if status != kCCSuccess:
            raise RuntimeError(f"CCCryptorUpdate failed with status {status}")
        if out_moved.value != len(data):
            raise RuntimeError(
                f"CCCryptorUpdate wrote {out_moved.value} bytes, expected {len(data)}"
            )

        return out_buf.raw

    def decrypt(self, data: bytes) -> bytes:
        # AES-CTR is a symmetric stream cipher — decrypt is identical to encrypt
        return self.encrypt(data)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self._release()

    def __del__(self):
        self._release()

    def _release(self):
        # Guard against double-free and against __del__ running at interpreter
        # shutdown when the ctypes module may already be partially torn down
        if self._cryptor_ref is not None and self._cryptor_ref.value is not None:
            try:
                _cc.CCCryptorRelease(self._cryptor_ref)
            except Exception:
                pass
            finally:
                self._cryptor_ref = None

# Phase 5: Counter Extraction Bridge
def extract_iv_from_counter(counter_obj) -> bytes:
    """
    Extract the initial 16-byte IV from a pycryptodome Counter object.

    pycryptodome does not expose a clean public API for this. We read the
    internal initial_value that was passed to Counter.new() and re-encode it.

    If nsz's counter construction differs from the pattern below, update this
    function to match what you found during the Pre-Work grounding step.

    COUNTER MUTATION WARNING:
    The fallback path below calls `counter_obj()` to read the current 16-byte
    counter block. This call is STATEFUL — pycryptodome advances its internal
    counter by 1 on every call. This de-sync between the Python counter and
    the macOS hardware counter does NOT matter for correctness, because once we
    hand the IV to CommonCrypto we discard the Python counter entirely and never
    use it again. However, this is only safe if nsz discards the counter object
    after passing it into AES.new(). Before using the fallback path, verify
    (from your Pre-Work grounding step) that nsz does not retain and reuse the
    same counter_obj instance across multiple AES.new() calls. If it does,
    use only the `_initial_value` attribute path and never call counter_obj().
    """
    # Preferred path: read the stored initial integer without any side effects

    # Try the dictionary form (PyCryptodomex > 3.10 uses dictionaries internally for Counter)
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
        initial_int = counter_obj._initial_value
        return initial_int.to_bytes(16, byteorder='big')

    # Fallback: call the counter to get current block bytes.
    # ONLY safe if counter_obj is not reused after this point (see warning above).
    if callable(counter_obj):
        block_bytes = counter_obj()
        if isinstance(block_bytes, bytes) and len(block_bytes) == 16:
            return block_bytes

    raise RuntimeError(
        "Could not extract IV from pycryptodome Counter object. "
        "Inspect the Counter construction in nsz and update extract_iv_from_counter()."
    )

# Phase 6: Integration — The Fallback Router
def create_aes_cipher(key: bytes, mode: int, counter=None, **kwargs):
    """
    Returns a hardware-accelerated AES-CTR cipher on macOS (both Apple Silicon
    and Intel) when mode is AES.MODE_CTR. All other modes (XTS, CBC, ECB, etc.)
    are passed directly to pycryptodome unconditionally — MacAESCTR only handles CTR.

    Falls back to pycryptodome on all non-macOS platforms or on any error.

    THREAD SAFETY: This function creates a new cipher context on every call.
    Never share the returned object across threads.

    Usage — replace all AES.new() calls with this function:
        # Before:  AES.new(key, AES.MODE_CTR, counter=ctr)
        # After:   create_aes_cipher(key, AES.MODE_CTR, counter=ctr)
        # Before:  AES.new(key, AES.MODE_XTS, ...)
        # After:   create_aes_cipher(key, AES.MODE_XTS, ...)  # routes to pycryptodome
    """
    try:
        from Cryptodome.Cipher import AES
    except ImportError:
        from Crypto.Cipher import AES

    # Only intercept CTR mode on macOS — every other mode goes straight to pycryptodome
    if platform.system() == "Darwin" and mode == AES.MODE_CTR:
        try:
            if counter is None:
                raise ValueError("CTR mode requires a counter object")
            iv = extract_iv_from_counter(counter)
            return MacAESCTR(key, iv)
        except Exception as e:
            # Any failure falls through to pycryptodome. Log so the user can diagnose.
            print(f"[nsz] Native Mac crypto unavailable, using software AES: {e}")

    # Universal fallback: all non-CTR modes, non-macOS platforms, and any CTR failure
    if counter is not None:
        kwargs['counter'] = counter
    return AES.new(key, mode, **kwargs)
