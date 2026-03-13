# Pure python AES128 implementation
# SciresM, 2017
from struct import unpack as up, pack as pk
from binascii import hexlify as hx, unhexlify as uhx
from nsz.mac_crypto import create_aes_cipher as AES_new
from Crypto.Cipher import AES
from Crypto.Util import Counter

def sxor(s1, s2):
	assert(len(s1) == len(s2))
	return b''.join([pk('B', x ^ y) for x,y in zip(s1, s2)])

class AESCBC:
	'''Class for performing AES CBC cipher operations.'''

	def __init__(self, key, iv):
		self.aes = AES_new(key, getattr(AES, 'MODE_CBC', 2), iv)
		self.block_size = 16
		if len(iv) != self.block_size:
			raise ValueError('IV must be of size %X!' % self.block_size)
		self.iv = iv

	def encrypt(self, data, iv=None):
		'''Encrypts some data in CBC mode.'''
		if iv is None:
			return self.aes.encrypt(data)
		else:
			return AES_new(self.aes.key if hasattr(self.aes, 'key') else self.aes._key if hasattr(self.aes, '_key') else self.aes, getattr(AES, 'MODE_CBC', 2), iv).encrypt(data)

	def decrypt(self, data, iv=None):
		'''Decrypts some data in CBC mode.'''
		if len(data) % self.block_size:
			raise ValueError('Data is not aligned to block size!')
		if iv is None:
			return self.aes.decrypt(data)
		else:
			return AES_new(self.aes.key if hasattr(self.aes, 'key') else self.aes._key if hasattr(self.aes, '_key') else self.aes, getattr(AES, 'MODE_CBC', 2), iv).decrypt(data)

	def set_iv(self, iv):
		if len(iv) != self.aes.block_size:
			raise ValueError('IV must be of size %X!' % self.aes.block_size)
		self.iv = iv

class AESCTR:
	'''Class for performing AES CTR cipher operations.'''

	def __init__(self, key, nonce, offset = 0):
		self.key = key
		self.nonce = nonce
		self.seek(offset)

	def encrypt(self, data, ctr=None):
		if ctr is None:
			ctr = self.ctr
		return self.aes.encrypt(data)

	def decrypt(self, data, ctr=None):
		return self.encrypt(data, ctr)

	def seek(self, offset):
		self.ctr = Counter.new(64, prefix=self.nonce[0:8], initial_value=(offset >> 4))
		self.aes = AES_new(self.key, AES.MODE_CTR, counter=self.ctr)
		
	def bktrPrefix(self, ctr_val):
		return self.nonce[0:4] + ctr_val.to_bytes(4, 'big')
		
	def bktrSeek(self, offset, ctr_val, virtualOffset = 0):
		offset += virtualOffset
		self.ctr = Counter.new(64, prefix=self.bktrPrefix(ctr_val), initial_value=(offset >> 4))
		self.aes = AES_new(self.key, AES.MODE_CTR, counter=self.ctr)

class AESXTS:
	'''Class for performing AES XTS cipher operations'''

	def __init__(self, keys, sector=0):
		self.keys = keys[:16], keys[16:]
		if not(type(self.keys) is tuple and len(self.keys) == 2):
			raise TypeError('XTS mode requires a tuple of two keys.')
		self.raw_keys = keys

		self.sector = sector
		self.block_size = 16
		self.sector_size = 0x200

	def encrypt(self, data, sector=None):
		if sector is None:
			sector = self.sector
		if len(data) % self.block_size:
			raise ValueError('Data is not aligned to block size!')
		out = b''
		while data:
			tweak = self.get_tweak(sector)
			out += AES_new(self.raw_keys, getattr(AES, 'MODE_XTS', 7), nonce=tweak.to_bytes(16, 'little'), encrypt=True).encrypt(data[:self.sector_size])
			data = data[self.sector_size:]
			sector += 1
		return out

	def decrypt(self, data, sector=None):
		if sector is None:
			sector = self.sector
		if len(data) % self.block_size:
			raise ValueError('Data is not aligned to block size!')
		out = b''
		while data:
			tweak = self.get_tweak(sector)
			out += AES_new(self.raw_keys, getattr(AES, 'MODE_XTS', 7), nonce=tweak.to_bytes(16, 'little'), encrypt=False).decrypt(data[:self.sector_size])
			data = data[self.sector_size:]
			sector += 1
		return out

	def get_tweak(self, sector=None):
		if sector is None:
			sector = self.sector
		return sector

	def set_sector(self, sector):
		self.sector = sector

class AESXTSN:
	'''Class for performing Nintendo AES XTS cipher operations'''

	def __init__(self, keys, sector_size=0x200, sector=0):
		if not(type(keys) is tuple and len(keys) == 2):
			raise TypeError('XTS mode requires a tuple of two keys.')
		self.raw_keys = keys[0] + keys[1]
		self.keys = keys
		self.sector = sector
		self.sector_size = sector_size
		self.block_size = 16

	def encrypt(self, data, sector=None):
		if sector is None:
			sector = self.sector
		if len(data) % self.block_size:
			raise ValueError('Data is not aligned to block size!')
		out = b''
		while data:
			tweak = self.get_tweak(sector)
			out += AES_new(self.raw_keys, getattr(AES, 'MODE_XTS', 7), nonce=tweak.to_bytes(16, 'little'), encrypt=True).encrypt(data[:self.sector_size])
			data = data[self.sector_size:]
			sector += 1
		return out

	def decrypt(self, data, sector=None):
		if sector is None:
			sector = self.sector
		if len(data) % self.block_size:
			raise ValueError('Data is not aligned to block size!')
		out = b''
		while data:
			tweak = self.get_tweak(sector)
			out += AES_new(self.raw_keys, getattr(AES, 'MODE_XTS', 7), nonce=tweak.to_bytes(16, 'little'), encrypt=False).decrypt(data[:self.sector_size])
			data = data[self.sector_size:]
			sector += 1
		return out

	def get_tweak(self, sector=None):
		'''Gets tweak for use in XEX.'''
		if sector is None:
			sector = self.sector
		return sector

	def set_sector(self, sector):
		self.sector = sector

	def set_sector_size(self, sector_size):
		self.sector_size = sector_size

class AESECB:
	'''Class for performing AES ECB cipher operations.'''

	def __init__(self, key):
		self.aes = AES_new(key, getattr(AES, 'MODE_ECB', 1))
		self.block_size = 16
		if len(key) != self.block_size:
			raise ValueError('Key must be of size %X!' % self.block_size)

	def encrypt(self, data):
		'''Encrypts some data in ECB mode.'''
		return AES_new(self.aes.key if hasattr(self.aes, 'key') else self.aes._key if hasattr(self.aes, '_key') else getattr(self.aes, '_key', self.aes), getattr(AES, 'MODE_ECB', 1), encrypt=True).encrypt(data)

	def decrypt(self, data):
		'''Decrypts some data in EBC mode.'''
		if len(data) % self.block_size:
			raise ValueError('Data is not aligned to block size!')
		return AES_new(self.aes.key if hasattr(self.aes, 'key') else self.aes._key if hasattr(self.aes, '_key') else getattr(self.aes, '_key', self.aes), getattr(AES, 'MODE_ECB', 1), encrypt=False).decrypt(data)

	def encrypt_block_ecb(self, block):
		return self.encrypt(block)

	def decrypt_block_ecb(self, block):
		return self.decrypt(block)
