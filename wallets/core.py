import os
import re
import struct
import binascii
try:
	import bsddb3
except:
	pass
import sqlite3
import bitcoinlib
import hashlib
import Crypto
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from wallets import wallet

class SerializationError(Exception):
	""" Thrown when there's a problem deserializing or serializing """

def priv_key_to_secret(privkey):
	if len(privkey) == 279:
		return privkey[9:9+32]
	else:
		return privkey[8:8+32]

def ordsix(x):
	if x.__class__ == int:return x
	return ord(x)
def chrsix(x):
	if not(x.__class__ in [int, int]):return x
	return bytes([x])

class BCDataStream(object):
	def __init__(self):
		self.input = None
		self.read_cursor = 0

	def clear(self):
		self.input = None
		self.read_cursor = 0

	def write(self, bytes):	# Initialize with string of bytes
		if self.input is None:
			self.input = bytes
		else:
			self.input += bytes

	def seek_file(self, position):
		self.read_cursor = position
	def close_file(self):
		self.input.close()

	def read_string(self):
		# Strings are encoded depending on length:
		# 0 to 252 :	1-byte-length followed by bytes (if any)
		# 253 to 65,535 : byte'253' 2-byte-length followed by bytes
		# 65,536 to 4,294,967,295 : byte '254' 4-byte-length followed by bytes
		# ... and the Bitcoin client is coded to understand:
		# greater than 4,294,967,295 : byte '255' 8-byte-length followed by bytes of string
		# ... but I don't think it actually handles any strings that big.
		if self.input is None:
			raise SerializationError("call write(bytes) before trying to deserialize")

		try:
			length = self.read_compact_size()
		except IndexError:
			raise SerializationError("attempt to read past end of buffer")

		return self.read_bytes(length)

	def write_string(self, string):
		# Length-encoded as with read-string
		self.write_compact_size(len(string))
		self.write(string)

	def read_bytes(self, length):
		try:
			result = self.input[self.read_cursor:self.read_cursor+length]
			self.read_cursor += length
			return result
		except IndexError:
			raise SerializationError("attempt to read past end of buffer")

		return b''

	def read_boolean(self): return self.read_bytes(1)[0] != chrsix(0)
	def read_int16(self): return self._read_num('<h')
	def read_uint16(self): return self._read_num('<H')
	def read_int32(self): return self._read_num('<i')
	def read_uint32(self): return self._read_num('<I')
	def read_int64(self): return self._read_num('<q')
	def read_uint64(self): return self._read_num('<Q')

	def write_boolean(self, val): return self.write(chrsix(int(val)))
	def write_int16(self, val): return self._write_num('<h', val)
	def write_uint16(self, val): return self._write_num('<H', val)
	def write_int32(self, val): return self._write_num('<i', val)
	def write_uint32(self, val): return self._write_num('<I', val)
	def write_int64(self, val): return self._write_num('<q', val)
	def write_uint64(self, val): return self._write_num('<Q', val)

	def read_compact_size(self):
		size = ordsix(self.input[self.read_cursor])
		self.read_cursor += 1
		if size == 253:
			size = self._read_num('<H')
		elif size == 254:
			size = self._read_num('<I')
		elif size == 255:
			size = self._read_num('<Q')
		return size

	def write_compact_size(self, size):
		if size < 0:
			raise SerializationError("attempt to write size < 0")
		elif size < 253:
			self.write(chrsix(size))
		elif size < 2**16:
			self.write('\xfd')
			self._write_num('<H', size)
		elif size < 2**32:
			self.write('\xfe')
			self._write_num('<I', size)
		elif size < 2**64:
			self.write('\xff')
			self._write_num('<Q', size)

	def _read_num(self, format):
		(i,) = struct.unpack_from(format, self.input, self.read_cursor)
		self.read_cursor += struct.calcsize(format)
		return i

	def _write_num(self, format, num):
		s = struct.pack(format, num)
		self.write(s)


class Core:
	def __init__(self, wallet_filename, params):
		self._wallet_filename = wallet_filename
		self._network_name = params['network_name']

		self._json_db = {}
		self._json_db['addresses'] = []
		self._json_db['walletdescriptorckeys'] = []
		self._json_db['walletdescriptorkeys'] = []
		self._json_db['walletdescriptors'] = []
		self._json_db['ckeys'] = []
		self._json_db['keys'] = []
		self._json_db['keys'] = []
		self._json_db['mkey'] = {}

		self._parse_wallet()
		
		if self.is_encrypted():
			self._part_encrypted_master_key = self._json_db['mkey']['encrypted_key'][-32:]
			self._salt = self._json_db['mkey']['salt']
			self._iter_count = self._json_db['mkey']['derivation_iterations']

	def _item_callback(self, kds, vds):
		type = kds.read_string()
		
		try:
			if type == b"name":
				address = kds.read_string()
				self._json_db["addresses"].append(address.decode())
			elif type == b"walletdescriptorkey":
				desc_id = kds.read_bytes(32)
				public_key = kds.read_bytes(kds.read_compact_size())
				private_key = vds.read_bytes(vds.read_compact_size())
				self._json_db['walletdescriptorkeys'].append({'desc_id': desc_id, 'public_key': public_key, 'private_key': priv_key_to_secret(private_key)})
			elif type == b"walletdescriptorckey":
				desc_id = kds.read_bytes(32)
				public_key = kds.read_bytes(kds.read_compact_size())
				encrypted_private_key = vds.read_bytes(vds.read_compact_size())
				self._json_db['walletdescriptorckeys'].append({'desc_id': desc_id, 'public_key': public_key, 'encrypted_private_key': encrypted_private_key})
			elif type == b"walletdescriptor":
				desc_id = kds.read_bytes(32)
				descriptor_str = vds.read_string()
				self._json_db['walletdescriptors'].append({'desc_id': desc_id, 'descriptor_str': descriptor_str.decode()})
			elif type == b"ckey":
				public_key = kds.read_bytes(kds.read_compact_size())
				encrypted_private_key = vds.read_bytes(vds.read_compact_size())
				self._json_db['ckeys'].append({'public_key': public_key, 'encrypted_private_key': encrypted_private_key})
			elif type == b"key":
				public_key = kds.read_bytes(kds.read_compact_size())
				private_key = vds.read_bytes(vds.read_compact_size())
				self._json_db['keys'].append({'public_key': public_key, 'private_key': priv_key_to_secret(private_key)})
			elif type == b"mkey":
				self._json_db['mkey']['id'] = kds.read_uint32()
				self._json_db['mkey']['encrypted_key'] = vds.read_string()
				self._json_db['mkey']['salt'] = vds.read_string()
				self._json_db['mkey']['derivation_method'] = vds.read_uint32()
				self._json_db['mkey']['derivation_iterations'] = vds.read_uint32()
				self._json_db['mkey']['other_params'] = vds.read_string()
		except:
			pass

	def _parse_wallet(self):
		kds = BCDataStream()
		vds = BCDataStream()

		try:
			wallet_filename = os.path.abspath(self._wallet_filename)
			db = bsddb3.db.DB()
			db.open(wallet_filename, "main", bsddb3.db.DB_BTREE, bsddb3.db.DB_RDONLY)

			try:
				for (key, value) in db.items():
					kds.clear(); kds.write(key)
					vds.clear(); vds.write(value)
					self._item_callback(kds, vds)
			finally:
				db.close()
			
			return
		except UnicodeEncodeError as e:
			raise ValueError("The entire path and filename of core wallets must be entirely ASCII")
		except:
			pass
    
		# It may be a more modern wallet file
		wallet_conn = sqlite3.connect(wallet_filename)
		try:
			for key, value in wallet_conn.execute('SELECT * FROM main'):
				kds.clear(); kds.write(key)
				vds.clear(); vds.write(value)
				self._item_callback(kds, vds)
		except sqlite3.OperationalError as e:
			wallet_conn.close()
			if str(e).startswith("no such table"):
				raise ValueError("Not an core wallet: " + str(e)) 
			else:
				raise  # unexpected error
		
		wallet_conn.close()

	def is_encrypted(self):
		return 'salt' in self._json_db['mkey']

	def _decrypt(self, password):
		l_sha512 = hashlib.sha512
		derived_key = password + self._json_db['mkey']['salt']
		for i in range(self._json_db['mkey']["derivation_iterations"]):
			derived_key = l_sha512(derived_key).digest()
		decrypyted_key = AES.new(derived_key[:32], Crypto.Cipher.AES.MODE_CBC, derived_key[32:32+16]).decrypt(self._json_db['mkey']['encrypted_key'])
		decrypyted_key = unpad(decrypyted_key, AES.block_size)

		for k in self._json_db['walletdescriptorckeys']:
			iv = hashlib.sha256(hashlib.sha256(k["public_key"]).digest()).digest()[0:16]
			decrypyted = AES.new(decrypyted_key, Crypto.Cipher.AES.MODE_CBC, iv).decrypt(k["encrypted_private_key"])
			decrypyted = unpad(decrypyted, AES.block_size)
			self._json_db['walletdescriptorkeys'].append({'desc_id': k['desc_id'], 'public_key': k['public_key'], 'private_key': decrypyted})
		for k in self._json_db['ckeys']:
			iv = hashlib.sha256(hashlib.sha256(k["public_key"]).digest()).digest()[0:16]
			decrypyted = AES.new(decrypyted_key, Crypto.Cipher.AES.MODE_CBC, iv).decrypt(k["encrypted_private_key"])
			decrypyted = unpad(decrypyted, AES.block_size)
			self._json_db['keys'].append({'public_key': k['public_key'], 'private_key': decrypyted})
			
	def try_passwords(self, passwords):
		# Convert Unicode strings (lazily) to UTF-8 bytestrings
		passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)

		for count, password in enumerate(passwords, 1):
			derived_key = password + self._salt
			for i in range(self._iter_count):
				derived_key = hashlib.sha512(derived_key).digest()
			part_master_key = AES.new(derived_key[:32], Crypto.Cipher.AES.MODE_CBC, self._part_encrypted_master_key[:16]).decrypt(self._part_encrypted_master_key[16:])
			
			if part_master_key == b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10":
				try:
					self._decrypt(password)
				except:
					pass

				return password.decode("utf_8", "replace")
	
	def extract_wallet_data(self):
		result = []
		bip32_keys = set()
		for address in self._json_db['addresses']:
			try:
				parsed_address = bitcoinlib.keys.Address.parse(address, network=self._network_name)
				if parsed_address.script_type == 'p2sh':
					parsed_address.script_type = 'p2sh_p2wpkh'
				for k in self._json_db['keys']:
					try:
						public_key_obj = bitcoinlib.keys.Key(k['public_key'], is_private=False, network=self._network_name)
						pub_address = public_key_obj.address(script_type=parsed_address.script_type, encoding=parsed_address.encoding)
						if pub_address == address:
							private_key_obj = bitcoinlib.keys.Key(k['private_key'], is_private=True, network=self._network_name, compressed=public_key_obj.compressed)
							res = {'address': address, 'private_key': private_key_obj.wif()}
							result.append(wallet.WalletData(wallet.WalletDataType.JSON, json.dumps(res)))
							break
					except:
						pass
				for k in self._json_db['walletdescriptorkeys']:
					try:
						descriptor = next((x for x in self._json_db['walletdescriptors'] if x['desc_id'] == k['desc_id']), None)

						match = re.search(r'\((\w+)/', descriptor['descriptor_str'])
						if match:
							pub_key = match.group(1)
							parsed_pub_key = bitcoinlib.keys.HDKey.from_wif(pub_key, self._network_name)
							priv_hd_key = bitcoinlib.keys.HDKey(None, k['private_key'], parsed_pub_key.chain, parsed_pub_key.depth, parsed_pub_key.parent_fingerprint, parsed_pub_key.child_index, True, self._network_name)
							bip32_keys.add(priv_hd_key.wif_private())
							break
					except:
						pass
			except:
				pass
		bip_result = [wallet.WalletData(wallet.WalletDataType.BIP32_MASTER_KEY, i) for i in bip32_keys]
		if len(bip_result) != 0:
			result.append([wallet.WalletData(wallet.WalletDataType.BIP32_MASTER_KEY, i) for i in bip32_keys])

		return result

	def extract_adresses_after_decrypt(self):
		return set()

	def extract_adresses(self):
		return set(self._json_db['addresses'])
	
	def extract_hashcat(self):
		cry_master = self._json_db['mkey']['encrypted_key']
		cry_master_hexlify = binascii.hexlify(self._json_db['mkey']['encrypted_key']).decode('ascii')
		cry_salt = binascii.hexlify(self._json_db['mkey']['salt']).decode('ascii')
		cry_rounds = self._json_db['mkey']['derivation_iterations']
		cry_method = self._json_db['mkey']['derivation_method']

		if cry_method != 0:
			raise ValueError("This wallet uses unknown key derivation method")
		
		if len(cry_salt) == 16:
			expected_mkey_len = 96  # 32 bytes padded to 3 AES blocks (last block is padding-only)
		elif len(cry_salt) == 36:  # Nexus legacy wallet
			expected_mkey_len = 160  # 72 bytes padded to whole AES blocks
		else:
			raise ValueError("This wallet uses unsupported salt size")
		
		if len(cry_master_hexlify) != expected_mkey_len:
			raise ValueError("This wallet uses unsupported master key size")

		cry_master = cry_master_hexlify[-64:]

		return "$bitcoin$%s$%s$%s$%s$%s$2$00$2$00" % (len(cry_master), cry_master, len(cry_salt), cry_salt, cry_rounds)


	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		pass