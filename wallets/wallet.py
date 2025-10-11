import itertools
import os
import re
import json
import base64
import dataclasses
import pathlib
import struct
import base58
import bip39
import hashlib
import sqlite3
import binascii
import ast

from Crypto.Protocol.KDF import PBKDF2, scrypt
from Crypto.Hash import SHA1, SHA256, SHA512, MD5, keccak
from Crypto.Cipher import AES, ChaCha20
from Crypto.Util import Counter
from Crypto.Util.Padding import unpad

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from nacl import secret
from mnemonic import Mnemonic
from gzip import decompress
from struct import Struct, unpack_from
from io import BytesIO
from dataclasses import dataclass
from enum import Enum
from binascii import crc32

from electrum.crypto import pw_decode
from electrum.storage import WalletStorage

from libs.chrome_leveldb.storage_formats.ccl_leveldb import LevelDb, RawLevelDb
from libs.chrome_leveldb.ccl_chromium_localstorage import LocalStoreDb
from libs.chrome_leveldb.ccl_chromium_indexeddb import WrappedIndexDB

from wallets.core import Core

from . import coinomi_pb2


class WalletType(Enum):
    METAMASK = 0
    CORE = 1
    TRUST = 2
    TRONLINK = 3
    ATOMIC = 4
    GUARDA = 5
    BRAVE = 6
    KEPLR = 7
    PHANTOM = 8
    RONIN = 9
    UNISAT = 10
    BRAVE_EXTENSION = 11
    BNB_CHAIN = 12
    CLOVER = 13
    KARDIA_CHAIN = 14
    SUI = 15
    COINBASE = 16
    BRAAVOS = 17
    RABBY = 18
    TERRA = 19
    EXODUS_EXTENSION = 20
    EXODUS_DESKTOP = 21
    CRYPTOCOM_EXTENSION = 22
    CRYPTOCOM = 23
    SAFEPAL = 24
    OKX = 25
    COINOMI = 26
    COIN98 = 27
    MARTIAN = 28
    MATH = 29
    PETRA = 30
    MYMONERO = 31
    METAMASK_LIKE = 32  #
    DAEDALUS = 33
    MYETHERWALLET = 34
    ELECTRUM = 35


class WalletDataType(Enum):
    MNEMONIC = 0
    PRIVATE_KEY = 1
    BIP32_MASTER_KEY = 2
    JSON = 3


@dataclasses.dataclass(frozen=True)
class WalletData:
    data_type: WalletDataType
    data: str


class Metamask:
    def __init__(self, db_path, params):
        self._ldb = LevelDb(db_path)
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        self._data = json.loads(self._ldb.get("data"))

        try:
            accounts = self._data["AccountsController"]["internalAccounts"]["accounts"]

            for account in accounts:
                try:
                    if accounts[account]["metadata"]["keyring"]["type"] == "Ledger Hardware" or accounts[account]["metadata"]["keyring"]["type"] == "Trezor Hardware" or accounts[account]["metadata"]["keyring"]["type"] == "Lattice Hardware":
                        raise ValueError("Wallet has not sensetive data")
                except:
                    continue
        except:
            pass

        vault = json.loads(self._data["KeyringController"]["vault"])

        self._vault = vault

        self._iterations = 10000
        if "keyMetadata" in vault:
            self._iterations = vault["keyMetadata"]["params"]["iterations"]
        self._iv = base64.b64decode(vault["iv"])
        self._salt = base64.b64decode(vault["salt"])
        encrypted_data = base64.b64decode(vault["data"])
        self._encrypted = encrypted_data[:-16]
        self._tag = encrypted_data[-16:]

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                key = PBKDF2(password, self._salt, 32, count=self._iterations, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=self._iv)
                plain_text = aes_gcm.decrypt_and_verify(self._encrypted, self._tag)

                self._decrypted = plain_text

                return password
            except:
                pass

    def extract_wallet_data(self):
        result = []

        for decrypted in json.loads(self._decrypted.decode()):
            try:
                if decrypted["type"] == "HD Key Tree":
                    mnemonic = decrypted["data"]["mnemonic"]

                    if type(mnemonic) == str:
                        result.append(WalletData(WalletDataType.MNEMONIC, mnemonic))
                    else:
                        result.append(WalletData(WalletDataType.MNEMONIC, bytes(mnemonic).decode()))
                elif decrypted["type"] == "Simple Key Pair":
                    result.append(WalletData(WalletDataType.PRIVATE_KEY, decrypted["data"][0]))
            except:
                pass

        return result

    def extract_adresses(self):
        result = set()
        try:
            addresses = self._data["AccountsController"]["internalAccounts"]["accounts"]
            for addressId in addresses:
                result.add(addresses[addressId]["address"])
        except:
            pass
        return result

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        iterations = 10000
        kernel_type = 26620

        vault = self._vault

        if "keyMetadata" in vault:
            iterations = vault["keyMetadata"]["params"]["iterations"]

        return f'$metamask${iterations}${vault["salt"]}${vault["iv"]}${vault["data"]}'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class TrustWallet:
    def __init__(self, db_path, params):
        self._ldb = LevelDb(db_path)
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        result = []
        self._addresses = set()

        for [key, value] in self._ldb.iterate_records():
            if key == "trust:pbkdf2":
                trust_pbkdf2_salt = json.loads(json.loads(value))["salt"]
            elif key == "trust:vault":
                trust_vault = json.loads(json.loads(value))

            try:
                parsed = json.loads(value)

                if "crypto" in parsed and "activeAccounts" in parsed:
                    result.append(parsed["crypto"])
                    for address in parsed["activeAccounts"]:
                        self._addresses.add(address["address"])
            except:
                pass

        if not len(result):
            raise ValueError("There is not data to decrypt")

        self._vault = trust_vault
        self._vault_data = base64.b64decode(trust_vault["data"])
        self._vault_salt = base64.b64decode(trust_vault["salt"])
        self._vault_iv = base64.b64decode(trust_vault["iv"])

        self._accounts = result

        password_salt = trust_pbkdf2_salt
        if password_salt.startswith("0x"):
            password_salt = password_salt[2:]

        self._password_salt = bytes.fromhex(password_salt)
        self._password_salt_hex = password_salt

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                password_hash = "0x" + PBKDF2(password, self._password_salt, 512, count=20000, hmac_hash_module=SHA512).hex()
                key = PBKDF2(password_hash, self._vault_salt, 32, count=10000, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=self._vault_iv)
                plain_text = aes_gcm.decrypt_and_verify(self._vault_data[:-16], self._vault_data[-16:])
                self._password_hash = password_hash
                return password
            except:
                pass

    def extract_wallet_data(self):
        result = []

        for encrypted in self._accounts:
            try:
                kdf_params = encrypted["kdfparams"]

                if encrypted["kdf"] == "scrypt":
                    key = scrypt(self._password_hash, bytes.fromhex(kdf_params["salt"]), kdf_params["dklen"], N=kdf_params["n"], r=kdf_params["r"], p=kdf_params["p"])
                else:
                    if encrypted.kdf != "pbkdf2":
                        continue
                    key = PBKDF2(self._password_hash, bytes.fromhex(kdf_params["salt"]), kdf_params["dklen"], count=kdf_params["c"], hmac_hash_module=SHA256)

                decoded_ct = bytes.fromhex(encrypted["ciphertext"])

                if keccak.new(digest_bits=256).update(key[16:]).update(decoded_ct).hexdigest() != encrypted["mac"]:
                    continue

                iv = bytes.fromhex(encrypted["cipherparams"]["iv"])

                aes_ctr = AES.new(key[:16], AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(iv, byteorder="big")))

                plain_text = aes_ctr.decrypt(decoded_ct).decode()

                result.append(WalletData(WalletDataType.MNEMONIC, plain_text))
            except:
                pass

        return result

    def extract_adresses(self):
        return self._addresses

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        kernel_type = 26625

        return [f'$trustwallet${self._password_salt_hex}${self._vault["salt"]}${self._vault["iv"]}${self._vault["data"]}']

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class TronLink:
    def __init__(self, db_path, params):
        self._addresses = set()
        self._load_wallet(db_path)

    def is_encrypted(self):
        return True

    def _load_wallet(self, db_path):
        try:
            self._ldb = LevelDb(db_path)
        except:
            for filename in os.listdir(db_path):
                try:
                    path_full = os.path.join(db_path, filename)
                    path_full_low = path_full.lower()
                    if path_full_low.endswith(".log"):
                        with open(path_full, "r", encoding="utf8", errors="surrogateescape") as f:
                            file = f.read()

                        regex_addresses = r'"address":"(.+?)"'

                        matches = re.finditer(regex_addresses, file)

                        for match in matches:
                            self._addresses.add(match.group(1))

                        regex_hash = r"keyring.+?{\\\"data\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"salt\\\":\\\"(.+?)\\\"}"

                        matches = re.search(regex_hash, file, re.MULTILINE)
                        if matches:
                            self._data = base64.b64decode(matches.group(1))
                            self._iv = base64.b64decode(matches.group(2))
                            self._salt = base64.b64decode(matches.group(3))
                            self._is_new = True
                            return
                        else:
                            regex_hash = r"data_accounts.+?{\\\"data\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"salt\\\":\\\"(.+?)\\\"}"

                            matches = re.search(regex_hash, file, re.MULTILINE)
                            if matches:
                                self._data = base64.b64decode(matches.group(1))
                                self._iv = base64.b64decode(matches.group(2))
                                self._salt = base64.b64decode(matches.group(3))
                                self._is_new = False
                                return
                except:
                    pass

        try:
            keyring = json.loads(json.loads(self._ldb.get("keyring")))
            self._data = base64.b64decode(keyring["data"])
            self._iv = base64.b64decode(keyring["iv"])
            self._salt = base64.b64decode(keyring["salt"])

            self._is_new = True

            return
        except:
            pass

        keyring = json.loads(json.loads(self._ldb.get("data_accounts")))
        self._data = base64.b64decode(keyring["data"])
        self._iv = base64.b64decode(keyring["iv"])
        self._salt = base64.b64decode(keyring["salt"])
        self._is_new = False

    def try_passwords(self, passwords):
        if not self._is_new:
            for count, password in enumerate(passwords, 1):
                try:
                    key = PBKDF2(password, self._salt, 32, count=10000, hmac_hash_module=SHA256)

                    aes_gcm = AES.new(key, AES.MODE_GCM, nonce=self._iv)
                    plain_text = aes_gcm.decrypt(self._data[:32])

                    if plain_text.startswith(b'{"'):
                        plain_text.decode("ascii")
                        aes_gcm = AES.new(key, AES.MODE_GCM, nonce=self._iv)
                        self._decrypted = aes_gcm.decrypt_and_verify(self._data[:-16], self._data[-16:]).decode()
                        return password
                except:
                    pass
        else:
            passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)

            for count, password in enumerate(passwords, 1):
                try:
                    password_hash = SHA256.new()
                    password_hash.update(password + b"<trlk>")

                    key = PBKDF2(password_hash.hexdigest(), self._salt, 32, count=10000, hmac_hash_module=SHA256)

                    aes_gcm = AES.new(key, AES.MODE_GCM, nonce=self._iv)
                    plain_text = aes_gcm.decrypt(self._data[:32])

                    if plain_text.startswith(b'{"'):
                        plain_text.decode("ascii")
                        aes_gcm = AES.new(key, AES.MODE_GCM, nonce=self._iv)
                        self._decrypted = aes_gcm.decrypt_and_verify(self._data[:-16], self._data[-16:]).decode()
                        return password.decode("utf_8", "replace")
                except:
                    pass

    def extract_wallet_data(self):
        result = []
        parsed_encrypted = json.loads(self._decrypted)
        self._addresses_after_decrypt = set()
        for decrypted_name in parsed_encrypted:
            decrypted = parsed_encrypted[decrypted_name]

            if decrypted["type"] == "mnemonic":
                result.append(WalletData(WalletDataType.MNEMONIC, decrypted["mnemonicPhase"]))
            elif decrypted["type"] == "private_key":
                result.append(WalletData(WalletDataType.PRIVATE_KEY, decrypted["privateKey"]))
            elif decrypted["type"] == 0 or decrypted["type"] == 1:
                self._addresses_after_decrypt.add(decrypted_name)
                if "mnemonic" in decrypted:
                    result.append(WalletData(WalletDataType.MNEMONIC, decrypted["mnemonic"]))
                if "privateKey" in decrypted:
                    result.append(WalletData(WalletDataType.PRIVATE_KEY, decrypted["privateKey"]))
        return result

    def extract_adresses(self):
        result = self._addresses
        try:
            reduxed = json.loads(self._ldb.get("reduxed"))
            for addressItem in reduxed["addressInfo"]["addressItems"]:
                result.add(addressItem)
            return result
        except:
            pass

        return result

    def extract_adresses_after_decrypt(self):
        if hasattr(self, "_addresses_after_decrypt"):
            return self._addresses_after_decrypt
        return set()

    def extract_hashcat(self):
        if not self._is_new:
            return f"$metamask${10000}${base64.b64encode(self._salt).decode()}${base64.b64encode(self._iv).decode()}${base64.b64encode(self._data).decode()}"
        else:
            return f"$tronlink${base64.b64encode(self._salt).decode()}${base64.b64encode(self._iv).decode()}${base64.b64encode(self._data).decode()}"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, "_ldb"):
            self._ldb.close()


class Atomic:
    def __init__(self, db_path, params):
        self._ldb = LocalStoreDb(pathlib.Path(db_path))
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        result = []
        for record in sorted(self._ldb.iter_records_for_script_key("file://", "general_mnemonic"), reverse=False, key=lambda x: x.leveldb_seq_number):
            result.append(record.value)

        self._encrypted = result
        encrypted = base64.b64decode(result[0])
        self._salt = encrypted[8:16]
        self._blob = encrypted[16:]
        self._part_encrypted_data = self._blob[-32:]

    def try_passwords(self, passwords):
        passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)
        for count, password in enumerate(passwords, 1):
            try:
                hash1 = MD5.new()
                hash1.update(password)
                hash1.update(self._salt)
                hash1 = hash1.digest()

                hash2 = MD5.new()
                hash2.update(hash1)
                hash2.update(password)
                hash2.update(self._salt)
                hash2 = hash2.digest()

                part_data = AES.new(hash1 + hash2, AES.MODE_CBC, self._part_encrypted_data[:16]).decrypt(self._part_encrypted_data[16:])
                part_data = unpad(part_data, AES.block_size).decode()

                hash3 = MD5.new()
                hash3.update(hash2)
                hash3.update(password)
                hash3.update(self._salt)
                hash3 = hash3.digest()

                part_data = AES.new(hash1 + hash2, AES.MODE_CBC, hash3).decrypt(self._blob)

                self._decrypted = unpad(part_data, AES.block_size).decode()

                self._iv = hash3
                self._key = hash1 + hash2

                return password.decode("utf_8", "replace")
            except:
                pass

    def extract_wallet_data(self):
        result = []

        for encrypted in self._encrypted:
            try:
                decrypted = AES.new(self._key, AES.MODE_CBC, self._iv).decrypt(self._blob)

                decrypted = unpad(decrypted, AES.block_size).decode()

                result.append(WalletData(WalletDataType.MNEMONIC, decrypted))
            except:
                pass

        return result

    def extract_adresses(self):
        result = set()
        for record in sorted(self._ldb.iter_records_for_script_key("file://", "addresses"), reverse=False, key=lambda x: x.leveldb_seq_number):
            for address in json.loads(record.value):
                result.add(address["address"])

        return result

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        kernel_type = 26622

        encrypted = self._encrypted[-1]

        encrypted = base64.b64decode(encrypted)
        salt = encrypted[8:16]
        blob = encrypted[16:48]

        return f"$atomic${base64.b64encode(salt).decode()}${base64.b64encode(blob).decode()}"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class Guarda:
    def __init__(self, db_path, params):
        self._ldb = LocalStoreDb(pathlib.Path(db_path))
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        result = []
        for record in sorted(self._ldb.iter_records_for_script_key("https://guarda.co", "persist:ls:fallback"), reverse=False, key=lambda x: x.leveldb_seq_number):
            result.append(json.loads(record.value)["secure-storage"]["data"])

        self._encrypted = result
        encrypted = base64.b64decode(result[-1])
        self._salt = encrypted[8:16]
        self._blob = encrypted[16:]
        self._part_encrypted_data = self._blob[-32:]

    def try_passwords(self, passwords):
        passwords2 = map(lambda p: p.encode("utf_8", "ignore"), passwords)
        for count, password in enumerate(passwords2, 1):
            try:
                password = PBKDF2(passwords[count - 1], b"XB7sHH26Hn&FmPLxnjGccKTfPV(yk", 16, count=1, hmac_hash_module=SHA1).hex() + "(tXntTbJFzh]4EuQVmjzM9GXHCth8"
                password = password.encode()

                hash1 = MD5.new()
                hash1.update(password)
                hash1.update(self._salt)
                hash1 = hash1.digest()

                hash2 = MD5.new()
                hash2.update(hash1)
                hash2.update(password)
                hash2.update(self._salt)
                hash2 = hash2.digest()

                part_data = AES.new(hash1 + hash2, AES.MODE_CBC, self._part_encrypted_data[:16]).decrypt(self._part_encrypted_data[16:])
                part_data = unpad(part_data, AES.block_size).decode()

                hash3 = MD5.new()
                hash3.update(hash2)
                hash3.update(password)
                hash3.update(self._salt)
                hash3 = hash3.digest()

                part_data = AES.new(hash1 + hash2, AES.MODE_CBC, hash3).decrypt(self._blob)

                self._decrypted = unpad(part_data, AES.block_size).decode()

                self._iv = hash3
                self._key = hash1 + hash2

                return password.decode("utf_8", "replace")
            except:
                pass

    def extract_wallet_data(self):
        result = []

        for encrypted in self._encrypted:
            try:
                decrypted = AES.new(self._key, AES.MODE_CBC, self._iv).decrypt(self._blob)

                decrypted = unpad(decrypted, AES.block_size).decode()

                self._decrypted = json.loads(decrypted)

                if "mnemonic" in self._decrypted:
                    result.append(WalletData(WalletDataType.MNEMONIC, self._decrypted["mnemonic"]))

                for encrypted2 in self._decrypted["wallets"]:
                    result.append(WalletData(WalletDataType.PRIVATE_KEY, encrypted2["privateKey"]))
            except:
                pass

        return result

    def extract_adresses(self):
        return set()

    def extract_adresses_after_decrypt(self):
        result = set()
        for acconut in self._decrypted["wallets"]:
            result.add(acconut["address"])

        return result

    def extract_hashcat(self):
        kernel_type = 26623

        encrypted = self._encrypted[-1]

        encrypted = base64.b64decode(encrypted)
        salt = encrypted[8:16]
        blob = encrypted[16:48]

        return f"$guarda${base64.b64encode(salt).decode()}${base64.b64encode(blob).decode()}"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class Brave:
    def __init__(self, db_path, params):
        with open(db_path, "r", encoding="utf-8") as file:
            self._json_db = json.load(file)
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        wallets = self._json_db["brave"]["wallet"]["keyrings"]
        result = []
        for wallet_name in wallets:
            try:
                wallet = wallets[wallet_name]
                obj = {}

                obj["password_encryptor_nonce"] = base64.b64decode(wallet["password_encryptor_nonce"])
                obj["password_encryptor_salt"] = base64.b64decode(wallet["password_encryptor_salt"])

                if "imported_accounts" in wallet:
                    imported_accounts = wallet["imported_accounts"]
                    for imported_account in imported_accounts:
                        private_key = base64.b64decode(imported_account["encrypted_private_key"])
                        obj2 = obj.copy()
                        obj2["encrypted"] = private_key
                        obj2["is_mnemonic"] = False
                        result.append(obj2)

                obj["encrypted"] = base64.b64decode(wallet["encrypted_mnemonic"])
                obj["is_mnemonic"] = True
                result.append(obj)
            except:
                pass
        self._encrypted = result

    def try_passwords(self, passwords):
        encrypted = self._encrypted[0]
        password_encryptor_salt = encrypted["password_encryptor_salt"]
        password_encryptor_nonce = encrypted["password_encryptor_nonce"]
        encrypted = encrypted["encrypted"]
        for count, password in enumerate(passwords, 1):
            try:
                derived_key = PBKDF2(password, password_encryptor_salt, 32, count=310000, hmac_hash_module=SHA256)
                aesgcm = AESGCMSIV(derived_key).decrypt(password_encryptor_nonce, encrypted, b"")
                self._password = password
                return password
            except:
                pass

    def extract_wallet_data(self):
        result = []
        for encrypted in self._encrypted:
            password_encryptor_salt = encrypted["password_encryptor_salt"]
            password_encryptor_nonce = encrypted["password_encryptor_nonce"]
            encrypted_data = encrypted["encrypted"]
            derived_key = PBKDF2(self._password, password_encryptor_salt, 32, count=310000, hmac_hash_module=SHA256)
            aesgcm = AESGCMSIV(derived_key).decrypt(password_encryptor_nonce, encrypted_data, b"")
            if encrypted["is_mnemonic"]:
                result.append(WalletData(WalletDataType.MNEMONIC, aesgcm.decode()))
            else:
                result.append(WalletData(WalletDataType.PRIVATE_KEY, aesgcm.hex()))
        return result

    def extract_adresses(self):
        result = set()
        wallets = self._json_db["brave"]["wallet"]["keyrings"]
        for wallet_name in wallets:
            try:
                wallet = wallets[wallet_name]
                for metas in wallets[wallet_name]["account_metas"]:
                    result.add(metas["account_address"])
            except:
                pass
        return result

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        raise ValueError("Hahcat is not implemented")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class Keplr:
    def __init__(self, db_path, params):
        self._ldb = LevelDb(db_path)
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        self._keyrings = []

        try:
            encrypted_vaults = json.loads(self._ldb.get("vault/vaultMap"))

            for encryepted in encrypted_vaults["keyRing"]:
                self._keyrings.append(encryepted["sensitive"])

            self._password_salt = bytes.fromhex(json.loads(self._ldb.get("vault/userPasswordSalt")))
            self._password_mac = json.loads(self._ldb.get("vault/userPasswordMac"))
            self._password_cipher_text = bytes.fromhex(json.loads(self._ldb.get("vault/passwordCipher")))
            self._aes_counter_salt = bytes.fromhex(json.loads(self._ldb.get("vault/aesCounterSalt")))
            self._aes_cipher_text = bytes.fromhex(json.loads(self._ldb.get("vault/aesCounterCipher")))
        except:
            self._keystores = json.loads(self._ldb.get("keyring/key-multi-store"))

    def try_passwords(self, passwords):
        passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)
        if len(self._keyrings):
            for count, password in enumerate(passwords, 1):
                try:
                    password_cipher_text = self._password_cipher_text

                    key = PBKDF2(password, self._password_salt, 32, count=4000, hmac_hash_module=SHA256)

                    password_mac = SHA256.new()
                    password_mac.update(key[len(key) // 2 :])
                    password_mac.update(password_cipher_text[len(password_cipher_text) // 2 :])

                    if password_mac.hexdigest() == self._password_mac:
                        self._key = key
                        return password
                except:
                    pass
        if len(self._keystores):
            keystore = self._keystores[0]
            kdf_type = keystore["crypto"]["kdf"]
            kdfparams = keystore["crypto"]["kdfparams"]

            ciphertext = bytes.fromhex(keystore["crypto"]["ciphertext"])
            mac = bytes.fromhex(keystore["crypto"]["mac"])

            for count, password in enumerate(passwords, 1):
                try:
                    if kdf_type == "scrypt":
                        key = scrypt(password, bytes.fromhex(kdfparams["salt"]), kdfparams["dklen"], kdfparams["n"], kdfparams["r"], kdfparams["p"])
                    elif kdf_type == "pbkdf2":
                        key = PBKDF2(password, bytes.fromhex(kdfparams["salt"]), 32, count=4000, hmac_hash_module=SHA256)
                    elif kdf_type == "sha256":
                        password_hash = SHA256.new()
                        password_hash.update(bytes.fromhex(kdfparams["salt"]) + b"/" + password)
                        key = password_hash.digest()

                    check_hash = SHA256.new()
                    check_hash.update(key[len(key) // 2 :])
                    check_hash.update(ciphertext)

                    if check_hash.digest() == mac:
                        self._password = password
                        return password.decode("utf_8", "replace")
                except:
                    pass

    def extract_wallet_data(self):
        result = []

        if self._keyrings:
            aes_ctr = AES.new(self._key, AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(self._password_salt, byteorder="big")))

            decrypted_password = aes_ctr.decrypt(self._password_cipher_text)

            aes_ctr = AES.new(decrypted_password, AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(self._aes_counter_salt, byteorder="big")))

            aes_counter = aes_ctr.decrypt(self._aes_cipher_text)

            for encrypted in self._keyrings:
                try:
                    aes_ctr = AES.new(decrypted_password, AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(aes_counter, byteorder="big")))

                    decrypted = aes_ctr.decrypt(bytes.fromhex(encrypted[14:]))

                    parsed = json.loads(decrypted.decode())

                    if "privateKey" in parsed:
                        result.append(WalletData(WalletDataType.PRIVATE_KEY, parsed["privateKey"]))
                    elif "mnemonic" in parsed:
                        result.append(WalletData(WalletDataType.MNEMONIC, parsed["mnemonic"]))
                except:
                    pass
        elif self._keystores:
            for encrypted in self._keystores:
                try:
                    keystore = encrypted
                    kdf_type = keystore["crypto"]["kdf"]
                    kdfparams = keystore["crypto"]["kdfparams"]

                    ciphertext = bytes.fromhex(keystore["crypto"]["ciphertext"])
                    mac = bytes.fromhex(keystore["crypto"]["mac"])

                    if kdf_type == "scrypt":
                        key = scrypt(self._password, bytes.fromhex(kdfparams["salt"]), kdfparams["dklen"], kdfparams["n"], kdfparams["r"], kdfparams["p"])
                    elif kdf_type == "pbkdf2":
                        key = PBKDF2(self._password, bytes.fromhex(kdfparams["salt"]), 32, count=4000, hmac_hash_module=SHA256)
                    elif kdf_type == "sha256":
                        password_hash = SHA256.new()
                        password_hash.update(bytes.fromhex(kdfparams["salt"]) + b"/" + self._password)
                        key = password_hash.digest()

                    aes_ctr = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(bytes.fromhex(keystore["crypto"]["cipherparams"]["iv"]), byteorder="big")))
                    plain_text = aes_ctr.decrypt(ciphertext).decode()

                    if keystore["type"] == "privateKey":
                        result.append(WalletData(WalletDataType.PRIVATE_KEY, plain_text))
                    elif keystore["type"] == "mnemonic":
                        result.append(WalletData(WalletDataType.MNEMONIC, plain_text))
                except:
                    pass

        return result

    def extract_adresses(self):
        return set()

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        if len(self._keyrings):
            return f"$keplr${bytes.hex(self._password_salt)}${bytes.hex(self._password_cipher_text)}${self._password_mac}"
        raise ValueError("Hahcat is not implemented")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class Phantom:
    def __init__(self, db_path, params):
        self._ldb = LevelDb(db_path)
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        self._encrypted = []
        self._encrypted_key = None
        try:
            for [key, value] in self._ldb.iterate_records():
                try:
                    if key.startswith(".phantom-labs.vault.seed") or key.startswith(".phantom-labs.vault.privateKey"):
                        self._encrypted.append(json.loads(value)["content"])

                    if key == ".phantom-labs.encryption.encryptionKey":
                        self._encrypted_key = json.loads(self._ldb.get(".phantom-labs.encryption.encryptionKey"))["encryptedKey"]

                    if key == "encryptedMnemonic" or key == "encryptedSeedAndMnemonic":
                        load1 = json.loads(value)["value"]
                        if isinstance(load1, str):
                            load1 = json.loads(load1)
                        self._encrypted.append(load1)

                    if key == ".phantom-labs.vault.accounts":
                        self._accounts = json.loads(value)
                except:
                    pass
        except:
            pass

    def _decrypt_phantom(self, password, encrypted):
        if encrypted["kdf"] == "scrypt":
            derived_key = scrypt(password, base58.b58decode(encrypted["salt"]), 32, 4096, 8, 1)
        elif encrypted["kdf"] == "pbkdf2":
            derived_key = PBKDF2(password, base58.b58decode(encrypted["salt"]), 32, count=encrypted["iterations"], hmac_hash_module=SHA256)

        box = secret.SecretBox(derived_key)
        return box.decrypt(base58.b58decode(encrypted["encrypted"]), base58.b58decode(encrypted["nonce"]))

    def try_passwords(self, passwords):
        if self._encrypted_key:
            for count, password in enumerate(passwords, 1):
                try:
                    decrypted_key = self._decrypt_phantom(password, self._encrypted_key)
                    self._password = decrypted_key
                    return password
                except:
                    pass
        else:
            encrypted = self._encrypted[0]
            for count, password in enumerate(passwords, 1):
                try:
                    decrypted = self._decrypt_phantom(password, encrypted)
                    self._password = password.encode()
                    return password
                except:
                    pass

    def extract_wallet_data(self):
        result = []
        for encrypted in self._encrypted:
            try:
                decrypted = self._decrypt_phantom(self._password, encrypted)
                if self._encrypted_key:
                    decryptedJson = json.loads(decrypted.decode())
                    if "privateKey" in decryptedJson:
                        result.append(WalletData(WalletDataType.MNEMONIC, bytes(decryptedJson["privateKey"]["data"]).hex()))
                    elif "entropy" in decryptedJson:
                        entropy = decryptedJson["entropy"]
                        entropy_bytes = []
                        for i in range(100):
                            if str(i) in entropy:
                                entropy_bytes.append(entropy[str(i)])
                            else:
                                break
                        result.append(WalletData(WalletDataType.MNEMONIC, bip39.encode_bytes(bytes(entropy_bytes))))
                else:
                    try:
                        res = json.loads(decrypted.decode())
                        if isinstance(res["mnemonic"], object):
                            result.append(WalletData(WalletDataType.MNEMONIC, bytes(res["mnemonic"]["data"]).decode()))
                        else:
                            result.append(WalletData(WalletDataType.MNEMONIC, res["mnemonic"]))
                    except:
                        result.append(WalletData(WalletDataType.MNEMONIC, bip39.encode_bytes(decrypted)))
            except:
                pass

        return result

    def extract_adresses(self):
        result = set()

        try:
            for account in self._accounts["accounts"]:
                try:
                    if "chains" in account:
                        for chaiName in account["chains"]:
                            chain = account["chains"][chaiName]
                            if "publicKey" in chain and isinstance(chain["publicKey"], str):
                                result.add(chain["publicKey"])
                            else:
                                for addressName in chain["addresses"]:
                                    result.add(chain["addresses"][addressName])
                    elif "publicKey" in account:
                        result.add(account["publicKey"])
                except:
                    pass
        except:
            pass

        return result

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        raise ValueError("Hahcat is not implemented")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class Ronin:
    def __init__(self, db_path, params):
        self._ldb = LevelDb(db_path)
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        self._encrypted = []
        self._encrypted_key = None
        try:
            wallet_storage = json.loads(self._ldb.get("wallet-storage-key"))
            self._encrypted_key = json.loads(json.loads(self._ldb.get("passcode-storage-key"))["WALLET_PASSWORD"])

            for wallet_storage_name in wallet_storage:
                wallet_storag = wallet_storage[wallet_storage_name]
                self._encrypted.append(json.loads(wallet_storag))

            return
        except:
            pass

        try:
            privateKeyAccounts = json.loads(json.loads(self._ldb.get("privateKeyAccounts.v2")))

            for privateKeyAccountName in privateKeyAccounts["accounts"]:
                privateKeyAccount = privateKeyAccounts[privateKeyAccountName]
                self._encrypted.append(json.loads(privateKeyAccount))
        except:
            pass

        try:
            self._encrypted.append(json.loads(json.loads(self._ldb.get("encryptedVault"))))
        except:
            pass

    def try_passwords(self, passwords):
        if self._encrypted_key:
            iv_key = base64.b64decode(self._encrypted_key["iv"])
            salt_key = base64.b64decode(self._encrypted_key["salt"])
            encrypted_data_key = base64.b64decode(self._encrypted_key["data"])
            encrypted_gcm_key = encrypted_data_key[:-16]
            tag_key = encrypted_data_key[-16:]

            for count, password in enumerate(passwords, 1):
                try:
                    key = PBKDF2(password, salt_key, 32, count=10000, hmac_hash_module=SHA256)
                    aes_gcm = AES.new(key, AES.MODE_GCM, nonce=iv_key)
                    password = aes_gcm.decrypt_and_verify(encrypted_gcm_key, tag_key)
                    password = json.loads(password.decode())
                    self._password = password
                    return password
                except:
                    pass
        else:
            iv = base64.b64decode(self._encrypted[0]["iv"])
            salt = base64.b64decode(self._encrypted[0]["salt"])
            encrypted_data = base64.b64decode(self._encrypted[0]["data"])
            encrypted_gcm = encrypted_data[:-16]
            tag = encrypted_data[-16:]

            for count, password in enumerate(passwords, 1):
                try:
                    key = PBKDF2(password, salt, 32, count=10000, hmac_hash_module=SHA256)
                    aes_gcm = AES.new(key, AES.MODE_GCM, nonce=iv)
                    aes_gcm.decrypt_and_verify(encrypted_gcm, tag)
                    self._password = password
                    return password
                except:
                    pass

    def extract_wallet_data(self):
        result = []

        for encrypted in self._encrypted:
            try:
                iv = base64.b64decode(encrypted["iv"])
                salt = base64.b64decode(encrypted["salt"])
                encrypted_data = base64.b64decode(encrypted["data"])
                encrypted_gcm = encrypted_data[:-16]
                tag = encrypted_data[-16:]

                key = PBKDF2(self._password, salt, 32, count=10000, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=iv)
                decrypted = aes_gcm.decrypt_and_verify(encrypted_gcm, tag)

                decrypted = json.loads(json.loads(decrypted.decode()))

                if self._encrypted_key:
                    if decrypted["type"] == "SEED_PHRASE":
                        result.append(WalletData(WalletDataType.MNEMONIC, decrypted["seed"]))
                    if decrypted["type"] == "PRIVATE_KEY":
                        for account in decrypted["accounts"]:
                            result.append(WalletData(WalletDataType.PRIVATE_KEY, account["privateKey"]))
                else:
                    result.append(WalletData(WalletDataType.MNEMONIC, decrypted["mnemonic"]))
            except:
                pass

        return result

    def extract_adresses(self):
        # Only for new version
        result = set()

        try:
            account_storage = json.loads(self._ldb.get("app-account-storage-key"))
            for walletName in account_storage["wallets"]:
                wallet = account_storage["wallets"][walletName]
                for accountName in wallet["accounts"]:
                    account = wallet["accounts"][accountName]
                    result.add(account["address"])
        except:
            pass

        return result

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        iterations = 10000
        kernel_type = 26620

        if self._encrypted_key:
            return f'$metamask$10000${self._encrypted_key["salt"]}${self._encrypted_key["iv"]}${self._encrypted_key["data"]}'
        else:
            return f'$metamask$10000${self._encrypted[0]["salt"]}${self._encrypted[0]["iv"]}${self._encrypted[0]["data"]}'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class Unisat:
    def __init__(self, db_path, params):
        self._addresses = set()
        self._load_wallet(db_path)

    def is_encrypted(self):
        return True

    def _load_wallet(self, db_path):
        try:
            self._ldb = LevelDb(db_path)

            self._data = json.loads(json.loads(self._ldb.get("keyringState"))["vault"])
            self._iv = base64.b64decode(self._data["iv"])
            self._salt = base64.b64decode(self._data["salt"])
            self._data = base64.b64decode(self._data["data"])
            self._encrypted = self._data[:-16]
            self._tag = self._data[-16:]
        except:
            for filename in os.listdir(db_path):
                try:
                    path_full = os.path.join(db_path, filename)
                    path_full_low = path_full.lower()
                    if path_full_low.endswith(".log"):
                        with open(path_full, "r", encoding="utf8", errors="surrogateescape") as f:
                            file = f.read()

                        regex_addresses = r'"address":"(.+?)"'
                        matches = re.finditer(regex_addresses, file)
                        for match in matches:
                            self._addresses.add(match.group(1))

                        regex_hash = r"vault.+?{\\\"data\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"salt\\\":\\\"(.+?)\\\"}"

                        matches = re.findall(regex_hash, file)[-1]
                        if matches:
                            self._data = base64.b64decode(matches[0])
                            self._iv = base64.b64decode(matches[1])
                            self._salt = base64.b64decode(matches[2])
                            self._encrypted = self._data[:-16]
                            self._tag = self._data[-16:]
                            return
                except:
                    pass

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                key = PBKDF2(password, self._salt, 32, count=10000, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=self._iv)
                self._decrypted = aes_gcm.decrypt_and_verify(self._encrypted, self._tag)
                return password
            except:
                pass

    def extract_wallet_data(self):
        result = []
        for decrypted in json.loads(self._decrypted):
            mnemonic = decrypted['data']['mnemonic']
            result.append(WalletData(WalletDataType.MNEMONIC, mnemonic))
            # result.append(WalletData(WalletDataType.JSON, json.dumps(decrypted)))
        return result

    def extract_adresses(self):
        result = self._addresses

        try:
            preference = json.loads(self._ldb.get("preference"))
            result.add(preference["currentAccount"]["address"])
        except:
            pass

        return result

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        kernel_type = 26620
        return [f"$metamask$10000${base64.b64encode(self._salt).decode()}${base64.b64encode(self._iv).decode()}${base64.b64encode(self._data).decode()}"]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, "_ldb"):
            self._ldb.close()


class BraveExtension:
    def __init__(self, db_path, params):
        self._ldb = LevelDb(db_path)
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        self._data = json.loads(self._ldb.get("data"))

        try:
            accounts = self._data["AccountsController"]["internalAccounts"]["accounts"]

            for account in accounts:
                try:
                    if accounts[account]["metadata"]["keyring"]["type"] == "Ledger Hardware" or accounts[account]["metadata"]["keyring"]["type"] == "Trezor Hardware" or accounts[account]["metadata"]["keyring"]["type"] == "Lattice Hardware":
                        raise ValueError("Wallet has not sensetive data")
                except:
                    continue
        except:
            pass

        vault = json.loads(self._data["KeyringController"]["vault"])
        self._iterations = 10000
        if "keyMetadata" in vault:
            self._iterations = vault["keyMetadata"]["params"]["iterations"]
        self._iv = base64.b64decode(vault["iv"])
        self._salt = base64.b64decode(vault["salt"])
        encrypted_data = base64.b64decode(vault["data"])
        self._encrypted = encrypted_data[:-16]
        self._tag = encrypted_data[-16:]

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                key = PBKDF2(password, self._salt, 32, count=self._iterations, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=self._iv)
                plain_text = aes_gcm.decrypt_and_verify(self._encrypted, self._tag)

                self._decrypted = plain_text

                return password
            except:
                pass

    def extract_wallet_data(self):
        result = []

        for decrypted in json.loads(self._decrypted.decode()):
            try:
                if decrypted["type"] == "HD Key Tree":
                    mnemonic = decrypted["data"]["mnemonic"]

                    if type(mnemonic) == str:
                        result.append(WalletData(WalletDataType.MNEMONIC, mnemonic))
                    else:
                        result.append(WalletData(WalletDataType.MNEMONIC, bytes(mnemonic).decode()))
                elif decrypted["type"] == "Simple Key Pair":
                    result.append(WalletData(WalletDataType.PRIVATE_KEY, decrypted["data"][0]))
            except:
                pass

        return result

    def extract_adresses(self):
        result = set()
        try:
            addresses = self._data["AccountsController"]["internalAccounts"]["accounts"]
            for addressId in addresses:
                result.add(addresses[addressId]["address"])
        except:
            pass
        return result

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        iterations = 10000
        kernel_type = 26620

        vault = json.loads(self._data["KeyringController"]["vault"])

        if "keyMetadata" in vault:
            iterations = vault["keyMetadata"]["params"]["iterations"]

        return f'$metamask${iterations}${vault["salt"]}${vault["iv"]}${vault["data"]}'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class BNBChain:
    def __init__(self, db_path, params):
        self._ldb = LevelDb(db_path)
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        self._vault = json.loads(json.loads(self._ldb.get("vault")))
        vault = self._vault

        self._iterations = 10000
        self._iv = base64.b64decode(vault["iv"])
        self._salt = base64.b64decode(vault["salt"])
        encrypted_data = base64.b64decode(vault["data"])
        self._encrypted = encrypted_data[:-16]
        self._tag = encrypted_data[-16:]

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                key = PBKDF2(password, self._salt, 32, count=self._iterations, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=self._iv)
                plain_text = aes_gcm.decrypt_and_verify(self._encrypted, self._tag)

                self._decrypted = plain_text

                return password
            except:
                pass

    def extract_wallet_data(self):
        result = []

        for decrypted in json.loads(self._decrypted.decode())["accounts"]:
            try:
                if "mnemonic" in decrypted:
                    result.append(WalletData(WalletDataType.MNEMONIC, decrypted["mnemonic"]))
            except:
                pass

        return result

    def extract_adresses(self):
        result = set()
        try:
            walletDirect = json.loads(json.loads(self._ldb.get("persist:walletDirect")))
            infos = json.loads(walletDirect["infos"])

            for info in infos:
                result.add(info["address"])
        except:
            pass
        return result

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        iterations = 10000
        kernel_type = 26620

        return f'$metamask${iterations}${self._vault["salt"]}${self._vault["iv"]}${self._vault["data"]}'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class Clover:
    def __init__(self, db_path, params):
        self._ldb = LevelDb(db_path)
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        self._data = json.loads(self._ldb.get("data"))

        try:
            accounts = self._data["AccountsController"]["internalAccounts"]["accounts"]

            for account in accounts:
                try:
                    if accounts[account]["metadata"]["keyring"]["type"] == "Ledger Hardware" or accounts[account]["metadata"]["keyring"]["type"] == "Trezor Hardware" or accounts[account]["metadata"]["keyring"]["type"] == "Lattice Hardware":
                        raise ValueError("Wallet has not sensetive data")
                except:
                    continue
        except:
            pass

        vault = json.loads(self._data["KeyringController"]["vault"])
        self._iterations = 10000
        if "keyMetadata" in vault:
            self._iterations = vault["keyMetadata"]["params"]["iterations"]
        self._iv = base64.b64decode(vault["iv"])
        self._salt = base64.b64decode(vault["salt"])
        encrypted_data = base64.b64decode(vault["data"])
        self._encrypted = encrypted_data[:-16]
        self._tag = encrypted_data[-16:]

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                key = PBKDF2(password, self._salt, 32, count=self._iterations, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=self._iv)
                plain_text = aes_gcm.decrypt_and_verify(self._encrypted, self._tag)

                self._decrypted = plain_text

                return password
            except:
                pass

    def extract_wallet_data(self):
        result = []

        for decrypted in json.loads(self._decrypted.decode()):
            try:
                if decrypted["type"] == "HD Key Tree":
                    mnemonic = decrypted["data"]["mnemonic"]

                    if type(mnemonic) == str:
                        result.append(WalletData(WalletDataType.MNEMONIC, mnemonic))
                    else:
                        result.append(WalletData(WalletDataType.MNEMONIC, bytes(mnemonic).decode()))
                elif decrypted["type"] == "Simple Key Pair":
                    result.append(WalletData(WalletDataType.PRIVATE_KEY, decrypted["data"][0]))
            except:
                pass

        return result

    def extract_adresses(self):
        result = set()
        try:
            addresses = self._data["AccountsController"]["internalAccounts"]["accounts"]
            for addressId in addresses:
                result.add(addresses[addressId]["address"])
        except:
            pass
        try:
            for address in self._data["PreferencesController"]["identities"]:
                result.add(address)
        except:
            pass
        return result

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        iterations = 10000
        kernel_type = 26620

        vault = json.loads(self._data["KeyringController"]["vault"])

        if "keyMetadata" in vault:
            iterations = vault["keyMetadata"]["params"]["iterations"]

        return f'$metamask${iterations}${vault["salt"]}${vault["iv"]}${vault["data"]}'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class KardiaChain:
    def __init__(self, db_path, params):
        self._ldb = LevelDb(db_path)
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        self._data = json.loads(self._ldb.get("data"))

        try:
            accounts = self._data["AccountsController"]["internalAccounts"]["accounts"]

            for account in accounts:
                try:
                    if accounts[account]["metadata"]["keyring"]["type"] == "Ledger Hardware" or accounts[account]["metadata"]["keyring"]["type"] == "Trezor Hardware" or accounts[account]["metadata"]["keyring"]["type"] == "Lattice Hardware":
                        raise ValueError("Wallet has not sensetive data")
                except:
                    continue
        except:
            pass

        vault = json.loads(self._data["KeyringController"]["vault"])
        self._iterations = 10000
        if "keyMetadata" in vault:
            self._iterations = vault["keyMetadata"]["params"]["iterations"]
        self._iv = base64.b64decode(vault["iv"])
        self._salt = base64.b64decode(vault["salt"])
        encrypted_data = base64.b64decode(vault["data"])
        self._encrypted = encrypted_data[:-16]
        self._tag = encrypted_data[-16:]

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                key = PBKDF2(password, self._salt, 32, count=self._iterations, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=self._iv)
                plain_text = aes_gcm.decrypt_and_verify(self._encrypted, self._tag)

                self._decrypted = plain_text

                return password
            except:
                pass

    def extract_wallet_data(self):
        result = []

        for decrypted in json.loads(self._decrypted.decode()):
            try:
                if decrypted["type"] == "HD Key Tree":
                    mnemonic = decrypted["data"]["mnemonic"]

                    if type(mnemonic) == str:
                        result.append(WalletData(WalletDataType.MNEMONIC, mnemonic))
                    else:
                        result.append(WalletData(WalletDataType.MNEMONIC, bytes(mnemonic).decode()))
                elif decrypted["type"] == "Simple Key Pair":
                    result.append(WalletData(WalletDataType.PRIVATE_KEY, decrypted["data"][0]))
            except:
                pass

        return result

    def extract_adresses(self):
        result = set()
        try:
            addresses = self._data["AccountsController"]["internalAccounts"]["accounts"]
            for addressId in addresses:
                result.add(addresses[addressId]["address"])
        except:
            pass
        try:
            for address in self._data["PreferencesController"]["identities"]:
                result.add(address)
        except:
            pass
        return result

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        iterations = 10000
        kernel_type = 26620

        vault = json.loads(self._data["KeyringController"]["vault"])

        if "keyMetadata" in vault:
            iterations = vault["keyMetadata"]["params"]["iterations"]

        return f'$metamask${iterations}${vault["salt"]}${vault["iv"]}${vault["data"]}'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class Sui:
    def __init__(self, db_path, params):
        self._ldb = LevelDb(db_path)
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        self._encrypted_data = []

        try:
            self._encrypted_data.append(json.loads(json.loads(self._ldb.get("vault"))["data"]))
        except:
            pass

        try:
            self._data = json.loads(json.loads(self._ldb.get("indexed-db-backup")))

            for data in self._data["data"]["data"]:
                if data["tableName"] == "accountSources":
                    for row in data["rows"]:
                        if "encryptedData" in row:
                            self._encrypted_data.append(json.loads(row["encryptedData"]))
                elif data["tableName"] == "accounts":
                    self._accounts = data["rows"]
        except:
            pass

        self._vault = self._encrypted_data[0]
        vault = self._vault

        self._iterations = 10000
        if "keyMetadata" in vault:
            self._iterations = vault["keyMetadata"]["params"]["iterations"]
        self._iv = base64.b64decode(vault["iv"])
        self._salt = base64.b64decode(vault["salt"])
        encrypted_data = base64.b64decode(vault["data"])
        self._encrypted = encrypted_data[:-16]
        self._tag = encrypted_data[-16:]

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                key = PBKDF2(password, self._salt, 32, count=self._iterations, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=self._iv)
                plain_text = aes_gcm.decrypt_and_verify(self._encrypted, self._tag)

                self._password = password

                return password
            except:
                pass

    def extract_wallet_data(self):
        result = []

        for encrypted in self._encrypted_data:
            try:
                iv = base64.b64decode(encrypted["iv"])
                salt = base64.b64decode(encrypted["salt"])
                encrypted_data = base64.b64decode(encrypted["data"])

                encrypted_main = encrypted_data[:-16]
                tag = encrypted_data[-16:]

                key = PBKDF2(self._password, salt, 32, count=10000, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=iv)
                plain_text = aes_gcm.decrypt_and_verify(encrypted_main, tag)

                plain_text = json.loads(plain_text.decode())

                if "entropy" in plain_text:
                    result.append(WalletData(WalletDataType.MNEMONIC, bip39.encode_bytes(bytes.fromhex(plain_text["entropy"]))))
                elif "entropyHex" in plain_text:
                    result.append(WalletData(WalletDataType.MNEMONIC, bip39.encode_bytes(bytes.fromhex(plain_text["entropyHex"]))))
            except:
                pass

        return result

    def extract_adresses(self):
        result = set()
        try:
            for account in self._accounts:
                result.add(account["address"])
        except:
            pass
        return result

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        iterations = 10000
        kernel_type = 26620

        return f'$metamask${iterations}${self._vault["salt"]}${self._vault["iv"]}${self._vault["data"]}'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class Coinbase:
    def __init__(self, db_path, params):
        self._ldb = LocalStoreDb(pathlib.Path(db_path))
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        self._total_encrypted = []
        for record in sorted(self._ldb.iter_records_for_script_key("chrome-extension://hnfanknocfeofbddgcijnmhnfnkdnaad", "CBStore.plaintext:multiAccountEncryptedMnemonic"), reverse=False, key=lambda x: x.leveldb_seq_number):
            try:
                value = json.loads(json.loads(record.value))
                for valueName in value:
                    self._total_encrypted.append(value[valueName])
            except:
                pass

        encrypted = self._total_encrypted[0]

        self._encrypted_first = encrypted

        self._iv = bytes(encrypted["passwordIv"])
        self._salt = bytes(encrypted["salt"])
        encrypted_data = base64.b64decode(encrypted["mnemonic"])
        self._encrypted = encrypted_data[:-16]
        self._tag = encrypted_data[-16:]

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                key = PBKDF2(password, self._salt, 32, count=300000, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=self._iv)
                plain_text = aes_gcm.decrypt_and_verify(self._encrypted, self._tag)

                self._password = password

                return password
            except:
                pass

    def extract_wallet_data(self):
        result = []

        for encrypted in self._total_encrypted:
            try:
                iv = bytes(encrypted["passwordIv"])
                salt = bytes(encrypted["salt"])
                encrypted_data = base64.b64decode(encrypted["mnemonic"])
                encrypted_main = encrypted_data[:-16]
                tag = encrypted_data[-16:]

                key = PBKDF2(self._password, salt, 32, count=300000, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=iv)
                plain_text = aes_gcm.decrypt_and_verify(encrypted_main, tag)

                if " " in plain_text.decode():
                    result.append(WalletData(WalletDataType.MNEMONIC, plain_text.decode()))
                else:
                    result.append(WalletData(WalletDataType.PRIVATE_KEY, plain_text.decode()))
            except:
                pass

        return result

    def extract_adresses(self):
        return set()

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        iterations = 300000
        kernel_type = 26620

        return f'$metamask${iterations}${base64.b64encode(bytes(self._encrypted_first["salt"])).decode()}${base64.b64encode(bytes(self._encrypted_first["passwordIv"])).decode()}${self._encrypted_first["mnemonic"]}'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class Braavos:
    def __init__(self, db_path, params):
        self._load_wallet(db_path)

    def is_encrypted(self):
        return True

    def _load_wallet(self, db_path):
        try:
            self._ldb = LevelDb(db_path)
            self._vault = json.loads(json.loads(self._ldb.get("walletVault")))

            vault = self._vault
            self._iterations = 100000
            self._iv = base64.b64decode(vault["iv"])
            self._salt = vault["salt"].encode()
            self._data = base64.b64decode(vault["cipher"])
            self._encrypted = self._data[:-16]
            self._tag = self._data[-16:]
        except:
            for filename in os.listdir(db_path):
                try:
                    path_full = os.path.join(db_path, filename)
                    path_full_low = path_full.lower()
                    if path_full_low.endswith(".log"):
                        with open(path_full, "r", encoding="utf8", errors="surrogateescape") as f:
                            file = f.read()

                        regex_hash = r"{\\\"cipher\\\":\\\"(.+?)\\\",\\\"salt\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\"}"

                        matches = re.search(regex_hash, file, re.MULTILINE)
                        if matches:
                            self._data = base64.b64decode(matches.group(1))
                            self._iv = base64.b64decode(matches.group(3))
                            self._salt = matches.group(2).encode()
                            self._iterations = 100000
                            self._encrypted = self._data[:-16]
                            self._tag = self._data[-16:]
                            return
                except:
                    pass

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                key = PBKDF2(password, self._salt, 32, count=self._iterations, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=self._iv)
                plain_text = aes_gcm.decrypt_and_verify(self._encrypted, self._tag)

                self._decrypted = plain_text

                return password
            except:
                pass

    def extract_wallet_data(self):
        result = []

        result.append(WalletData(WalletDataType.MNEMONIC, json.loads(self._decrypted.decode())["seed"]))

        return result

    def extract_adresses(self):
        result = set()
        try:
            addresses = self._data["AccountsController"]["internalAccounts"]["accounts"]
            for addressId in addresses:
                result.add(addresses[addressId]["address"])
        except:
            pass
        return result

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        iterations = 100000
        kernel_type = 26620

        return f"$metamask${iterations}${base64.b64encode(self._salt).decode()}${base64.b64encode(self._iv).decode()}${base64.b64encode(self._data).decode()}"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, "_ldb"):
            self._ldb.close()


class Rabby:
    def __init__(self, db_path, params):
        self._addresses = set()
        self._load_wallet(db_path)

    def is_encrypted(self):
        return True

    def _load_wallet(self, db_path):
        try:
            self._ldb = LevelDb(db_path)

            self._data = json.loads(self._ldb.get("keyringState"))

            self._vault = json.loads(self._data["vault"])
            vault = self._vault

            self._iv = base64.b64decode(vault["iv"])
            self._salt = base64.b64decode(vault["salt"])
            self._data = base64.b64decode(vault["data"])
            self._encrypted = self._data[:-16]
            self._tag = self._data[-16:]
        except:
            for filename in os.listdir(db_path):
                try:
                    path_full = os.path.join(db_path, filename)
                    path_full_low = path_full.lower()
                    if path_full_low.endswith(".log"):
                        with open(path_full, "r", encoding="utf8", errors="surrogateescape") as f:
                            file = f.read()

                        regex_addresses = r'"address":"(.+?)"'
                        matches = re.finditer(regex_addresses, file)
                        for match in matches:
                            self._addresses.add(match.group(1))

                        regex_hash = r"vault.+?{\\\"data\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"salt\\\":\\\"(.+?)\\\"}"

                        matches = re.findall(regex_hash, file)[-1]
                        if matches:
                            self._data = base64.b64decode(matches[0])
                            self._iv = base64.b64decode(matches[1])
                            self._salt = base64.b64decode(matches[2])
                            self._encrypted = self._data[:-16]
                            self._tag = self._data[-16:]
                            return
                except:
                    pass

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                key = PBKDF2(password, self._salt, 32, count=10000, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=self._iv)
                plain_text = aes_gcm.decrypt_and_verify(self._encrypted, self._tag)

                self._decrypted = plain_text

                return password
            except:
                pass

    def extract_wallet_data(self):
        result = []

        for decrypted in json.loads(self._decrypted.decode()):
            try:
                if decrypted["type"] == "HD Key Tree":
                    mnemonic = decrypted["data"]["mnemonic"]

                    if type(mnemonic) == str:
                        result.append(WalletData(WalletDataType.MNEMONIC, mnemonic))
                    else:
                        result.append(WalletData(WalletDataType.MNEMONIC, bytes(mnemonic).decode()))
                elif decrypted["type"] == "Simple Key Pair":
                    result.append(WalletData(WalletDataType.PRIVATE_KEY, decrypted["data"][0]))
            except:
                pass

        return result

    def extract_adresses(self):
        result = self._addresses
        try:
            contact_book = json.loads(self._ldb.get("contactBook"))
            for address in contact_book:
                result.add(address)
        except:
            pass
        return result

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        iterations = 10000
        kernel_type = 26620
        return f"$metamask${iterations}${base64.b64encode(self._salt).decode()}${base64.b64encode(self._iv).decode()}${base64.b64encode(self._data).decode()}"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, "_ldb"):
            self._ldb.close()


class Terra:
    def __init__(self, db_path, params):
        self._ldb = LocalStoreDb(pathlib.Path(db_path))
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        result = []
        for record in sorted(self._ldb.iter_records_for_script_key("chrome-extension://aiifbnbfobpmeekipheeijimdpnlpgpp", "wallets"), reverse=False, key=lambda x: x.leveldb_seq_number):
            for wallet in json.loads(record.value):
                if "encryptedSeed" in wallet:
                    result.append(wallet["encryptedSeed"])
                if "encryptedMnemonic" in wallet:
                    result.append(wallet["encryptedMnemonic"])

        self._encrypted = result

        self._salt = bytes.fromhex(result[0][:32])
        self._iv = bytes.fromhex(result[0][32:64])
        encrypted = base64.b64decode(result[0][64:])
        self._part_encrypted_data = encrypted[:16]

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                key = PBKDF2(password, self._salt, 32, count=20000, hmac_hash_module=SHA1)

                part_data = AES.new(key, AES.MODE_CBC, self._iv).decrypt(self._part_encrypted_data)
                if part_data.startswith(b"STATION:"):
                    self._password = password
                    return password
            except:
                pass

    def extract_wallet_data(self):
        result = []

        for encrypted in self._encrypted:
            try:
                salt = bytes.fromhex(encrypted[:32])
                iv = bytes.fromhex(encrypted[32:64])
                encrypteddata = base64.b64decode(encrypted[64:])

                key = PBKDF2(self._password, salt, 32, count=20000, hmac_hash_module=SHA1)

                data = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypteddata)
                data = unpad(data, AES.block_size).decode()[8:]

                if " " in data:
                    result.append(WalletData(WalletDataType.MNEMONIC, data))
                else:
                    result.append(WalletData(WalletDataType.PRIVATE_KEY, data))
            except:
                pass

        return result

    def extract_adresses(self):
        return set()

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        result = set(self._encrypted)
        return result

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class ExodusExtension:
    class ExodusImpl:
        HEADER_MAGIC = b"SECO"
        HEADER_VERSION = 0
        HEADER_VERSION_TAG = b"seco-v0-scrypt-aes"
        HEADER_SIZE = 224

        CHECKSUM_SIZE = 256 // 8

        METADATA_SALT_SIZE = 32
        METADATA_CIPHER_SIZE = 32
        METADATA_BLOB_KEY_IV_SIZE = 12
        METADATA_BLOB_KEY_AUTH_TAG_SIZE = 16
        METADATA_BLOB_KEY_KEY_SIZE = 32
        METADATA_BLOB_IV_SIZE = 12
        METADATA_BLOB_AUTH_TAG_SIZE = 16
        METADATA_SIZE = 256

        @dataclass
        class Header:
            magic: bytes
            version: int
            version_tag: bytes
            app_name: bytes
            app_version: bytes

        @dataclass(init=False)
        class Metadata:
            class Cipher(str, Enum):
                AES_256_GCM = "aes-256-gcm"

            @dataclass
            class BlobKey:
                iv: bytes
                auth_tag: bytes
                key: bytes

            @dataclass
            class Blob:
                iv: bytes
                auth_tag: bytes

            salt: bytes
            n: int
            r: int
            p: int
            cipher: Cipher
            blob_key: BlobKey
            blob: Blob

            def __init__(self, salt, n, r, p, cipher, blob_key, blob):
                self.salt = salt
                self.n = n
                self.r = r
                self.p = p
                if isinstance(cipher, bytes):
                    cipher = cipher.rstrip(b"\x00")
                    cipher = cipher.decode()
                cipher = self.Cipher(cipher)
                self.cipher = cipher
                self.blob_key = blob_key
                self.blob = blob

        @dataclass
        class File:
            header: "ExodusImpl.Header"
            checksum: bytes
            metadata: "ExodusImpl.Metadata"
            blob: bytes

        # header
        @staticmethod
        def read_header(file):
            # prepare structs
            partial_header_struct = Struct(">4sL4x")
            byte_struct = Struct(">B")

            # read whole header space
            file = BytesIO(file.read(ExodusExtension.ExodusImpl.HEADER_SIZE))

            # read partial header
            partial_header = file.read(partial_header_struct.size)
            if len(partial_header) < partial_header_struct.size:
                raise ValueError("file contains less data than needed")
            partial_header = partial_header_struct.unpack(partial_header)

            # read header version tag
            header_version_tag_length = file.read(byte_struct.size)
            if len(header_version_tag_length) < byte_struct.size:
                raise ValueError("file contains less data than needed")
            (header_version_tag_length,) = byte_struct.unpack(header_version_tag_length)
            header_version_tag = file.read(header_version_tag_length)
            if len(header_version_tag) < header_version_tag_length:
                raise ValueError("file contains less data than needed")

            # read header app name
            header_app_name_length = file.read(byte_struct.size)
            if len(header_app_name_length) < byte_struct.size:
                raise ValueError("file contains less data than needed")
            (header_app_name_length,) = byte_struct.unpack(header_app_name_length)
            header_app_name = file.read(header_app_name_length)
            if len(header_app_name) < header_app_name_length:
                raise ValueError("file contains less data than needed")

            # read header app version
            header_app_version_length = file.read(byte_struct.size)
            if len(header_app_version_length) < byte_struct.size:
                raise ValueError("file contains less data than needed")
            (header_app_version_length,) = byte_struct.unpack(header_app_version_length)
            header_app_version = file.read(header_app_version_length)
            if len(header_app_version) < header_app_version_length:
                raise ValueError("file contains less data than needed")

            # make header
            header = ExodusExtension.ExodusImpl.Header(*partial_header, header_version_tag, header_app_name, header_app_version)

            return header

        # checksum
        @staticmethod
        def read_checksum(file):
            # read checksum
            checksum = file.read(ExodusExtension.ExodusImpl.CHECKSUM_SIZE)
            if len(checksum) < ExodusExtension.ExodusImpl.CHECKSUM_SIZE:
                raise ValueError("file contains less data than needed")

            return checksum

        @staticmethod
        def validate_checksum(checksum, metadata, blob):
            # prepare hash
            sha256 = SHA256.new()

            # update with metadata
            sha256.update(metadata.salt)
            sha256.update(struct.pack(">LLL", metadata.n, metadata.r, metadata.p))
            sha256.update(metadata.cipher.value.encode().ljust(ExodusExtension.ExodusImpl.METADATA_CIPHER_SIZE, b"\x00"))

            # update with metadata blob key
            sha256.update(metadata.blob_key.iv)
            sha256.update(metadata.blob_key.auth_tag)
            sha256.update(metadata.blob_key.key)

            # update with metadata metadata.blob
            sha256.update(metadata.blob.iv)
            sha256.update(metadata.blob.auth_tag)

            # update with metadata padding
            metadata_size = ExodusExtension.ExodusImpl.METADATA_SALT_SIZE + struct.calcsize(">LLL") + ExodusExtension.ExodusImpl.METADATA_CIPHER_SIZE + ExodusExtension.ExodusImpl.METADATA_BLOB_KEY_IV_SIZE + ExodusExtension.ExodusImpl.METADATA_BLOB_KEY_AUTH_TAG_SIZE + ExodusExtension.ExodusImpl.METADATA_BLOB_KEY_KEY_SIZE + ExodusExtension.ExodusImpl.METADATA_BLOB_IV_SIZE + ExodusExtension.ExodusImpl.METADATA_BLOB_AUTH_TAG_SIZE
            sha256.update(bytes(ExodusExtension.ExodusImpl.METADATA_SIZE - metadata_size))

            # update with blob
            sha256.update(struct.pack(">L", len(blob)))
            sha256.update(blob)

            # make digest
            digest = sha256.digest()

            # compare
            if checksum != digest:
                raise ValueError("file corrupted - checksum validation failed")

        # metadata
        @staticmethod
        def read_metadata(file):
            # prepare structs
            partial_metadata_struct = Struct(">" + str(ExodusExtension.ExodusImpl.METADATA_SALT_SIZE) + "sLLL" + str(ExodusExtension.ExodusImpl.METADATA_CIPHER_SIZE) + "s")
            blob_key_struct = Struct(">" + str(ExodusExtension.ExodusImpl.METADATA_BLOB_KEY_IV_SIZE) + "s" + str(ExodusExtension.ExodusImpl.METADATA_BLOB_KEY_AUTH_TAG_SIZE) + "s" + str(ExodusExtension.ExodusImpl.METADATA_BLOB_KEY_KEY_SIZE) + "s")
            blob_struct = Struct(">" + str(ExodusExtension.ExodusImpl.METADATA_BLOB_IV_SIZE) + "s" + str(ExodusExtension.ExodusImpl.METADATA_BLOB_AUTH_TAG_SIZE) + "s")

            # read whole metadata space
            file = BytesIO(file.read(ExodusExtension.ExodusImpl.METADATA_SIZE))

            # read partial metadata
            partial_metadata = file.read(partial_metadata_struct.size)
            if len(partial_metadata) < partial_metadata_struct.size:
                raise ValueError("file contains less data than needed")
            partial_metadata = partial_metadata_struct.unpack(partial_metadata)

            # read blob key
            blob_key = file.read(blob_key_struct.size)
            if len(blob_key) < blob_key_struct.size:
                raise ValueError("file contains less data than needed")
            blob_key = blob_key_struct.unpack(blob_key)
            blob_key = ExodusExtension.ExodusImpl.Metadata.BlobKey(*blob_key)

            # read blob
            blob = file.read(blob_struct.size)
            if len(blob) < blob_struct.size:
                raise ValueError("file contains less data than needed")
            blob = blob_struct.unpack(blob)
            blob = ExodusExtension.ExodusImpl.Metadata.Blob(*blob)

            # make metadata
            metadata = ExodusExtension.ExodusImpl.Metadata(*partial_metadata, blob_key, blob)

            return metadata

        # blob
        @staticmethod
        def read_blob(file):
            # prepare structs
            size_struct = Struct(">L")

            # read size
            size = file.read(size_struct.size)
            if len(size) < size_struct.size:
                raise ValueError("file contains less data than needed")
            (size,) = size_struct.unpack(size)

            # read blob
            blob = file.read(size)
            if len(blob) < size:
                raise ValueError("file contains less data than needed")

            return blob

        # file
        @staticmethod
        def read_exodus(file):
            # read header
            header = ExodusExtension.ExodusImpl.read_header(file)

            # validate header values
            if header.magic != ExodusExtension.ExodusImpl.HEADER_MAGIC:
                raise ValueError("not a SECO file")
            if (header.version != ExodusExtension.ExodusImpl.HEADER_VERSION) or (header.version_tag != ExodusExtension.ExodusImpl.HEADER_VERSION_TAG):
                raise ValueError("unsupported version")

            # read checksum
            checksum = ExodusExtension.ExodusImpl.read_checksum(file)

            # read metadata
            metadata = ExodusExtension.ExodusImpl.read_metadata(file)

            # read blob
            blob = ExodusExtension.ExodusImpl.read_blob(file)

            # validate digest
            ExodusExtension.ExodusImpl.validate_checksum(checksum, metadata, blob)

            # make file
            file = ExodusExtension.ExodusImpl.File(header, checksum, metadata, blob)

            return file

    def __init__(self, db_path, params):
        self._ldb = LevelDb(db_path)
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        self._data = json.loads(self._ldb.get("!wallet!seed"))
        self._data = base64.b64decode(self._data)

    def try_passwords(self, passwords):
        bytes_file = BytesIO(self._data)
        file = ExodusExtension.ExodusImpl.read_exodus(bytes_file)
        passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            try:
                if hasattr(self, "_passphrase"):
                    password = self._passphrase

                password = password.encode()

                encrypted_key = scrypt(password, file.metadata.salt, 32, file.metadata.n, file.metadata.r, file.metadata.p)
                aes_gcm = AES.new(encrypted_key, mode=AES.MODE_GCM, nonce=file.metadata.blob_key.iv)
                decrypted_key = aes_gcm.decrypt_and_verify(file.metadata.blob_key.key, file.metadata.blob_key.auth_tag)

                aes_gcm = AES.new(decrypted_key, mode=AES.MODE_GCM, nonce=file.metadata.blob.iv)
                decrypted_data = aes_gcm.decrypt_and_verify(file.blob, file.metadata.blob.auth_tag)

                decrypted_data = decrypted_data[4 : unpack_from(">I", decrypted_data, 0)[0] + 4]

                decrypted_data = decompress(decrypted_data)

                self._decrypted = decrypted_data.decode()

                return password.decode("utf_8", "replace")
            except:
                pass

    def extract_wallet_data(self):
        result = []
        result.append(WalletData(WalletDataType.MNEMONIC, json.loads(self._decrypted)["mnemonic"]))
        return result

    def extract_adresses(self):
        return set()

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        kernel_type = 28200

        vault = self._data

        bytes_file = BytesIO(vault)
        file = ExodusExtension.ExodusImpl.read_exodus(bytes_file)

        result = ":".join(
            map(
                str,
                [
                    "EXODUS",
                    file.metadata.n,
                    file.metadata.r,
                    file.metadata.p,
                    base64.b64encode(file.metadata.salt).decode(),
                    base64.b64encode(file.metadata.blob_key.iv).decode(),
                    base64.b64encode(file.metadata.blob_key.key).decode(),
                    base64.b64encode(file.metadata.blob_key.auth_tag).decode(),
                ],
            )
        )

        return result

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class ExodusDesktop:
    def __init__(self, db_path, params):
        self._db_path = db_path
        passphrase_path = os.path.join(db_path, "passphrase.json")

        if os.path.exists(passphrase_path):
            try:
                with open(passphrase_path, "r") as file:
                    self._passphrase = json.loads(file.read())["passphrase"]
            except:
                pass

        self._load_wallet()

    def is_encrypted(self):
        return False if hasattr(self, "_passphrase") else True

    def _load_wallet(self):
        with open(os.path.join(self._db_path, "seed.seco"), "rb") as file:
            self._encrypted = file.read()

    def _decrypt_inner(self, file, password):
        encrypted_key = scrypt(password, file.metadata.salt, 32, file.metadata.n, file.metadata.r, file.metadata.p)
        aes_gcm = AES.new(encrypted_key, mode=AES.MODE_GCM, nonce=file.metadata.blob_key.iv)
        decrypted_key = aes_gcm.decrypt_and_verify(file.metadata.blob_key.key, file.metadata.blob_key.auth_tag)

        aes_gcm = AES.new(decrypted_key, mode=AES.MODE_GCM, nonce=file.metadata.blob.iv)
        decrypted_data = aes_gcm.decrypt_and_verify(file.blob, file.metadata.blob.auth_tag)

        decrypted_data = decrypted_data[4 : unpack_from(">I", decrypted_data, 0)[0] + 4]

        decrypted_data = decompress(decrypted_data)

        return decrypted_data

    def try_passwords(self, passwords):
        passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)

        bytes_file = BytesIO(self._encrypted)
        file = ExodusExtension.ExodusImpl.read_exodus(bytes_file)

        for count, password in enumerate(passwords, 1):
            try:
                self._decrypted = self._decrypt_inner(file, password)

                return password.decode("utf_8", "replace")
            except:
                pass

    def extract_wallet_data(self):
        result = []

        try:
            if hasattr(self, "_passphrase"):
                bytes_file = BytesIO(self._encrypted)
                file = ExodusExtension.ExodusImpl.read_exodus(bytes_file)
                password = self._passphrase.encode("utf_8", "ignore")
                decrypted = self._decrypt_inner(file, password)
            else:
                decrypted = self._decrypted

            result.append(WalletData(WalletDataType.MNEMONIC, Mnemonic("english").to_mnemonic(decrypted[64:])))
        except:
            pass

        return result

    def extract_adresses(self):
        return set()

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        kernel_type = 28200

        vault = self._encrypted

        bytes_file = BytesIO(vault)
        file = ExodusExtension.ExodusImpl.read_exodus(bytes_file)

        result = ":".join(
            map(
                str,
                [
                    "EXODUS",
                    file.metadata.n,
                    file.metadata.r,
                    file.metadata.p,
                    base64.b64encode(file.metadata.salt).decode(),
                    base64.b64encode(file.metadata.blob_key.iv).decode(),
                    base64.b64encode(file.metadata.blob_key.key).decode(),
                    base64.b64encode(file.metadata.blob_key.auth_tag).decode(),
                ],
            )
        )

        return result

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class CryptoComExtension:
    def __init__(self, db_path, params):
        self._ldb = WrappedIndexDB(pathlib.Path(db_path))
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        result = []

        for record in self._ldb["keyring-model"]["keyrings"].iterate_records():
            try:
                result.append(bytes(record.value["buffer"]).decode())
            except:
                pass

        for record in self._ldb["keyring-model"]["privateKeys"].iterate_records():
            try:
                result.append(bytes(record.value["buffer"]).decode())
            except:
                pass

        self._encrypted_data = result

        vault = json.loads(result[0])
        self._iv = base64.b64decode(vault["iv"])
        self._salt = base64.b64decode(vault["salt"])
        encrypted_data = base64.b64decode(vault["data"])
        self._encrypted = encrypted_data[:-16]
        self._tag = encrypted_data[-16:]

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                key = PBKDF2(password, self._salt, 32, count=10000, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=self._iv)
                plain_text = aes_gcm.decrypt_and_verify(self._encrypted, self._tag)

                self._password = password

                return password
            except:
                pass

    def extract_wallet_data(self):
        result = []

        for encrypted in self._encrypted_data:
            try:
                vault = json.loads(encrypted)
                iv = base64.b64decode(vault["iv"])
                salt = base64.b64decode(vault["salt"])
                encrypted_data = base64.b64decode(vault["data"])
                encrypted = encrypted_data[:-16]
                tag = encrypted_data[-16:]

                key = PBKDF2(self._password, salt, 32, count=10000, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=iv)
                plain_text = aes_gcm.decrypt_and_verify(encrypted, tag)

                d = json.loads(plain_text.decode())

                if " " == d:
                    result.append(WalletData(WalletDataType.MNEMONIC, d))
                else:
                    result.append(WalletData(WalletDataType.PRIVATE_KEY, d))
            except:
                pass

        return result

    def extract_adresses(self):
        result = set()
        return result

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        iterations = 10000
        kernel_type = 26620

        vault = json.loads(self._encrypted_data[0])

        return f'$metamask${iterations}${vault["salt"]}${vault["iv"]}${vault["data"]}'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class CryptoCom:
    def __init__(self, db_path, params):
        self._ldb = WrappedIndexDB(pathlib.Path(db_path))
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        result = []

        try:
            for record in self._ldb["NeDB"]["nedbdata"].iterate_records():
                try:
                    for splitted in record.value.split("\n"):
                        try:
                            splitted = json.loads(splitted)
                            if "cipher" in splitted["data"] and "iv" in splitted["data"]:
                                pass
                            result.append(bytes(record.value["buffer"]).decode())
                        except:
                            pass
                except:
                    pass
        except:
            pass

        for record in self._ldb["keyring-model"]["privateKeys"].iterate_records():
            try:
                result.append(bytes(record.value["buffer"]).decode())
            except:
                pass

        self._encrypted_data = result

        vault = json.loads(result[0])
        self._iv = base64.b64decode(vault["iv"])
        self._salt = base64.b64decode(vault["salt"])
        encrypted_data = base64.b64decode(vault["data"])
        self._encrypted = encrypted_data[:-16]
        self._tag = encrypted_data[-16:]

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                key = PBKDF2(password, self._salt, 32, count=10000, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=self._iv)
                plain_text = aes_gcm.decrypt_and_verify(self._encrypted, self._tag)

                self._password = password

                return password
            except:
                pass

    def extract_wallet_data(self):
        result = []

        for encrypted in self._encrypted_data:
            try:
                vault = json.loads(encrypted)
                iv = base64.b64decode(vault["iv"])
                salt = base64.b64decode(vault["salt"])
                encrypted_data = base64.b64decode(vault["data"])
                encrypted = encrypted_data[:-16]
                tag = encrypted_data[-16:]

                key = PBKDF2(self._password, salt, 32, count=10000, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=iv)
                plain_text = aes_gcm.decrypt_and_verify(encrypted, tag)

                d = json.loads(plain_text.decode())

                if " " == d:
                    result.append(WalletData(WalletDataType.MNEMONIC, d))
                else:
                    result.append(WalletData(WalletDataType.PRIVATE_KEY, d))
            except:
                pass

        return result

    def extract_adresses(self):
        result = set()
        return result

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        iterations = 10000
        kernel_type = 26620

        vault = json.loads(self._encrypted_data[0])

        return f'$metamask${iterations}${vault["salt"]}${vault["iv"]}${vault["data"]}'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class Safepal:
    def __init__(self, db_path, params):
        self._ldb = LevelDb(db_path)
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        self._data = json.loads(self._ldb.get("keyringState"))

        vault = json.loads(self._data["booted"])
        self._vault = vault

        self._iv = base64.b64decode(vault["iv"])
        self._salt = base64.b64decode(vault["salt"])
        encrypted_data = base64.b64decode(vault["data"])
        self._encrypted = encrypted_data[:-16]
        self._tag = encrypted_data[-16:]

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                key = PBKDF2(password, self._salt, 32, count=10000, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=self._iv)
                plain_text = aes_gcm.decrypt_and_verify(self._encrypted, self._tag)

                return password
            except:
                pass

    def extract_wallet_data(self):
        result = []

        return result

    def extract_adresses(self):
        result = set()
        return result

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        iterations = 10000
        kernel_type = 26620

        vault = self._vault

        return f'$metamask${iterations}${vault["salt"]}${vault["iv"]}${vault["data"]}'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class Okx:
    def __init__(self, db_path, params):
        self._ldb = LevelDb(db_path)
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        self._data = json.loads(self._ldb.get("data"))

        try:
            accounts = self._data["AccountsController"]["internalAccounts"]["accounts"]

            for account in accounts:
                try:
                    if accounts[account]["metadata"]["keyring"]["type"] == "Ledger Hardware" or accounts[account]["metadata"]["keyring"]["type"] == "Trezor Hardware" or accounts[account]["metadata"]["keyring"]["type"] == "Lattice Hardware":
                        raise ValueError("Wallet has not sensetive data")
                except:
                    continue
        except:
            pass

        vault = json.loads(self._data["KeyringController"]["vault"])
        self._iterations = 10000
        if "keyMetadata" in vault:
            self._iterations = vault["keyMetadata"]["params"]["iterations"]
        self._iv = base64.b64decode(vault["iv"])
        self._salt = base64.b64decode(vault["salt"])
        encrypted_data = base64.b64decode(vault["data"])
        self._encrypted = encrypted_data[:-16]
        self._tag = encrypted_data[-16:]

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                key = PBKDF2(password, self._salt, 32, count=self._iterations, hmac_hash_module=SHA256)
                aes_gcm = AES.new(key, AES.MODE_GCM, nonce=self._iv)
                plain_text = aes_gcm.decrypt_and_verify(self._encrypted, self._tag)

                self._decrypted = plain_text

                return password
            except:
                pass

    def extract_wallet_data(self):
        result = []

        for decrypted in json.loads(self._decrypted.decode()):
            try:
                if decrypted["type"] == "HD Key Tree":
                    mnemonic = decrypted["data"]["mnemonic"]

                    if type(mnemonic) == str:
                        result.append(WalletData(WalletDataType.MNEMONIC, mnemonic))
                    else:
                        result.append(WalletData(WalletDataType.MNEMONIC, bytes(mnemonic).decode()))
                elif decrypted["type"] == "Simple Key Pair":
                    result.append(WalletData(WalletDataType.PRIVATE_KEY, decrypted["data"][0]))
            except:
                pass

        return result

    def extract_adresses(self):
        result = set()
        try:
            addresses = self._data["AccountsController"]["internalAccounts"]["accounts"]
            for addressId in addresses:
                result.add(addresses[addressId]["address"])
        except:
            pass
        return result

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        iterations = 10000
        kernel_type = 26620

        vault = json.loads(self._data["KeyringController"]["vault"])

        if "keyMetadata" in vault:
            iterations = vault["keyMetadata"]["params"]["iterations"]

        return f'$metamask${iterations}${vault["salt"]}${vault["iv"]}${vault["data"]}'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class Coinomi:
    def __init__(self, db_path, params):
        with open(db_path, "rb") as file:
            self._file_data = file.read()
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        pb_wallet = coinomi_pb2.Wallet()
        pb_wallet.ParseFromString(self._file_data)

        self._encrypted_masterkey_part = pb_wallet.master_key.encrypted_data.encrypted_private_key[-32:]
        self._scrypt_salt = pb_wallet.encryption_parameters.salt
        self._scrypt_n = pb_wallet.encryption_parameters.n
        self._scrypt_r = pb_wallet.encryption_parameters.r
        self._scrypt_p = pb_wallet.encryption_parameters.p
        self._mnemonic = pb_wallet.seed.encrypted_data.encrypted_private_key
        self._mnemonic_iv = pb_wallet.seed.encrypted_data.initialisation_vector
        self._masterkey_encrypted = pb_wallet.master_key.encrypted_data.encrypted_private_key
        self._masterkey_encrypted_iv = pb_wallet.master_key.encrypted_data.initialisation_vector
        self._masterkey_chaincode = pb_wallet.master_key.deterministic_key.chain_code
        self._masterkey_pubkey = pb_wallet.master_key.public_key

    def try_passwords(self, passwords):
        _encrypted_masterkey_part = self._encrypted_masterkey_part
        scrypt_salt = self._scrypt_salt
        scrypt_n = self._scrypt_n
        scrypt_r = self._scrypt_r
        scrypt_p = self._scrypt_p
        passwords = map(lambda p: p.encode("utf_16_be", "ignore"), passwords)
        for count, password in enumerate(passwords, 1):
            key = hashlib.scrypt(password, salt=scrypt_salt, n=scrypt_n, r=scrypt_r, p=scrypt_p, dklen=32)

            part_key = AES.new(key, AES.MODE_CBC, _encrypted_masterkey_part[:16]).decrypt(_encrypted_masterkey_part[16:])

            if part_key == b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10":
                self._key = key
                return password.decode("utf_16_be", "replace")

    def extract_wallet_data(self):
        result = []
        try:
            mnemonic = AES.new(self._key, AES.MODE_CBC, self._mnemonic_iv).decrypt(self._mnemonic)
            mnemonic = unpad(mnemonic, AES.block_size).decode()
            result.append(WalletData(WalletDataType.MNEMONIC, mnemonic))
        except:
            pass
        return result

    def extract_adresses(self):
        return set()

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        tmp = binascii.hexlify(self._encrypted_masterkey_part).decode("ascii")
        salt = binascii.hexlify(self._scrypt_salt).decode("ascii")
        return f"$multibit$3*{self._scrypt_n}*{self._scrypt_r}*{self._scrypt_p}*{salt}*{tmp}"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class Coin98:
    class CryptoJs:
        def __init__(self, data):
            data = base64.b64decode(data)[8:]
            self.salt = data[:8]
            self.data = data[8:]

        def decrypt(self, password):
            key = b""
            block = None

            password_bytes = password.encode("utf-8")
            while len(key) < 48:
                hasher = hashlib.new("md5")
                if block:
                    hasher.update(block)
                hasher.update(password_bytes)
                hasher.update(self.salt)
                block = hasher.digest()
                key += block

            cipher = AES.new(key[0:32:], AES.MODE_CBC, iv=key[32:48:])
            return unpad(cipher.decrypt(self.data), AES.block_size)

    def __init__(self, db_path, params):
        self._ldb = LevelDb(db_path)
        self._load_wallet()
        self._decrypted = None

    def is_encrypted(self):
        return False if self._bypass else True

    def _add_address(self, addresData):
        try:
            address = addresData["address"]
            if not address == "":
                chain = "unknown"
                if "meta" in addresData:
                    if "chain" in addresData["meta"]:
                        chain = addresData["meta"]["chain"]
                self._addresses.append(f"{chain.upper()} - {address}")
        except:
            pass

    def _add_addresses(self, walletData):
        try:
            for wallet in walletData["activeWallet"]["wallets"]:
                self._add_address(wallet)
        except:
            pass

        try:
            for wallets in walletData["originalWallets"]:
                for wallet in wallets["wallets"]:
                    self._add_address(wallet)
        except:
            pass

        self._addresses = list(set(self._addresses))

    def _load_wallet(self):
        self._wallet = json.loads(json.loads(self._ldb.get("persist:root")))

        try:
            auth = json.loads(self._wallet["user"])["authentication"]
            self._bypass = Coin98.CryptoJs(auth["password"]).decrypt(auth["token"]).decode("utf-8")
        except:
            self._bypass = None

        wallet_data = json.loads(self._wallet["walletData"])

        self._addresses = []

        try:
            self._seed = Coin98.CryptoJs(wallet_data["activeWallet"]["mnemonic"])
        except:
            self._seed = None

        self._add_addresses(wallet_data)

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                self._decrypted = self._seed.decrypt(password)
                return password
            except:
                pass

    def extract_wallet_data(self):
        result = []
        try:
            if not self._decrypted and self._bypass:
                self._decrypted = self._seed.decrypt(self._bypass)

            result.append(WalletData(WalletDataType.MNEMONIC, self._decrypted.decode()))
        except:
            pass

        return result

    def extract_adresses(self):
        return set(self._addresses)

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        raise ValueError("Hahcat is not implemented")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class Martian:
    def __init__(self, db_path, params):
        self._ldb = LevelDb(db_path)
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _extract_wallets(self, entry):
        wallets_list = []
        try:
            store = json.loads(entry)
            for key, value in store.items():
                try:
                    if value["contains"] == "mnemonic" or value["contains"] == "privateKey":
                        wallets_list.append(value)
                except:
                    pass
            return {"nonce": store["passwordNonce"] if "passwordNonce" in store else "lTWLBilOrB", "wallets": wallets_list}
        except:
            pass

    def _load_wallet(self):
        self._wallets = self._extract_wallets(self._ldb.get("locked"))

    def try_passwords(self, passwords):
        wallet = self._wallets["wallets"][0]
        for count, password in enumerate(passwords, 1):
            try:
                password2 = base64.b64encode(hashlib.sha256((self._wallets["nonce"] + password).encode("utf-8")).digest())
                key = hashlib.pbkdf2_hmac(wallet["digest"], password2, base58.b58decode(wallet["salt"]), wallet["iterations"], dklen=secret.SecretBox.KEY_SIZE)
                box = secret.SecretBox(key)
                info = box.decrypt(base58.b58decode(wallet["encrypted"]), base58.b58decode(wallet["nonce"]))
                mnemonic = json.loads(info)["mnemonic"]
                self._password = password
                return password
            except:
                pass

    def extract_wallet_data(self):
        result = []
        try:
            for wallet in self._wallets["wallets"]:
                password = base64.b64encode(hashlib.sha256((self._wallets["nonce"] + self._password).encode("utf-8")).digest())
                key = hashlib.pbkdf2_hmac(wallet["digest"], password, base58.b58decode(wallet["salt"]), wallet["iterations"], dklen=secret.SecretBox.KEY_SIZE)
                box = secret.SecretBox(key)
                info = box.decrypt(base58.b58decode(wallet["encrypted"]), base58.b58decode(wallet["nonce"]))
                mnemonic = json.loads(info)["mnemonic"]
                if not mnemonic is None:
                    if " " in mnemonic:
                        result.append(WalletData(WalletDataType.MNEMONIC, mnemonic))
                    else:
                        result.append(WalletData(WalletDataType.PRIVATE_KEY, mnemonic))
        except:
            pass
        return result

    def extract_adresses(self):
        return set()

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        raise ValueError("Hahcat is not implemented")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class Math:
    class EncryptedItem:
        def __init__(self, item):
            tagged = base64.b64decode(item["ct"])
            self.tag = tagged[-8:]
            self.ct = tagged[:-8]
            self.iv = base64.b64decode(item["iv"])
            self.salt = base64.b64decode(item["salt"])

        def decrypt(self, rootKey):
            key = hashlib.pbkdf2_hmac("sha256", rootKey, self.salt, 10000, dklen=16)
            cipher = AES.new(key, AES.MODE_GCM, nonce=self.iv, mac_len=8)
            return cipher.decrypt_and_verify(self.ct, self.tag)

    class MathAccount:
        def __init__(self, account, key="Empty"):
            if "privateKey" in account:
                if key == "Empty":
                    self.privateKey = json.loads(account["privateKey"])
                else:
                    try:
                        self.privateKey = Math.EncryptedItem(json.loads(account["privateKey"])).decrypt(key).decode("utf-8")
                    except:
                        self.privateKey = None
            if "mnemonic" in account:
                if key == "Empty":
                    self.mnemonic = json.loads(account["mnemonic"])
                else:
                    try:
                        self.mnemonic = Math.EncryptedItem(json.loads(account["mnemonic"])).decrypt(key).decode("utf-8")
                    except:
                        self.mnemonic = None

    def __init__(self, db_path, params):
        self._ldb = LevelDb(db_path)
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        self._salt = json.loads(self._ldb.get("salt")).encode("utf-8")
        self._wallet = json.loads(self._ldb.get("mathWallet"))

        if isinstance(self._wallet["keychain"], str):
            self._keychain = Math.EncryptedItem(json.loads(self._wallet["keychain"]))
            self._rootKey = None
        else:
            self._keychain = self._wallet["keychain"]
            self._rootKey = "Empty"

    def try_passwords(self, passwords):
        passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)
        for count, password in enumerate(passwords, 1):
            try:
                hash = hashlib.scrypt(password, salt=self._salt, n=16384, r=8, p=1, dklen=16)
                rootKey = bip39.phrase_to_seed(bip39.encode_bytes(hash)).hex().encode("utf-8")
                self._keychain = json.loads(self._keychain.decrypt(rootKey))
                self._rootKey = rootKey
                return password.decode("utf_8", "replace")
            except:
                pass

    def extract_wallet_data(self):
        result = []

        try:
            for account in self._keychain["keypairs"]:
                acc = Math.MathAccount(account, self._rootKey)
                if hasattr(acc, "mnemonic") and acc.mnemonic:
                    result.append(WalletData(WalletDataType.MNEMONIC, acc.mnemonic))
                if hasattr(acc, "privateKey") and acc.privateKey:
                    result.append(WalletData(WalletDataType.PRIVATE_KEY, acc.privateKey))
        except:
            pass

        return result

    def extract_adresses(self):
        return set()

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        raise ValueError("Hahcat is not implemented")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


class Petra:
    class WalletDB:
        def __init__(self, path_wallet):
            self.salt = False
            self.vaults = []
            self.addresses = set()
            self.parse(path_wallet)

        def parse(self, path_wallet):
            try:
                leveldb_records = RawLevelDb(path_wallet)
                for record in leveldb_records.iterate_records_raw():
                    try:
                        data = record.value.decode("utf-8", "ignore").replace("\\", "")
                        if b"activeAccountAddress" in record.key:
                            try:
                                active_account = json.loads(json.loads(record.value))
                                self.addresses.add(active_account)
                            except:
                                pass
                        elif b"salt" in record.key:
                            self.salt = data[2:-2]
                        elif b"encryptedAccounts" in record.key:
                            data_json = json.loads(data[1:-1])
                            cipher = data_json["ciphertext"]
                            nonce = data_json["nonce"]
                            vault = {"cipher": cipher, "nonce": nonce}
                            if vault not in self.vaults:
                                self.vaults.append(vault)
                    except:
                        pass
            except:
                pass

    def __init__(self, db_path, params):
        self._wdb = Petra.WalletDB(db_path)

    def is_encrypted(self):
        return True

    def try_passwords(self, passwords):
        passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)
        salt = base58.b58decode(self._wdb.salt)
        ciphertext = base58.b58decode(self._wdb.vaults[0]["cipher"])
        nonce = base58.b58decode(self._wdb.vaults[0]["nonce"])

        for count, password in enumerate(passwords, 1):
            try:
                key = hashlib.pbkdf2_hmac("sha256", password, salt, 10000, dklen=32)
                cipher = secret.SecretBox(key)
                cipher.decrypt(ciphertext, nonce=nonce)
                self._key = key
                return password.decode("utf_8", "replace")
            except:
                pass

    def extract_wallet_data(self):
        result = []

        try:
            for vault in self._wdb.vaults:
                try:
                    ciphertext = base58.b58decode(vault["cipher"])
                    nonce = base58.b58decode(vault["nonce"])
                    cipher = secret.SecretBox(self._key)
                    decrypted = cipher.decrypt(ciphertext, nonce=nonce)
                    decrypted_data = json.loads(decrypted.decode("utf8"))
                    for key in decrypted_data.keys():
                        mnemonic = decrypted_data[key]["mnemonic"]
                        result.append(WalletData(WalletDataType.MNEMONIC, mnemonic))
                except:
                    pass
        except:
            pass

        return result

    def extract_adresses(self):
        return set(self._wdb.addresses)

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        raise ValueError("Hahcat is not implemented")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class MyMonero:
    english_words = [
        "abbey",
        "abducts",
        "ability",
        "ablaze",
        "abnormal",
        "abort",
        "abrasive",
        "absorb",
        "abyss",
        "academy",
        "aces",
        "aching",
        "acidic",
        "acoustic",
        "acquire",
        "across",
        "actress",
        "acumen",
        "adapt",
        "addicted",
        "adept",
        "adhesive",
        "adjust",
        "adopt",
        "adrenalin",
        "adult",
        "adventure",
        "aerial",
        "afar",
        "affair",
        "afield",
        "afloat",
        "afoot",
        "afraid",
        "after",
        "against",
        "agenda",
        "aggravate",
        "agile",
        "aglow",
        "agnostic",
        "agony",
        "agreed",
        "ahead",
        "aided",
        "ailments",
        "aimless",
        "airport",
        "aisle",
        "ajar",
        "akin",
        "alarms",
        "album",
        "alchemy",
        "alerts",
        "algebra",
        "alkaline",
        "alley",
        "almost",
        "aloof",
        "alpine",
        "already",
        "also",
        "altitude",
        "alumni",
        "always",
        "amaze",
        "ambush",
        "amended",
        "amidst",
        "ammo",
        "amnesty",
        "among",
        "amply",
        "amused",
        "anchor",
        "android",
        "anecdote",
        "angled",
        "ankle",
        "annoyed",
        "answers",
        "antics",
        "anvil",
        "anxiety",
        "anybody",
        "apart",
        "apex",
        "aphid",
        "aplomb",
        "apology",
        "apply",
        "apricot",
        "aptitude",
        "aquarium",
        "arbitrary",
        "archer",
        "ardent",
        "arena",
        "argue",
        "arises",
        "army",
        "around",
        "arrow",
        "arsenic",
        "artistic",
        "ascend",
        "ashtray",
        "aside",
        "asked",
        "asleep",
        "aspire",
        "assorted",
        "asylum",
        "athlete",
        "atlas",
        "atom",
        "atrium",
        "attire",
        "auburn",
        "auctions",
        "audio",
        "august",
        "aunt",
        "austere",
        "autumn",
        "avatar",
        "avidly",
        "avoid",
        "awakened",
        "awesome",
        "awful",
        "awkward",
        "awning",
        "awoken",
        "axes",
        "axis",
        "axle",
        "aztec",
        "azure",
        "baby",
        "bacon",
        "badge",
        "baffles",
        "bagpipe",
        "bailed",
        "bakery",
        "balding",
        "bamboo",
        "banjo",
        "baptism",
        "basin",
        "batch",
        "bawled",
        "bays",
        "because",
        "beer",
        "befit",
        "begun",
        "behind",
        "being",
        "below",
        "bemused",
        "benches",
        "berries",
        "bested",
        "betting",
        "bevel",
        "beware",
        "beyond",
        "bias",
        "bicycle",
        "bids",
        "bifocals",
        "biggest",
        "bikini",
        "bimonthly",
        "binocular",
        "biology",
        "biplane",
        "birth",
        "biscuit",
        "bite",
        "biweekly",
        "blender",
        "blip",
        "bluntly",
        "boat",
        "bobsled",
        "bodies",
        "bogeys",
        "boil",
        "boldly",
        "bomb",
        "border",
        "boss",
        "both",
        "bounced",
        "bovine",
        "bowling",
        "boxes",
        "boyfriend",
        "broken",
        "brunt",
        "bubble",
        "buckets",
        "budget",
        "buffet",
        "bugs",
        "building",
        "bulb",
        "bumper",
        "bunch",
        "business",
        "butter",
        "buying",
        "buzzer",
        "bygones",
        "byline",
        "bypass",
        "cabin",
        "cactus",
        "cadets",
        "cafe",
        "cage",
        "cajun",
        "cake",
        "calamity",
        "camp",
        "candy",
        "casket",
        "catch",
        "cause",
        "cavernous",
        "cease",
        "cedar",
        "ceiling",
        "cell",
        "cement",
        "cent",
        "certain",
        "chlorine",
        "chrome",
        "cider",
        "cigar",
        "cinema",
        "circle",
        "cistern",
        "citadel",
        "civilian",
        "claim",
        "click",
        "clue",
        "coal",
        "cobra",
        "cocoa",
        "code",
        "coexist",
        "coffee",
        "cogs",
        "cohesive",
        "coils",
        "colony",
        "comb",
        "cool",
        "copy",
        "corrode",
        "costume",
        "cottage",
        "cousin",
        "cowl",
        "criminal",
        "cube",
        "cucumber",
        "cuddled",
        "cuffs",
        "cuisine",
        "cunning",
        "cupcake",
        "custom",
        "cycling",
        "cylinder",
        "cynical",
        "dabbing",
        "dads",
        "daft",
        "dagger",
        "daily",
        "damp",
        "dangerous",
        "dapper",
        "darted",
        "dash",
        "dating",
        "dauntless",
        "dawn",
        "daytime",
        "dazed",
        "debut",
        "decay",
        "dedicated",
        "deepest",
        "deftly",
        "degrees",
        "dehydrate",
        "deity",
        "dejected",
        "delayed",
        "demonstrate",
        "dented",
        "deodorant",
        "depth",
        "desk",
        "devoid",
        "dewdrop",
        "dexterity",
        "dialect",
        "dice",
        "diet",
        "different",
        "digit",
        "dilute",
        "dime",
        "dinner",
        "diode",
        "diplomat",
        "directed",
        "distance",
        "ditch",
        "divers",
        "dizzy",
        "doctor",
        "dodge",
        "does",
        "dogs",
        "doing",
        "dolphin",
        "domestic",
        "donuts",
        "doorway",
        "dormant",
        "dosage",
        "dotted",
        "double",
        "dove",
        "down",
        "dozen",
        "dreams",
        "drinks",
        "drowning",
        "drunk",
        "drying",
        "dual",
        "dubbed",
        "duckling",
        "dude",
        "duets",
        "duke",
        "dullness",
        "dummy",
        "dunes",
        "duplex",
        "duration",
        "dusted",
        "duties",
        "dwarf",
        "dwelt",
        "dwindling",
        "dying",
        "dynamite",
        "dyslexic",
        "each",
        "eagle",
        "earth",
        "easy",
        "eating",
        "eavesdrop",
        "eccentric",
        "echo",
        "eclipse",
        "economics",
        "ecstatic",
        "eden",
        "edgy",
        "edited",
        "educated",
        "eels",
        "efficient",
        "eggs",
        "egotistic",
        "eight",
        "either",
        "eject",
        "elapse",
        "elbow",
        "eldest",
        "eleven",
        "elite",
        "elope",
        "else",
        "eluded",
        "emails",
        "ember",
        "emerge",
        "emit",
        "emotion",
        "empty",
        "emulate",
        "energy",
        "enforce",
        "enhanced",
        "enigma",
        "enjoy",
        "enlist",
        "enmity",
        "enough",
        "enraged",
        "ensign",
        "entrance",
        "envy",
        "epoxy",
        "equip",
        "erase",
        "erected",
        "erosion",
        "error",
        "eskimos",
        "espionage",
        "essential",
        "estate",
        "etched",
        "eternal",
        "ethics",
        "etiquette",
        "evaluate",
        "evenings",
        "evicted",
        "evolved",
        "examine",
        "excess",
        "exhale",
        "exit",
        "exotic",
        "exquisite",
        "extra",
        "exult",
        "fabrics",
        "factual",
        "fading",
        "fainted",
        "faked",
        "fall",
        "family",
        "fancy",
        "farming",
        "fatal",
        "faulty",
        "fawns",
        "faxed",
        "fazed",
        "feast",
        "february",
        "federal",
        "feel",
        "feline",
        "females",
        "fences",
        "ferry",
        "festival",
        "fetches",
        "fever",
        "fewest",
        "fiat",
        "fibula",
        "fictional",
        "fidget",
        "fierce",
        "fifteen",
        "fight",
        "films",
        "firm",
        "fishing",
        "fitting",
        "five",
        "fixate",
        "fizzle",
        "fleet",
        "flippant",
        "flying",
        "foamy",
        "focus",
        "foes",
        "foggy",
        "foiled",
        "folding",
        "fonts",
        "foolish",
        "fossil",
        "fountain",
        "fowls",
        "foxes",
        "foyer",
        "framed",
        "friendly",
        "frown",
        "fruit",
        "frying",
        "fudge",
        "fuel",
        "fugitive",
        "fully",
        "fuming",
        "fungal",
        "furnished",
        "fuselage",
        "future",
        "fuzzy",
        "gables",
        "gadget",
        "gags",
        "gained",
        "galaxy",
        "gambit",
        "gang",
        "gasp",
        "gather",
        "gauze",
        "gave",
        "gawk",
        "gaze",
        "gearbox",
        "gecko",
        "geek",
        "gels",
        "gemstone",
        "general",
        "geometry",
        "germs",
        "gesture",
        "getting",
        "geyser",
        "ghetto",
        "ghost",
        "giant",
        "giddy",
        "gifts",
        "gigantic",
        "gills",
        "gimmick",
        "ginger",
        "girth",
        "giving",
        "glass",
        "gleeful",
        "glide",
        "gnaw",
        "gnome",
        "goat",
        "goblet",
        "godfather",
        "goes",
        "goggles",
        "going",
        "goldfish",
        "gone",
        "goodbye",
        "gopher",
        "gorilla",
        "gossip",
        "gotten",
        "gourmet",
        "governing",
        "gown",
        "greater",
        "grunt",
        "guarded",
        "guest",
        "guide",
        "gulp",
        "gumball",
        "guru",
        "gusts",
        "gutter",
        "guys",
        "gymnast",
        "gypsy",
        "gyrate",
        "habitat",
        "hacksaw",
        "haggled",
        "hairy",
        "hamburger",
        "happens",
        "hashing",
        "hatchet",
        "haunted",
        "having",
        "hawk",
        "haystack",
        "hazard",
        "hectare",
        "hedgehog",
        "heels",
        "hefty",
        "height",
        "hemlock",
        "hence",
        "heron",
        "hesitate",
        "hexagon",
        "hickory",
        "hiding",
        "highway",
        "hijack",
        "hiker",
        "hills",
        "himself",
        "hinder",
        "hippo",
        "hire",
        "history",
        "hitched",
        "hive",
        "hoax",
        "hobby",
        "hockey",
        "hoisting",
        "hold",
        "honked",
        "hookup",
        "hope",
        "hornet",
        "hospital",
        "hotel",
        "hounded",
        "hover",
        "howls",
        "hubcaps",
        "huddle",
        "huge",
        "hull",
        "humid",
        "hunter",
        "hurried",
        "husband",
        "huts",
        "hybrid",
        "hydrogen",
        "hyper",
        "iceberg",
        "icing",
        "icon",
        "identity",
        "idiom",
        "idled",
        "idols",
        "igloo",
        "ignore",
        "iguana",
        "illness",
        "imagine",
        "imbalance",
        "imitate",
        "impel",
        "inactive",
        "inbound",
        "incur",
        "industrial",
        "inexact",
        "inflamed",
        "ingested",
        "initiate",
        "injury",
        "inkling",
        "inline",
        "inmate",
        "innocent",
        "inorganic",
        "input",
        "inquest",
        "inroads",
        "insult",
        "intended",
        "inundate",
        "invoke",
        "inwardly",
        "ionic",
        "irate",
        "iris",
        "irony",
        "irritate",
        "island",
        "isolated",
        "issued",
        "italics",
        "itches",
        "items",
        "itinerary",
        "itself",
        "ivory",
        "jabbed",
        "jackets",
        "jaded",
        "jagged",
        "jailed",
        "jamming",
        "january",
        "jargon",
        "jaunt",
        "javelin",
        "jaws",
        "jazz",
        "jeans",
        "jeers",
        "jellyfish",
        "jeopardy",
        "jerseys",
        "jester",
        "jetting",
        "jewels",
        "jigsaw",
        "jingle",
        "jittery",
        "jive",
        "jobs",
        "jockey",
        "jogger",
        "joining",
        "joking",
        "jolted",
        "jostle",
        "journal",
        "joyous",
        "jubilee",
        "judge",
        "juggled",
        "juicy",
        "jukebox",
        "july",
        "jump",
        "junk",
        "jury",
        "justice",
        "juvenile",
        "kangaroo",
        "karate",
        "keep",
        "kennel",
        "kept",
        "kernels",
        "kettle",
        "keyboard",
        "kickoff",
        "kidneys",
        "king",
        "kiosk",
        "kisses",
        "kitchens",
        "kiwi",
        "knapsack",
        "knee",
        "knife",
        "knowledge",
        "knuckle",
        "koala",
        "laboratory",
        "ladder",
        "lagoon",
        "lair",
        "lakes",
        "lamb",
        "language",
        "laptop",
        "large",
        "last",
        "later",
        "launching",
        "lava",
        "lawsuit",
        "layout",
        "lazy",
        "lectures",
        "ledge",
        "leech",
        "left",
        "legion",
        "leisure",
        "lemon",
        "lending",
        "leopard",
        "lesson",
        "lettuce",
        "lexicon",
        "liar",
        "library",
        "licks",
        "lids",
        "lied",
        "lifestyle",
        "light",
        "likewise",
        "lilac",
        "limits",
        "linen",
        "lion",
        "lipstick",
        "liquid",
        "listen",
        "lively",
        "loaded",
        "lobster",
        "locker",
        "lodge",
        "lofty",
        "logic",
        "loincloth",
        "long",
        "looking",
        "lopped",
        "lordship",
        "losing",
        "lottery",
        "loudly",
        "love",
        "lower",
        "loyal",
        "lucky",
        "luggage",
        "lukewarm",
        "lullaby",
        "lumber",
        "lunar",
        "lurk",
        "lush",
        "luxury",
        "lymph",
        "lynx",
        "lyrics",
        "macro",
        "madness",
        "magically",
        "mailed",
        "major",
        "makeup",
        "malady",
        "mammal",
        "maps",
        "masterful",
        "match",
        "maul",
        "maverick",
        "maximum",
        "mayor",
        "maze",
        "meant",
        "mechanic",
        "medicate",
        "meeting",
        "megabyte",
        "melting",
        "memoir",
        "menu",
        "merger",
        "mesh",
        "metro",
        "mews",
        "mice",
        "midst",
        "mighty",
        "mime",
        "mirror",
        "misery",
        "mittens",
        "mixture",
        "moat",
        "mobile",
        "mocked",
        "mohawk",
        "moisture",
        "molten",
        "moment",
        "money",
        "moon",
        "mops",
        "morsel",
        "mostly",
        "motherly",
        "mouth",
        "movement",
        "mowing",
        "much",
        "muddy",
        "muffin",
        "mugged",
        "mullet",
        "mumble",
        "mundane",
        "muppet",
        "mural",
        "musical",
        "muzzle",
        "myriad",
        "mystery",
        "myth",
        "nabbing",
        "nagged",
        "nail",
        "names",
        "nanny",
        "napkin",
        "narrate",
        "nasty",
        "natural",
        "nautical",
        "navy",
        "nearby",
        "necklace",
        "needed",
        "negative",
        "neither",
        "neon",
        "nephew",
        "nerves",
        "nestle",
        "network",
        "neutral",
        "never",
        "newt",
        "nexus",
        "nibs",
        "niche",
        "niece",
        "nifty",
        "nightly",
        "nimbly",
        "nineteen",
        "nirvana",
        "nitrogen",
        "nobody",
        "nocturnal",
        "nodes",
        "noises",
        "nomad",
        "noodles",
        "northern",
        "nostril",
        "noted",
        "nouns",
        "novelty",
        "nowhere",
        "nozzle",
        "nuance",
        "nucleus",
        "nudged",
        "nugget",
        "nuisance",
        "null",
        "number",
        "nuns",
        "nurse",
        "nutshell",
        "nylon",
        "oaks",
        "oars",
        "oasis",
        "oatmeal",
        "obedient",
        "object",
        "obliged",
        "obnoxious",
        "observant",
        "obtains",
        "obvious",
        "occur",
        "ocean",
        "october",
        "odds",
        "odometer",
        "offend",
        "often",
        "oilfield",
        "ointment",
        "okay",
        "older",
        "olive",
        "olympics",
        "omega",
        "omission",
        "omnibus",
        "onboard",
        "oncoming",
        "oneself",
        "ongoing",
        "onion",
        "online",
        "onslaught",
        "onto",
        "onward",
        "oozed",
        "opacity",
        "opened",
        "opposite",
        "optical",
        "opus",
        "orange",
        "orbit",
        "orchid",
        "orders",
        "organs",
        "origin",
        "ornament",
        "orphans",
        "oscar",
        "ostrich",
        "otherwise",
        "otter",
        "ouch",
        "ought",
        "ounce",
        "ourselves",
        "oust",
        "outbreak",
        "oval",
        "oven",
        "owed",
        "owls",
        "owner",
        "oxidant",
        "oxygen",
        "oyster",
        "ozone",
        "pact",
        "paddles",
        "pager",
        "pairing",
        "palace",
        "pamphlet",
        "pancakes",
        "paper",
        "paradise",
        "pastry",
        "patio",
        "pause",
        "pavements",
        "pawnshop",
        "payment",
        "peaches",
        "pebbles",
        "peculiar",
        "pedantic",
        "peeled",
        "pegs",
        "pelican",
        "pencil",
        "people",
        "pepper",
        "perfect",
        "pests",
        "petals",
        "phase",
        "pheasants",
        "phone",
        "phrases",
        "physics",
        "piano",
        "picked",
        "pierce",
        "pigment",
        "piloted",
        "pimple",
        "pinched",
        "pioneer",
        "pipeline",
        "pirate",
        "pistons",
        "pitched",
        "pivot",
        "pixels",
        "pizza",
        "playful",
        "pledge",
        "pliers",
        "plotting",
        "plus",
        "plywood",
        "poaching",
        "pockets",
        "podcast",
        "poetry",
        "point",
        "poker",
        "polar",
        "ponies",
        "pool",
        "popular",
        "portents",
        "possible",
        "potato",
        "pouch",
        "poverty",
        "powder",
        "pram",
        "present",
        "pride",
        "problems",
        "pruned",
        "prying",
        "psychic",
        "public",
        "puck",
        "puddle",
        "puffin",
        "pulp",
        "pumpkins",
        "punch",
        "puppy",
        "purged",
        "push",
        "putty",
        "puzzled",
        "pylons",
        "pyramid",
        "python",
        "queen",
        "quick",
        "quote",
        "rabbits",
        "racetrack",
        "radar",
        "rafts",
        "rage",
        "railway",
        "raking",
        "rally",
        "ramped",
        "randomly",
        "rapid",
        "rarest",
        "rash",
        "rated",
        "ravine",
        "rays",
        "razor",
        "react",
        "rebel",
        "recipe",
        "reduce",
        "reef",
        "refer",
        "regular",
        "reheat",
        "reinvest",
        "rejoices",
        "rekindle",
        "relic",
        "remedy",
        "renting",
        "reorder",
        "repent",
        "request",
        "reruns",
        "rest",
        "return",
        "reunion",
        "revamp",
        "rewind",
        "rhino",
        "rhythm",
        "ribbon",
        "richly",
        "ridges",
        "rift",
        "rigid",
        "rims",
        "ringing",
        "riots",
        "ripped",
        "rising",
        "ritual",
        "river",
        "roared",
        "robot",
        "rockets",
        "rodent",
        "rogue",
        "roles",
        "romance",
        "roomy",
        "roped",
        "roster",
        "rotate",
        "rounded",
        "rover",
        "rowboat",
        "royal",
        "ruby",
        "rudely",
        "ruffled",
        "rugged",
        "ruined",
        "ruling",
        "rumble",
        "runway",
        "rural",
        "rustled",
        "ruthless",
        "sabotage",
        "sack",
        "sadness",
        "safety",
        "saga",
        "sailor",
        "sake",
        "salads",
        "sample",
        "sanity",
        "sapling",
        "sarcasm",
        "sash",
        "satin",
        "saucepan",
        "saved",
        "sawmill",
        "saxophone",
        "sayings",
        "scamper",
        "scenic",
        "school",
        "science",
        "scoop",
        "scrub",
        "scuba",
        "seasons",
        "second",
        "sedan",
        "seeded",
        "segments",
        "seismic",
        "selfish",
        "semifinal",
        "sensible",
        "september",
        "sequence",
        "serving",
        "session",
        "setup",
        "seventh",
        "sewage",
        "shackles",
        "shelter",
        "shipped",
        "shocking",
        "shrugged",
        "shuffled",
        "shyness",
        "siblings",
        "sickness",
        "sidekick",
        "sieve",
        "sifting",
        "sighting",
        "silk",
        "simplest",
        "sincerely",
        "sipped",
        "siren",
        "situated",
        "sixteen",
        "sizes",
        "skater",
        "skew",
        "skirting",
        "skulls",
        "skydive",
        "slackens",
        "sleepless",
        "slid",
        "slower",
        "slug",
        "smash",
        "smelting",
        "smidgen",
        "smog",
        "smuggled",
        "snake",
        "sneeze",
        "sniff",
        "snout",
        "snug",
        "soapy",
        "sober",
        "soccer",
        "soda",
        "software",
        "soggy",
        "soil",
        "solved",
        "somewhere",
        "sonic",
        "soothe",
        "soprano",
        "sorry",
        "southern",
        "sovereign",
        "sowed",
        "soya",
        "space",
        "speedy",
        "sphere",
        "spiders",
        "splendid",
        "spout",
        "sprig",
        "spud",
        "spying",
        "square",
        "stacking",
        "stellar",
        "stick",
        "stockpile",
        "strained",
        "stunning",
        "stylishly",
        "subtly",
        "succeed",
        "suddenly",
        "suede",
        "suffice",
        "sugar",
        "suitcase",
        "sulking",
        "summon",
        "sunken",
        "superior",
        "surfer",
        "sushi",
        "suture",
        "swagger",
        "swept",
        "swiftly",
        "sword",
        "swung",
        "syllabus",
        "symptoms",
        "syndrome",
        "syringe",
        "system",
        "taboo",
        "tacit",
        "tadpoles",
        "tagged",
        "tail",
        "taken",
        "talent",
        "tamper",
        "tanks",
        "tapestry",
        "tarnished",
        "tasked",
        "tattoo",
        "taunts",
        "tavern",
        "tawny",
        "taxi",
        "teardrop",
        "technical",
        "tedious",
        "teeming",
        "tell",
        "template",
        "tender",
        "tepid",
        "tequila",
        "terminal",
        "testing",
        "tether",
        "textbook",
        "thaw",
        "theatrics",
        "thirsty",
        "thorn",
        "threaten",
        "thumbs",
        "thwart",
        "ticket",
        "tidy",
        "tiers",
        "tiger",
        "tilt",
        "timber",
        "tinted",
        "tipsy",
        "tirade",
        "tissue",
        "titans",
        "toaster",
        "tobacco",
        "today",
        "toenail",
        "toffee",
        "together",
        "toilet",
        "token",
        "tolerant",
        "tomorrow",
        "tonic",
        "toolbox",
        "topic",
        "torch",
        "tossed",
        "total",
        "touchy",
        "towel",
        "toxic",
        "toyed",
        "trash",
        "trendy",
        "tribal",
        "trolling",
        "truth",
        "trying",
        "tsunami",
        "tubes",
        "tucks",
        "tudor",
        "tuesday",
        "tufts",
        "tugs",
        "tuition",
        "tulips",
        "tumbling",
        "tunnel",
        "turnip",
        "tusks",
        "tutor",
        "tuxedo",
        "twang",
        "tweezers",
        "twice",
        "twofold",
        "tycoon",
        "typist",
        "tyrant",
        "ugly",
        "ulcers",
        "ultimate",
        "umbrella",
        "umpire",
        "unafraid",
        "unbending",
        "uncle",
        "under",
        "uneven",
        "unfit",
        "ungainly",
        "unhappy",
        "union",
        "unjustly",
        "unknown",
        "unlikely",
        "unmask",
        "unnoticed",
        "unopened",
        "unplugs",
        "unquoted",
        "unrest",
        "unsafe",
        "until",
        "unusual",
        "unveil",
        "unwind",
        "unzip",
        "upbeat",
        "upcoming",
        "update",
        "upgrade",
        "uphill",
        "upkeep",
        "upload",
        "upon",
        "upper",
        "upright",
        "upstairs",
        "uptight",
        "upwards",
        "urban",
        "urchins",
        "urgent",
        "usage",
        "useful",
        "usher",
        "using",
        "usual",
        "utensils",
        "utility",
        "utmost",
        "utopia",
        "uttered",
        "vacation",
        "vague",
        "vain",
        "value",
        "vampire",
        "vane",
        "vapidly",
        "vary",
        "vastness",
        "vats",
        "vaults",
        "vector",
        "veered",
        "vegan",
        "vehicle",
        "vein",
        "velvet",
        "venomous",
        "verification",
        "vessel",
        "veteran",
        "vexed",
        "vials",
        "vibrate",
        "victim",
        "video",
        "viewpoint",
        "vigilant",
        "viking",
        "village",
        "vinegar",
        "violin",
        "vipers",
        "virtual",
        "visited",
        "vitals",
        "vivid",
        "vixen",
        "vocal",
        "vogue",
        "voice",
        "volcano",
        "vortex",
        "voted",
        "voucher",
        "vowels",
        "voyage",
        "vulture",
        "wade",
        "waffle",
        "wagtail",
        "waist",
        "waking",
        "wallets",
        "wanted",
        "warped",
        "washing",
        "water",
        "waveform",
        "waxing",
        "wayside",
        "weavers",
        "website",
        "wedge",
        "weekday",
        "weird",
        "welders",
        "went",
        "wept",
        "were",
        "western",
        "wetsuit",
        "whale",
        "when",
        "whipped",
        "whole",
        "wickets",
        "width",
        "wield",
        "wife",
        "wiggle",
        "wildly",
        "winter",
        "wipeout",
        "wiring",
        "wise",
        "withdrawn",
        "wives",
        "wizard",
        "wobbly",
        "woes",
        "woken",
        "wolf",
        "womanly",
        "wonders",
        "woozy",
        "worry",
        "wounded",
        "woven",
        "wrap",
        "wrist",
        "wrong",
        "yacht",
        "yahoo",
        "yanks",
        "yard",
        "yawning",
        "yearbook",
        "yellow",
        "yesterday",
        "yeti",
        "yields",
        "yodel",
        "yoga",
        "younger",
        "yoyo",
        "zapped",
        "zeal",
        "zebra",
        "zero",
        "zesty",
        "zigzags",
        "zinger",
        "zippers",
        "zodiac",
        "zombie",
        "zones",
        "zoom",
    ]

    def _extract_block(self, message):
        return {
            "encryption_salt": message[0x2:0xA],
            "hmac_salt": message[0xA:0x12],
            "iv": message[0x12:0x22],
            "hmac": message[-0x20:],
            "cipher_text": message[0x22:-0x20],
        }

    def _extract_cipher_block(self, path):
        with open(path, "rb") as file:
            message = base64.b64decode(file.read())
        return self._extract_block(message)

    # Unused for now, encrypted data in PasswordMeta__ in current version is just dummy string
    def _extract_password_block(self, path):
        with open(path, "rb") as file:
            meta = json.loads(file.read())
        message = base64.b64decode(meta["encryptedMessageForUnlockChallenge"])
        return self._extract_block(message)

    def _decrypt_block(self, meta, password):
        key = hashlib.pbkdf2_hmac("sha1", password, meta["encryption_salt"], 10000, dklen=32)
        cipher = AES.new(key, AES.MODE_CBC, iv=meta["iv"])
        key_meta = unpad(cipher.decrypt(meta["cipher_text"]), AES.block_size)
        return key_meta.decode("utf-8")

    def _checksum_for_seed(self, words):
        if len(words) > 13:
            phrase = words[:24]
        elif len(words) == 12:
            phrase = words[:12]
        else:
            raise Exception("Invalid seed")
        seed_bytes = bytearray(("".join(word[:3] for word in phrase)).encode("utf-8"))
        checksum = (((((crc32(seed_bytes) & 0xFFFFFFFF) ^ 0xFFFFFFFF) >> 0) ^ 0xFFFFFFFF) >> 0) % len(phrase)
        return words[checksum]

    def _hex_seed_to_words_seed(self, seed):
        words = []
        for i in range(len(seed) // 8):
            word = "".join([seed[8 * i : 8 * i + 8][j : j + 2] for j in [6, 4, 2, 0]])
            x = int(word, 16)
            word1 = x % 1626
            word2 = (x // 1626 + word1) % 1626
            word3 = (x // 1626 // 1626 + word2) % 1626
            words += [MyMonero.english_words[word1], MyMonero.english_words[word2], MyMonero.english_words[word3]]
        words.append(self._checksum_for_seed(words))
        return " ".join(words)

    def __init__(self, db_path, params):
        self._cipher_block = self._extract_cipher_block(db_path)

    def is_encrypted(self):
        return True

    def try_passwords(self, passwords):
        passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)
        for count, password in enumerate(passwords, 1):
            try:
                self._decrypted = self._decrypt_block(self._cipher_block, password)
                return password.decode("utf_8", "replace")
            except:
                pass

    def extract_wallet_data(self):
        seed = json.loads(self._decrypted)["account_seed"]
        return [WalletData(WalletDataType.MNEMONIC, self._hex_seed_to_words_seed(seed))]

    def extract_adresses(self):
        return set()

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        raise ValueError("Hahcat is not implemented")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class MetamaskLike:
    class WalletDB:
        def __init__(self):
            self.vaults = []
            self.vaults_new = []
            self.addresses = set()
            self.trezor = False
            self.ledger = False

        def add_vault_log(self, path_wallet: str):
            for filename in os.listdir(path_wallet):
                try:
                    path_full = os.path.join(path_wallet, filename)
                    path_full_low = path_full.lower()

                    if path_full_low.endswith(".log"):
                        with open(path_full, "r", encoding="utf8", errors="surrogateescape") as f:
                            file = f.read()

                            regex_hash = [
                                r"{\\\"data\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"salt\\\":\\\"(.+?)\\\"}",
                                r"{\\\\\\\"data\\\\\\\":\\\\\\\"(.+?)\\\\\\\",\\\\\\\"iv\\\\\\\":\\\\\\\"(.+?)\\\\\\\",\\\\\\\"salt\\\\\\\":\\\\\\\"(.+?)\\\\\\\"}",
                                r"{\\\"encrypted\\\":\\\"(.+?)\\\",\\\"nonce\\\":\\\"(.+?)\\\",\\\"kdf\\\":\\\"pbkdf2\\\",\\\"salt\\\":\\\"(.+?)\\\",\\\"iterations\\\":10000,\\\"digest\\\":\\\"sha256\\\"}",
                                r"{\\\"ct\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"s\\\":\\\"(.+?)\\\"}",
                            ]

                            regex_hash_new = [
                                r"{\\\"data\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"keyMetadata\\\":{\\\"algorithm\\\":\\\"PBKDF2\\\",\\\"params\\\":{\\\"iterations\\\":600000}},\\\"salt\\\":\\\"(.+?)\\\"}\"},",
                            ]

                            for r in regex_hash:
                                matches = re.search(r, file, re.MULTILINE)
                                if matches:
                                    data = matches.group(1)
                                    iv = matches.group(2)
                                    salt = matches.group(3)
                                    vault = {"data": data, "iv": iv, "salt": salt}
                                    vault = json.loads(str(vault).replace("'", '"'))
                                    vault = json.loads(str(vault).replace("'", '"'))
                                    if vault not in self.vaults:
                                        self.vaults.append(vault)

                            for r in regex_hash_new:
                                matches = re.search(r, file, re.MULTILINE)
                                if matches:
                                    data = matches.group(1)
                                    iv = matches.group(2)
                                    salt = matches.group(3)
                                    vault = {"data": data, "iv": iv, "salt": salt}
                                    vault = json.loads(str(vault).replace("'", '"'))
                                    vault = json.loads(str(vault).replace("'", '"'))
                                    if vault not in self.vaults:
                                        self.vaults_new.append(vault)

                            # Brawe \ Metamask \ KardiaChain \ NiftyWallet \ cloverWallet \ monstraWallet
                            regex_addresses = re.finditer(r'"selectedAddress\":\"(.+?)\",\"', file, re.MULTILINE)
                            for item in regex_addresses:
                                address = item.group(1)
                                if len(address) <= 42:
                                    self.addresses.add(address)

                            # Ronin
                            regex_addresses = re.finditer(r'selectedAccount{"address":"(.+?)",', file, re.MULTILINE)
                            for item in regex_addresses:
                                address = item.group(1)
                                if len(address) <= 42:
                                    self.addresses.add(address)

                            for line in file.split("\n"):
                                if '"name":"Ledger' in line:
                                    self.ledger = True

                                if '"name":"Trezor' in line:
                                    self.trezor = True
                except:
                    pass

        def add_vault_old(self, value):
            try:
                data = value.decode("utf8", "ignore").replace("\\", "")
                if "salt" in data:
                    vault = data[1:-1]
                    vault = json.loads(str(vault).replace("'", '"'))
                    if vault not in self.vaults:
                        self.vaults.append(vault)
            except:
                pass

        def add_vault_new(self, value):
            try:
                data = value.decode("utf8", "ignore").replace("\\", "")
                if "salt" in data:
                    vault_start = data.lower().find("vault")
                    vault_trimmed = data[vault_start:]
                    vault_start = vault_trimmed.find("data")
                    vault_trimmed = vault_trimmed[vault_start - 2 :]
                    vault_end = vault_trimmed.find("}")
                    vault = vault_trimmed[: vault_end + 1]
                    vault = json.loads(str(vault).replace("'", '"'))
                    if vault not in self.vaults:
                        self.vaults.append(vault)
            except:
                pass

        def add_vault_v2(self, value):
            try:
                data = str(value).replace("\\", "")

                if "salt" in data:
                    vault_start = data.lower().find("vault")
                    vault_trimmed = data[vault_start:]
                    vault_start = vault_trimmed.find("data")
                    vault_trimmed = vault_trimmed[vault_start - 2 :]
                    vault_end = vault_trimmed.find('"}"},')
                    vault = vault_trimmed[: vault_end + 1] + "}"
                    vault = json.loads(str(vault))

                    if vault not in self.vaults:
                        self.vaults_new.append(vault)
            except:
                pass

    class MetamaskDecrypt:
        def __init__(self, vault, is_new):
            try:
                try:
                    vault = json.loads(vault)
                except json.decoder.JSONDecodeError:
                    vault_start = vault.lower().find("vault")
                    vault_trimmed = vault[vault_end:]
                    vault_start = vault_trimmed.find("cipher")
                    vault_trimmed = vault_trimmed[vault_start - 2 :]
                    vault_end = vault_trimmed.find("}")
                    vault = vault_trimmed[: vault_end + 1]
                    vault = json.loads(vault)
            except:
                pass

            self.encrypted_data = base64.b64decode(vault["data"])
            self.ciphertext = self.encrypted_data[:-16]
            self.salt = base64.b64decode(vault["salt"])
            self.iv = base64.b64decode(vault["iv"])
            self.tag = self.encrypted_data[-16:]
            if is_new:
                self.iter = 600000
            else:
                self.iter = 10000

        def decrypt(self, password):
            key = hashlib.pbkdf2_hmac("sha256", password, self.salt, self.iter, dklen=32)
            cipher = AES.new(key, AES.MODE_GCM, nonce=self.iv)
            return cipher.decrypt_and_verify(self.ciphertext, self.tag).decode("utf8")

    def _get_mnemonic(self, wallet_type, decrypted_data):
        try:
            if wallet_type in [
                "brave",
                "pontem_aptos",
                "kardia_chain",
                "clover",
                "token_pocket",
                "zeon",
                "pantograph",
                "starmask",
                "metamask",
            ]:
                mnemonic = json.loads(decrypted_data)[0]["data"]["mnemonic"]
                if type(mnemonic) == list:
                    mnemonic = bytes(mnemonic).decode("utf8")
                return mnemonic

            elif wallet_type == "ronin":
                mnemonic = json.loads(json.loads(decrypted_data))["mnemonic"]
                return mnemonic

            elif wallet_type == "bnb_chain":
                mnemonic = json.loads(decrypted_data)["accounts"][0]["mnemonic"]
                return mnemonic

            elif wallet_type in ["energy8", "finx", "monsta"]:
                mnemonic = json.loads(decrypted_data)[0]["data"]["mnemonic"]
                mnemonic = bytes(mnemonic).decode("utf8")
                return mnemonic

            elif wallet_type == "spika":
                mnemonic = decrypted_data.replace('"', "")
                return mnemonic

            elif wallet_type == "sui":
                try:
                    entropy = json.loads(decrypted_data)["entropy"]
                except:
                    entropy = json.loads(decrypted_data)["entropyHex"]
                mnemonic = bip39.encode_bytes(bytes.fromhex(entropy))
                return mnemonic
        except:
            return False

    def _extract_wallet_data(self, path_wallet):
        wallet_ldb = MetamaskLike.WalletDB()

        wallet_ldb.add_vault_log(path_wallet)

        try:
            leveldb_records = RawLevelDb(path_wallet)
            for record in leveldb_records.iterate_records_raw():

                if b"vault" in record.key or b"encryptedVault" in record.key:
                    wallet_ldb.add_vault_old(record.value)
                elif b"data" in record.key:
                    wallet_ldb.add_vault_new(record.value)

                if "PBKDF2" in str(record.value):
                    wallet_ldb.add_vault_v2(record.value)

        except:
            pass

        return wallet_ldb

    def __init__(self, db_path, params):
        self._wallet_type = params["wallet_type"]
        self._wallet_data = self._extract_wallet_data(db_path)
        if self._wallet_data.ledger or self._wallet_data.trezor:
            raise ValueError("Hardware wallet detected")
        self._encrypted = []

        for vault in self._wallet_data.vaults:
            try:
                met = MetamaskLike.MetamaskDecrypt(vault, False)

                skip = False

                for encrypted in self._encrypted:
                    if met.ciphertext == encrypted.ciphertext:
                        skip = True

                if skip:
                    continue

                self._encrypted.append(met)
            except:
                pass
        for vault in self._wallet_data.vaults_new:
            try:
                met = MetamaskLike.MetamaskDecrypt(vault, True)

                skip = False

                for encrypted in self._encrypted:
                    if met.ciphertext == encrypted.ciphertext:
                        skip = True

                if skip:
                    continue

                self._encrypted.append(met)
            except:
                pass

    def is_encrypted(self):
        return True

    def try_passwords(self, passwords):
        passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)
        met = self._encrypted[0]
        for count, password in enumerate(passwords, 1):
            try:
                met.decrypt(password)
                self._password = password
                return password.decode("utf_8", "replace")
            except:
                pass

    def extract_wallet_data(self):
        result = []
        for met in self._encrypted:
            try:
                decrypted_data = met.decrypt(self._password)
                mnemonic = self._get_mnemonic(self._wallet_type, decrypted_data)

                pattern_privkey = "[0-9a-f]{64}"
                pattern_privkey_0x = "0x[0-9a-fA-F]{64}"

                for privkey in set(re.findall(pattern_privkey, decrypted_data)):
                    try:
                        result.append(WalletData(WalletDataType.PRIVATE_KEY, privkey))
                    except:
                        pass

                for privkey in set(re.findall(pattern_privkey_0x, decrypted_data)):
                    try:
                        result.append(WalletData(WalletDataType.PRIVATE_KEY, privkey))
                    except:
                        pass

                if mnemonic:
                    result.append(WalletData(WalletDataType.MNEMONIC, mnemonic))
            except:
                pass

        return result

    def extract_adresses(self):
        return set(self._wallet_data.addresses)

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        met = self._encrypted[0]

        return "$metamask$" + str(met.iter) + "$" + base64.b64encode(met.salt).decode() + "$" + base64.b64encode(met.iv).decode() + "$" + base64.b64encode(met.encrypted_data).decode()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class Daedalus:
    class DaedalusPasswordHash:
        def __init__(self, hash):
            salt_len = int(hash[0])
            self.salt = hash[1 : salt_len + 1 :]
            self.hash = hash[salt_len + 1 : :]

        def try_pbkdf_password(self, password):
            try:
                return self.hash == hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), self.salt, 20000, dklen=64)
            except:
                return False

    class DaedalusEncryptedKey:
        def __init__(self, key):
            self.root_key = key[0:64:]
            self.public_key = key[64:96:]
            self.chain_code = key[96:128:]

        def decrypt_shelley_root_key(self, password):
            try:
                key = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), "encrypted wallet salt\0".encode("utf-8"), 15000, dklen=40)
                cipher = ChaCha20.new(key=key[0:32:], nonce=key[32:40:])
                return (cipher.decrypt(self.root_key) + self.chain_code).hex()
            except:
                return ""

    class DeadalusWallet:
        def __init__(self, path_wallet):
            self.abort = True
            try:
                connection = sqlite3.connect(path_wallet)
                cursor = connection.cursor()
                result = cursor.execute("SELECT root, hash FROM private_key").fetchone()
                if not result is None:
                    root, hash = result
                    self.password_hash = Daedalus.DaedalusPasswordHash(bytes.fromhex(hash.decode("utf-8")))
                    self.encrypted_key = Daedalus.DaedalusEncryptedKey(bytes.fromhex(root.decode("utf-8")))
                    self.abort = False
            except:
                pass

    def __init__(self, db_path, params):
        self._wallet = Daedalus.DeadalusWallet(db_path)
        pass

    def is_encrypted(self):
        return True

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                if self._wallet.password_hash.try_pbkdf_password(password):
                    self._password = password
                    return password
            except:
                pass

    def extract_wallet_data(self):
        return [WalletData(WalletDataType.MNEMONIC, self._wallet.encrypted_key.decrypt_shelley_root_key(self._password))]

    def extract_adresses(self):
        return set()

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        raise ValueError("Hahcat is not implemented")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class MyEherwallet:
    def __init__(self, db_path, params):
        self._load_wallet(db_path)

    def is_encrypted(self):
        return True

    def _load_wallet(self, db_path):
        with open(db_path) as wallet_file:
            self._json_data = json.load(wallet_file)

    def try_passwords(self, passwords):
        passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)

        salt = bytes.fromhex(self._json_data["crypto"]["kdfparams"]["salt"])
        ciphertext = bytes.fromhex(self._json_data["crypto"]["ciphertext"])
        mac = self._json_data["crypto"]["mac"]
        kdf = self._json_data["crypto"]["kdf"]

        if kdf == "pbkdf2" and self._json_data["crypto"]["kdfparams"]["prf"] == "hmac-sha256":
            iter = self._json_data["crypto"]["kdfparams"]["c"]
            salt = self._json_data["crypto"]["kdfparams"]["salt"]

            for count, password in enumerate(passwords, 1):
                key = hashlib.pbkdf2_hmac("sha256", password, salt, iter, dklen=32)

                validate = key[16:] + ciphertext

                if keccak.new(digest_bits=256).update(validate).hexdigest() == mac:
                    self._key = key
                    return password.decode("utf_8", "replace")
        elif kdf == "scrypt":
            n = self._json_data["crypto"]["kdfparams"]["n"]
            r = self._json_data["crypto"]["kdfparams"]["r"]
            p = self._json_data["crypto"]["kdfparams"]["p"]
            dklen = self._json_data["crypto"]["kdfparams"]["dklen"]

            for count, password in enumerate(passwords, 1):
                key = hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, maxmem=2000000000, dklen=dklen)
                validate = key[16:] + ciphertext

                if keccak.new(digest_bits=256).update(validate).hexdigest() == mac:
                    self._key = key
                    return password.decode("utf_8", "replace")

    def extract_wallet_data(self):
        salt = bytes.fromhex(self._json_data["crypto"]["kdfparams"]["salt"])
        iv = self._json_data["crypto"]["cipherparams"]["iv"]
        ciphertext = bytes.fromhex(self._json_data["crypto"]["ciphertext"])

        iv_int = int(iv, 16)
        ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)

        dec_suite = AES.new(self._key[:16], AES.MODE_CTR, counter=ctr)
        decrypted_privkey = dec_suite.decrypt(ciphertext).hex()

        return [WalletData(WalletDataType.PRIVATE_KEY, decrypted_privkey)]

    def extract_adresses(self):
        return set([self._json_data["address"]])

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        kdf = self._json_data["crypto"]["kdf"]

        if kdf == "pbkdf2":
            prf = self._json_data["crypto"]["kdfparams"]["prf"]
            if prf == "hmac-sha256":
                ciphertext = self._json_data["crypto"]["ciphertext"]
                mac = self._json_data["crypto"]["mac"]
                iter = self._json_data["crypto"]["kdfparams"]["c"]
                salt = self._json_data["crypto"]["kdfparams"]["salt"]
                return "$ethereum$p*%s*%s*%s*%s" % (iter, salt, mac, ciphertext)
            else:
                raise ValueError("Wallet format unknown or unsupported")
        elif kdf == "scrypt":
            ciphertext = self._json_data["crypto"]["ciphertext"]
            mac = self._json_data["crypto"]["mac"]
            n = self._json_data["crypto"]["kdfparams"]["n"]
            p = self._json_data["crypto"]["kdfparams"]["p"]
            r = self._json_data["crypto"]["kdfparams"]["r"]
            salt = self._json_data["crypto"]["kdfparams"]["salt"]
            return "$ethereum$s*%s*%s*%s*%s*%s*%s" % (n, r, p, salt, mac, ciphertext)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class Electrum:
    def __init__(self, db_path, params):
        self._path_wallet = db_path
        self._wallet_storage = WalletStorage(db_path)
        self._load_wallet()

    def is_encrypted(self):
        return self._wallet_storage.is_encrypted()

    def _load_wallet(self):
        pass

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                self._wallet_storage.decrypt(password)
                self._password = password
                return password
            except:
                pass

    def extract_wallet_data(self):
        result = []
        if self._wallet_storage.is_encrypted():
            wallet_data = json.loads(self._wallet_storage.decrypted)
            if wallet_data["keystore"]["type"] == "bip32":
                xprv = pw_decode(wallet_data["keystore"]["xprv"], self._password, version=1)
                result.append(WalletData(WalletDataType.BIP32_MASTER_KEY, xprv))
            if wallet_data["keystore"]["type"] == "seed":
                mnemonic = pw_decode(wallet_data["keystore"]["seed"], self._password, version=1)
                result.append(WalletData(WalletDataType.MNEMONIC, mnemonic))
            if wallet_data["keystore"]["type"] == "imported":
                for keypairs_key in wallet_data["keystore"]["keypairs"]:
                    val = wallet_data["keystore"]["keypairs"][keypairs_key]
                    val = pw_decode(val, self._password, version=1)
                    result.append(WalletData(WalletDataType.PRIVATE_KEY, val))
        else:
            wallet_data = json.loads(self._wallet_storage.read())
            if wallet_data["keystore"]["type"] == "bip32":
                result.append(WalletData(WalletDataType.BIP32_MASTER_KEY, wallet_data["keystore"]["xprv"]))
            if wallet_data["keystore"]["type"] == "seed":
                result.append(WalletData(WalletDataType.MNEMONIC, wallet_data["keystore"]["seed"]))
            if wallet_data["keystore"]["type"] == "imported":
                for keypairs_key in wallet_data["keystore"]["keypairs"]:
                    result.append(WalletData(WalletDataType.PRIVATE_KEY, wallet_data["keystore"]["keypairs"][keypairs_key]))

        return result

    def extract_adresses(self):
        result = set()
        try:
            if not self._wallet_storage.is_encrypted():
                wallet_data = json.loads(self._wallet_storage.read())
                result = set(wallet_data["addresses"]["receiving"])
        except:
            pass
        return result

    def extract_adresses_after_decrypt(self):
        result = set()
        try:
            if self._wallet_storage.is_encrypted():
                wallet_data = json.loads(self._wallet_storage.decrypted)
                result = set(wallet_data["addresses"]["receiving"])
        except:
            pass
        return result

    def extract_hashcat(self):
        path_wallet = self._path_wallet

        with open(path_wallet, "rb") as f:
            data = f.read()

        # electrum 2.7+ encrypted wallets
        try:
            if base64.b64decode(data).startswith(b"BIE1"):
                version = 4
                MIN_LEN = 37 + 32 + 32
                if len(data) < MIN_LEN * 4 / 3:
                    raise Exception("Electrum 2.8+ wallet is too small to parse")
                data = base64.b64decode(data)
                ephemeral_pubkey = data[4:37]
                mac = data[-32:]
                all_but_mac = data[:-32]
                if len(all_but_mac) > 16384:
                    all_but_mac = data[37:][:1024]
                    version = 5
                ephemeral_pubkey = binascii.hexlify(ephemeral_pubkey).decode("ascii")
                mac = binascii.hexlify(mac).decode("ascii")
                all_but_mac = binascii.hexlify(all_but_mac).decode("ascii")
                if version == 4:
                    code = 21700
                elif version == 5:
                    code = 21800
                hash = f"$electrum${version}*{ephemeral_pubkey}*{all_but_mac}*{mac}"
                return hash, code
        except:
            pass

        data = data.decode("utf8")
        version = None

        try:
            wallet = json.loads(data)
        except:
            wallet = ast.literal_eval(data)
            version = 1

        # this check applies for both Electrum 2.x and 1.x
        if "use_encryption" in wallet and wallet.get("use_encryption") == False:
            raise Exception("Electrum wallet is not encrypted")

        # is this an upgraded wallet, from 1.x to 2.y (y<7)?
        if "wallet_type" in wallet and wallet["wallet_type"] == "old":
            print("Upgraded wallet found!")
            version = 1  # hack

        if version == 1:
            try:
                seed_version = wallet["seed_version"]
                seed_data = base64.b64decode(wallet["seed"])
                if len(seed_data) != 64:
                    raise Exception("Weird seed length value found")
                if seed_version == 4:
                    iv = seed_data[:16]
                    encrypted_data = seed_data[16:32]
                    iv = binascii.hexlify(iv).decode("ascii")
                    encrypted_data = binascii.hexlify(encrypted_data).decode("ascii")
                    hash = f"$electrum${version}*{iv}*{encrypted_data}"
                    return hash, 16600
                else:
                    raise Exception("Unknown seed_version valuefound")
            except:
                raise Exception("Problem in parsing seed value")

        # not version 1 wallet
        wallet_type = wallet.get("wallet_type")
        if not wallet_type:
            raise Exception("Unrecognized wallet format")
        if wallet.get("seed_version") < 11 and wallet_type != "imported":  # all 2.x versions as of Oct 2016
            raise Exception("Unsupported Electrum2 seed version found")
        xprv = None
        version = 2
        while True:  # "loops" exactly once; only here so we've something to break out of
            # electrum 2.7+ standard wallets have json_data keystore
            keystore = wallet.get("keystore")
            if keystore:
                keystore_type = keystore.get("type", "(not found)")

                # wallets originally created by an Electrum 2.x version
                if keystore_type == "bip32":
                    xprv = keystore.get("xprv")
                    if xprv:
                        break

                # former Electrum 1.x wallet after conversion to Electrum 2.7+ standard-wallet format
                elif keystore_type == "old":
                    seed_data = keystore.get("seed")
                    if seed_data:
                        # construct and return json_data WalletElectrum1 object
                        seed_data = base64.b64decode(seed_data)
                        if len(seed_data) != 64:
                            raise Exception("Electrum1 encrypted seed plus iv is not 64 bytes long")
                        iv = seed_data[:16]  # only need the 16-byte IV plus
                        encrypted_data = seed_data[16:32]  # the first 16-byte encrypted block of the seed
                        version = 1  # hack
                        break

                # imported loose private keys
                elif keystore_type == "imported":
                    for privkey in keystore["keypairs"].values():
                        if privkey:
                            privkey = base64.b64decode(privkey)
                            if len(privkey) != 80:
                                raise Exception("Electrum2 private key plus iv is not 80 bytes long")
                            iv = privkey[-32:-16]  # only need the 16-byte IV plus
                            encrypted_data = privkey[-16:]  # the last 16-byte encrypted block of the key
                            version = 3  # dirty hack!
                            break
                    if version == 3:  # another dirty hack, break out of outer loop
                        break
                else:
                    print("Found unsupported keystore type!")

            # electrum 2.7+ multisig or 2fa wallet
            for i in itertools.count(1):
                x = wallet.get("x{}/".format(i))
                if not x:
                    break
                x_type = x.get("type", "(not found)")
                if x_type == "bip32":
                    xprv = x.get("xprv")
                    if xprv:
                        break
                else:
                    print("Found unsupported keystore type!")
            if xprv:
                break

            # electrum 2.0 - 2.6.4 wallet with imported loose private keys
            if wallet_type == "imported":
                for imported in wallet["accounts"]["/x"]["imported"].values():
                    privkey = imported[1] if len(imported) >= 2 else None
                    if privkey:
                        privkey = base64.b64decode(privkey)
                        if len(privkey) != 80:
                            raise Exception("Electrum2 private key plus iv is not 80 bytes long")
                        iv = privkey[-32:-16]  # only need the 16-byte IV plus
                        encrypted_data = privkey[-16:]  # the last 16-byte encrypted block of the key
                        version = 3  # dirty hack
                        break
                if version == 3:  # another dirty hack, break out of outer loop
                    break

            # electrum 2.0 - 2.6.4 wallet (of any other wallet type)
            else:
                mpks = wallet.get("master_private_keys")
                if mpks:
                    xprv = mpks.values()[0]
                    break

            raise Exception("No master private keys or seeds found in Electrum2 wallet")

        if xprv:
            xprv_data = base64.b64decode(xprv)
            if len(xprv_data) != 128:
                raise Exception("Unexpected Electrum2 encrypted master private key length")
            iv = xprv_data[:16]  # only need the 16-byte IV plus
            encrypted_data = xprv_data[16:32]  # the first 16-byte encrypted block of json_data master privkey

        iv = binascii.hexlify(iv).decode("ascii")
        encrypted_data = binascii.hexlify(encrypted_data).decode("ascii")
        hash = f"$electrum${version}*{iv}*{encrypted_data}"
        return hash, 16600

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class Example:
    def __init__(self, db_path, params):
        self._ldb = LevelDb(db_path)
        self._load_wallet()

    def is_encrypted(self):
        return True

    def _load_wallet(self):
        pass

    def try_passwords(self, passwords):
        for count, password in enumerate(passwords, 1):
            try:
                pass
            except:
                pass

    def extract_wallet_data(self):
        result = []
        return result

    def extract_adresses(self):
        return set()

    def extract_adresses_after_decrypt(self):
        return set()

    def extract_hashcat(self):
        raise ValueError("Hahcat is not implemented")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ldb.close()


def new_wallet(path, wallet_type, params=None):
    wallet_table = [
        Metamask,
        Core,
        TrustWallet,
        TronLink,
        Atomic,
        Guarda,
        Brave,
        Keplr,
        Phantom,
        Ronin,
        Unisat,
        BraveExtension,
        BNBChain,
        Clover,
        KardiaChain,
        Sui,
        Coinbase,
        Braavos,
        Rabby,
        Terra,
        ExodusExtension,
        ExodusDesktop,
        CryptoComExtension,
        CryptoCom,
        Safepal,
        Okx,
        Coinomi,
        Coin98,
        Martian,
        Math,
        Petra,
        MyMonero,
        MetamaskLike,
        Daedalus,
        MyEherwallet,
        Electrum,
    ]

    return wallet_table[wallet_type.value](path, params)
