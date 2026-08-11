# coding: UTF-8
# Python 3.10.6
# crypto_utils.py - 加密工具模块
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import struct
import time

class CryptoUtils:
    TIMEOUT = 300   # 5分钟
    """加密工具类"""
    @staticmethod
    def generate_rsa_keypair():
        """生成 RSA 密钥对（服务器端使用）"""
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    @staticmethod
    def generate_aes_key() -> bytes:
        """生成 AES 密钥（客户端使用）"""
        return get_random_bytes(16)  # 生成128位密钥

    @staticmethod
    def rsa_encrypt(public_key: bytes, data: bytes) -> bytes:
        """使用 RSA 公钥加密数据"""
        rsa_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.encrypt(data)

    @staticmethod
    def rsa_decrypt(private_key: bytes, encrypted_data: bytes) -> bytes:
        """使用 RSA 私钥解密数据"""
        rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.decrypt(encrypted_data)

    @staticmethod
    def _pack_with_timestamp(data: bytes) -> bytes:
        """添加8位时间戳"""
        timestamp = int(time.time())
        timestamp_byte = struct.pack("!Q", timestamp)
        return timestamp_byte + data

    @staticmethod
    def _unpack_with_timestamp(data: bytes):
        """解包数据"""
        if len(data) < 8:
            raise Exception("数据太短，无法提取时间戳")

        timestamp_bytes = data[:8]
        timestamp = struct.unpack("!Q", timestamp_bytes)[0]
        rdata = data[8:]
        return timestamp, rdata

    @staticmethod
    def _verify_time(timestamp, window=TIMEOUT):
        current_time = int(time.time())
        diff = abs(current_time - timestamp)

        if diff > window:
            raise Exception(f"时间戳验证失败！时间差:{diff}秒")
        return True

    @staticmethod
    def aes_encrypt(aes_key: bytes, data: bytes):
        """使用 AES 私钥加密数据"""
        nonce = get_random_bytes(12)
        packed_data = CryptoUtils._pack_with_timestamp(data)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        cipher_text, tag = cipher.encrypt_and_digest(packed_data)
        return nonce + cipher_text + tag

    @staticmethod
    def aes_decrypt(aes_key: bytes, data: bytes) -> bytes:
        """使用 AES 私钥解密数据"""
        # 从数据中分离nonce和tag
        nonce = data[:12]
        tag = data[-16:]
        encrypted_data = data[12:-16]
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        try:
            cipher_text = cipher.decrypt_and_verify(encrypted_data, tag)
            timestamp, data = CryptoUtils._unpack_with_timestamp(cipher_text)
            if CryptoUtils._verify_time(timestamp):
                return data
        except BaseException as e:
            raise Exception("AES-GCM 认证失败，数据可能被篡改:", e)
