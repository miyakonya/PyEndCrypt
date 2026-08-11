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
        """
        生成 RSA 密钥对
        :return: RSA 密钥对
        """
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    @staticmethod
    def generate_aes_key() -> bytes:
        """
        生成 AES 密钥
        :return: 128位AES密钥
        """
        return get_random_bytes(16)

    @staticmethod
    def rsa_encrypt(public_key: bytes, data: bytes) -> bytes:
        """
        使用 RSA 公钥加密数据
        :param public_key: RSA 公钥
        :param data: 原始数据
        :return: 加密数据
        """
        rsa_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.encrypt(data)

    @staticmethod
    def rsa_decrypt(private_key: bytes, encrypted_data: bytes) -> bytes:
        """
        使用 RSA 私钥解密数据
        :param private_key: RSA 私钥
        :param encrypted_data: 加密数据
        :return: 解密数据
        """
        rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.decrypt(encrypted_data)

    @staticmethod
    def _pack_with_timestamp(data: bytes) -> bytes:
        """
        将8位时间戳打包进数据中
        :param data: 需要打包的数据
        :return: 打包好的数据
        """
        timestamp = int(time.time())
        timestamp_byte = struct.pack("!Q", timestamp)   # 8位时间戳
        return timestamp_byte + data

    @staticmethod
    def _unpack_with_timestamp(data: bytes):
        """
        解包数据
        :param data: 需要解包的数据
        :return: 时间戳和原始数据
        """
        if len(data) < 8:
            raise Exception("数据太短，无法提取时间戳")

        timestamp_bytes = data[:8]
        timestamp = struct.unpack("!Q", timestamp_bytes)[0]
        rdata = data[8:]
        return timestamp, rdata

    @staticmethod
    def _verify_time(timestamp, window=TIMEOUT):
        """
        时间戳校验
        :param timestamp: 时间戳
        :param window: 时间戳窗口有效期
        :return: 校验是否成功
        """
        current_time = int(time.time())
        diff = abs(current_time - timestamp)

        if diff > window:
            raise Exception(f"时间戳验证失败！时间差:{diff}秒")
        return True

    @staticmethod
    def aes_encrypt(aes_key: bytes, data: bytes):
        """
        使用 AES 私钥加密数据
        :param aes_key: AES 私钥
        :param data: 要加密的数据
        :return: 已加密的数据
        """
        nonce = get_random_bytes(12)
        packed_data = CryptoUtils._pack_with_timestamp(data)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        cipher_text, tag = cipher.encrypt_and_digest(packed_data)
        return nonce + cipher_text + tag

    @staticmethod
    def aes_decrypt(aes_key: bytes, data: bytes) -> bytes:
        """
        使用 AES 私钥解密数据
        :param aes_key: AES 私钥
        :param data: 加密的数据
        :return: 已解密的数据
        """
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
