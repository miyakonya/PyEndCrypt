# coding: UTF-8
# Python 3.10.6
# crypto_utils.py - 加密工具模块

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class CryptoUtils:
    """加密工具类"""

    @staticmethod
    def generate_rsa_keypair():
        """生成 RSA 密钥对（服务器端使用）"""
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    @staticmethod
    def generate_aes_key():
        """生成 AES 密钥（客户端使用）"""
        return get_random_bytes(32)  # 256位

    @staticmethod
    def rsa_encrypt(public_key, data):
        """使用 RSA 公钥加密数据"""
        rsa_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.encrypt(data)

    @staticmethod
    def rsa_decrypt(private_key, encrypted_data):
        """使用 RSA 私钥解密数据"""
        rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.decrypt(encrypted_data)

    @staticmethod
    def aes_encrypt(aes_key, data):
        """AES 加密数据（CBC 模式），返回 iv + 加密数据"""
        if isinstance(data, str):
            data = data.encode('utf-8')

        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        return iv + encrypted

    @staticmethod
    def aes_decrypt(aes_key, encrypted_data):
        """AES 解密数据，输入 iv + 加密数据"""
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        return unpad(decrypted_padded, AES.block_size)