"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

"""
加密工具类，所有的加密和解密逻辑都在这里
"""

# coding: UTF-8
# Python 3.14.7

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from kyber_py.ml_kem import ML_KEM_768
from secrets import token_bytes
from .exceptions import *
import struct
import time
import subprocess

class CryptoUtils:
    TIMEOUT = 300   # 5分钟
    @staticmethod
    def generate_x25519_keypair():
        """
        生成 x25519 临时密钥对
        :return: x25519 密钥对
        """
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return private_key, public_bytes
    
    @staticmethod
    def x25519_derive_shared_key(private_key: X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
        """用 X25519 密钥派生出共享密钥"""
        peer_public = X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_key = private_key.exchange(peer_public)
        return shared_key

    @staticmethod
    def generate_kyber_keypair():
        """生成 kyber 密钥对"""
        public_key, private_key = ML_KEM_768.keygen()
        return public_key, private_key

    @staticmethod
    def encaps(public_key: bytes):
        """用 kyber 公钥封装共享密钥"""
        shared_key, ciphertext = ML_KEM_768.encaps(public_key)
        return shared_key, ciphertext

    @staticmethod
    def decaps(private_key: bytes, ciphertext: bytes):
        """用 kyber 私钥解封装共享密钥"""
        return ML_KEM_768.decaps(private_key, ciphertext)

    @staticmethod
    def generate_salt():
        """生成随机256位的随机盐"""
        return token_bytes(32)

    @staticmethod
    def shared_key_derive_aes_key(shared_key: bytes, salt: bytes) -> bytes:
        """从共享密钥中派生出 AES 密钥"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(), 
            length=32, 
            salt=salt, 
            info=b"aes_key", 
            backend=default_backend()
        )
        return hkdf.derive(shared_key)

    @staticmethod
    def _pack(data: bytes, seq: int) -> bytes:
        """
        将8字节时间戳和4字节序列号打包进数据中
        :param data: 需要打包的数据
        :return: 打包好的数据
        """
        timestamp = int(time.time())
        timestamp_byte = struct.pack("!Q", timestamp)   # 8位时间戳
        seq_bytes = struct.pack("!I", seq)  # 4字节序列号
        return timestamp_byte + seq_bytes + data

    @staticmethod
    def _unpack(data: bytes):
        """
        解包数据
        :param data: 需要解包的数据
        :return: 时间戳和原始数据
        """
        if len(data) < 12:
            raise DataFormatError("数据太短，无法提取时间戳")

        timestamp_bytes = data[:8]
        seq_bytes = data[8:12]
        timestamp = struct.unpack("!Q", timestamp_bytes)[0]
        data_seq = struct.unpack("!I", seq_bytes)[0]
        rdata = data[12:]
        return timestamp, rdata, data_seq

    @staticmethod
    def _verify(timestamp: int, seq: int, data_seq: int, window=TIMEOUT) -> bool:
        """
        数据校验
        :param timestamp: 时间戳
        :param seq: 序列号
        :param data_seq: 数据内的序列号
        :param window: 时间戳窗口有效期
        :return: 校验是否成功
        """
        current_time = int(time.time())
        diff = abs(current_time - timestamp)
        if seq != data_seq:
            raise ReplayAttackError("序列号校验失败！可能存在重放攻击！")
        if diff > window:
            raise ReplayAttackError(f"时间戳验证失败！时间差:{diff}秒")
        return True

    @staticmethod
    def aes_encrypt(aes_key: bytes, data: bytes, seq: int) -> bytes:
        """
        使用 AES 密钥加密数据
        :param aes_key: AES 私钥
        :param data: 要加密的数据
        :param seq: 序列号
        :return: 已加密的数据(密文已包含tag)
        """
        nonce = token_bytes(12)
        packed_data = CryptoUtils._pack(data, seq)
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, packed_data, None)
        return nonce + ciphertext

    @staticmethod
    def aes_decrypt(aes_key: bytes, data: bytes, seq: int) -> bytes:
        """
        使用 AES 密钥解密数据
        :param aes_key: AES 私钥
        :param data: 加密的数据
        :param seq: 序列号
        :return: 已解密的数据
        """
        # 从数据中分离nonce和tag
        nonce = data[:12]
        encrypted_data = data[12:]
        try:
            aesgcm = AESGCM(aes_key)
            # 这里会自动验证tag
            ciphertext = aesgcm.decrypt(nonce, encrypted_data, None)
        except Exception as e:
            raise DecryptionError(f"AES-GCM 认证失败，数据可能被篡改: {e}") from e
        timestamp, data, data_seq = CryptoUtils._unpack(ciphertext)
        CryptoUtils._verify(timestamp, seq, data_seq)
        return data
    @staticmethod
    def generate_cert_key(ca_cert: str, ca_key: str):
        """
        生成客户端证书和密钥
        :return: 客户端证书和密钥
        """
        # 生成客户端密钥
        subprocess.run([
            "openssl", "genrsa", "-out", "client.key", "2048"
        ])
        subprocess.run([
            "openssl", "req", "-new", "-key", "client.key",
            "-out", "client.csr", "-subj", "/CN=client"
        ])
        # 生成客户端证书
        subprocess.run([
            "openssl", "x509", "-req", "-days", "365",
            "-in", "client.csr", "-CA", f"{ca_cert}",
            "-CAkey", f"{ca_key}", "-set_serial", "02",
            "-out", "client.crt"
        ])
        with open("client.crt", "r") as cr:
            cert = cr.read()
        with open("client.key", "r") as kr:
            key = kr.read()
        return cert, key