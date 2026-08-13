# coding: UTF-8
# Python 3.10.6

"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from ecies import encrypt, decrypt
from ecies.keys import PrivateKey
import struct
import time

class CryptoUtils:
    """加密工具类，所有的加密和解密逻辑都在这里"""
    TIMEOUT = 300   # 5分钟
    @staticmethod
    def generate_ecc_keypair():
        """
        生成 ECC 密钥对
        :return: ECC 密钥对
        """
        sk = PrivateKey(curve="secp256k1")
        return sk.to_hex(), sk.public_key.to_hex()

    @staticmethod
    def ecc_encrypt(public_key_hex: str, aes_key: bytes) -> bytes:
        """用服务器公钥加密 AES 密钥"""
        return encrypt(public_key_hex, aes_key)

    @staticmethod
    def ecc_decrypt(private_key_hex: str, encrypted_data: bytes) -> bytes:
        """用私钥解密得到 AES 密钥"""
        return decrypt(private_key_hex, encrypted_data)

    @staticmethod
    def generate_aes_key() -> bytes:
        """
        生成 AES 密钥
        :return: 256位AES密钥
        """
        return get_random_bytes(32)

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
            raise Exception("数据太短，无法提取时间戳")

        timestamp_bytes = data[:8]
        seq_bytes = data[8:12]
        timestamp = struct.unpack("!Q", timestamp_bytes)[0]
        data_seq = struct.unpack("!I", seq_bytes)[0]
        rdata = data[12:]
        return timestamp, rdata, data_seq

    @staticmethod
    def _verify(timestamp: int, seq: int, data_seq: int, window=TIMEOUT):
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
            raise Exception("序列号校验失败！可能存在重放攻击！")
        if diff > window:
            raise Exception(f"时间戳验证失败！时间差:{diff}秒")
        return True

    @staticmethod
    def aes_encrypt(aes_key: bytes, data: bytes, seq: int):
        """
        使用 AES 私钥加密数据
        :param aes_key: AES 私钥
        :param data: 要加密的数据
        :param seq: 序列号
        :return: 已加密的数据
        """
        nonce = get_random_bytes(12)
        packed_data = CryptoUtils._pack(data, seq)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        cipher_text, tag = cipher.encrypt_and_digest(packed_data)
        return nonce + cipher_text + tag

    @staticmethod
    def aes_decrypt(aes_key: bytes, data: bytes, seq: int) -> bytes:
        """
        使用 AES 私钥解密数据
        :param aes_key: AES 私钥
        :param data: 加密的数据
        :param seq: 序列号
        :return: 已解密的数据
        """
        # 从数据中分离nonce和tag
        nonce = data[:12]
        tag = data[-16:]
        encrypted_data = data[12:-16]
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        try:
            cipher_text = cipher.decrypt_and_verify(encrypted_data, tag)
            timestamp, data, data_seq = CryptoUtils._unpack(cipher_text)
            if CryptoUtils._verify(timestamp, seq, data_seq):
                return data
            else:
                raise Exception("解密失败")
        except BaseException as e:
            raise Exception("AES-GCM 认证失败，数据可能被篡改:", e)
