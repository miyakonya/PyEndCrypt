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
from .secure_memory import clear, clear_key
import gc
from secrets import token_bytes
from .exceptions import *
import struct
import time

class CryptoUtils:
    def __init__(self):
        self.TIMEOUT = 300   # 5分钟
        self._session_root_key = None
        self._session_private_key = None
        self._session_public_key = None
        self._session_peer_public = None
        self._session_seq_limit = 0

    def generate_keypair(self):
        """
        生成 临时密钥对
        :return: 密钥对
        """
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return private_key, public_bytes

    def init_session(self, peer_public_key: bytes) -> tuple:
        """
        初始化会话，生成根密钥
        :param peer_public_key: 对方公钥
        :return: (私钥, 公钥)
        """
        private_key, public_bytes = self.generate_keypair()
        shared_key = self.derive_shared_key(private_key, peer_public_key)
        root_key = self.shared_key_derive_aes_key(shared_key, b"session_root")
        self._session_root_key = root_key
        self._session_private_key = private_key
        self._session_public_key = public_bytes
        self._session_peer_public = peer_public_key
        self._session_seq_limit = 5
        return private_key, public_bytes

    def refresh_session(self, peer_public_key: bytes) -> tuple:
        """
        刷新会话根密钥
        :param peer_public_key: 对方的公钥
        :return: (私钥, 公钥)
        """
        seq = self._session_seq_limit
        self.clear_session()
        self._session_seq_limit = seq
        private_key, public_key = self.generate_keypair()
        shared_key = self.derive_shared_key(private_key, peer_public_key)
        root_key = self.shared_key_derive_aes_key(shared_key, b"session_root")
        self._session_root_key = root_key
        self._session_private_key = private_key
        self._session_public_key = public_key
        self._session_peer_public = peer_public_key

        return private_key, public_key

    def derive_message_key(self, seq: int) -> bytes:
        """
        从根密钥派生消息密钥
        :param seq: 序列号
        :return: 32字节的消息密钥
        """
        if self._session_root_key is None:
            raise Exception("会话未初始化")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"message_salt",
            info=struct.pack("!I", seq),
            backend=default_backend()
        )
        message_key = hkdf.derive(self._session_root_key)
        return message_key

    def derive_shared_key(self, private_key, peer_public_bytes: bytes) -> bytes:
        """从公钥派生出共享密钥"""
        peer_public = X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_key = private_key.exchange(peer_public)
        return shared_key

    def shared_key_derive_aes_key(self, shared_key: bytes, salt: bytes) -> bytes:
        """从共享密钥中派生出 AES 密钥"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"aes_key",
            backend=default_backend()
        )
        return hkdf.derive(shared_key)

    def _pack(self, data: bytes, seq: int) -> bytes:
        """
        将8字节时间戳和4字节序列号打包进数据中
        :param data: 需要打包的数据
        :return: 打包好的数据
        """
        timestamp = int(time.time())
        timestamp_byte = struct.pack("!Q", timestamp)   # 8字节时间戳
        seq_bytes = struct.pack("!I", seq)  # 4字节序列号
        return timestamp_byte + seq_bytes + data

    def _unpack(self, data: bytes):
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

    def _verify(self, timestamp: int, seq: int, data_seq: int, window=300) -> bool:
        """
        数据校验
        :param timestamp: 时间戳
        :param seq: 序列号
        :param data_seq: 数据内的序列号
        :param window: 时间戳窗口有效期
        :return: 校验是否成功
        """
        current_time = int(time.time())
        diff = current_time - timestamp
        if seq != data_seq:
            raise ReplayAttackError("序列号校验失败！可能存在重放攻击！")
        if diff > window:
            raise ReplayAttackError(f"时间戳验证失败！时间差:{diff}秒")
        return True

    def aes_encrypt(self, peer_public_key: bytes, data: bytes, seq: int) -> bytes:
        """
        使用 AES 密钥加密数据
        :param peer_public_key: 对方的 x25519 公钥
        :param data: 要加密的数据
        :param seq: 序列号
        :return: 已加密的数据(密文已包含tag)
        """

        if (self._session_root_key is None or
        self._session_peer_public != peer_public_key):
            _, public_key = self.init_session(peer_public_key)
        elif seq > self._session_seq_limit:
            _, public_key = self.refresh_session(peer_public_key)
            self._session_seq_limit += 5
        else:
            public_key = self._session_public_key
        nonce = token_bytes(12)
        aes_key = bytearray(self.derive_message_key(seq))
        try:
            packed_data = self._pack(data, seq)
            aesgcm = AESGCM(aes_key)
            ciphertext = aesgcm.encrypt(nonce, packed_data, None)
            return nonce + public_key + ciphertext
        finally:
            clear(aes_key)
            del aes_key

    def aes_decrypt(self, data: bytes, seq: int, private_key: X25519PrivateKey) -> bytes:
        """
        使用 AES 密钥解密数据
        :param data: 加密的数据
        :param seq: 序列号
        :param private_key: x25519 私钥
        :return: 已解密的数据
        """
        # 从数据中分离nonce、公钥和密文
        nonce = data[:12]
        public_key = data[12:44]
        encrypted_data = data[44:]
        # 重新生成 AES 密钥
        shared_key = self.derive_shared_key(private_key, public_key)
        root_key = self.shared_key_derive_aes_key(shared_key, b"session_root")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"message_salt",
            info=struct.pack("!I", seq),
            backend=default_backend()
        )
        aes_key = bytearray(hkdf.derive(root_key))
        try:
            aesgcm = AESGCM(aes_key)
            # 这里会自动验证tag
            ciphertext = aesgcm.decrypt(nonce, encrypted_data, None)
        except Exception as e:
            raise DecryptionError(f"AES-GCM 认证失败，数据可能被篡改: {e}") from e
        finally:
            clear(shared_key)
            clear(root_key)
            clear(aes_key)
        timestamp, data, data_seq = self._unpack(ciphertext)
        self._verify(timestamp, seq, data_seq)
        return data

    def clear_session(self):
        """清除会话密钥"""
        if self._session_root_key:
            clear(self._session_root_key)
        if self._session_private_key:
            clear_key(self._session_private_key)
        if self._session_public_key:
            clear(self._session_public_key)
        if self._session_peer_public:
            clear(self._session_peer_public)

        self._session_root_key = None
        self._session_private_key = None
        self._session_public_key = None
        self._session_peer_public = None
        self._session_seq_limit = 0
        gc.collect()
        gc.collect()