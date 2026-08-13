# encoding: UTF-8
# Python 3.10.6

"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

import socket

from NetworkBase import NetworkBase
from crypto_utils import CryptoUtils
from Crypto.Hash import HMAC, SHA256
import gc

class Client(NetworkBase):
    def __init__(self, host: str, port: int, key_file: str, is_padding: bool = False, encoding: str = "utf-8"):
        super().__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(300)
        self.host = host
        self.port = port
        self.aes_key = None
        self.nonce = None
        self.handshake_done = False
        self.seq = 1
        self.is_padding = is_padding
        self.encoding = encoding
        self.shared_key = None
        self.pub = None
        self.key_file = key_file
        try:
            with open(self.key_file, "rb") as r:
                self.shared_key = bytearray(r.read())
        except FileNotFoundError:
            raise FileNotFoundError("没有找到 PSK 密钥文件")
        if self.shared_key:
            print(f"PSK 密钥读取完毕，共{len(self.shared_key)}字节")
        else:
            raise Exception("PSK 密钥读取失败")

    def _destroyer(self):
        """从内存中销毁 PSK 密钥和 RSA 密钥"""
        if hasattr(self, "shared_key") and self.shared_key is not None:
            self.shared_key[:] = b"\x00" * len(self.shared_key)
            self.shared_key = None
            print("PSK 密钥已从内存中销毁")
        if hasattr(self, "pub"):
            key = getattr(self, "pub")
            if key is not None:
                ba = bytearray(key.encode(self.encoding))
                ba[:] = b"\x00" * len(ba)
                del ba, key
                setattr(self, "pub", None)
        gc.collect()
        gc.collect()
        print("ECC 密钥已全部从内存中销毁")

    def _auth(self):
        if not self.shared_key:
            raise Exception("PSK 密钥读取失败")
        hmac_obj = HMAC.new(self.shared_key, digestmod=SHA256)
        hmac_obj.update(b"Client Hello")
        client_signature = hmac_obj.digest()
        print("认证消息签名完毕，发送给服务端")
        self._send_raw(b"Client Hello")
        self._send_raw(client_signature)
        print("发送完毕")
        response = self._recv_raw()
        if response == b"OK":
            print("PSK 密钥认证通过!")
        else:
            raise Exception("PSK 密钥认证失败！")

    def _handshake(self):
        """建立加密连接"""
        print("开始加密握手")
        self.pub = self._recv_raw().decode()
        if not self.pub:
            raise Exception("公钥接收失败")
        print(f"接收到服务器公钥，长度{len(self.pub)}字节")
        self.aes_key = CryptoUtils.generate_aes_key()
        print(f"生成 AES 密钥，共{len(self.aes_key)}字节")
        eak = CryptoUtils.ecc_encrypt(self.pub, self.aes_key)
        print("发送加密的 AES 密钥")
        self._send_raw(eak)
        self._send_raw(b"Client Hello")
        response = self._recv_raw()
        if response == b"Server Hello":
            self.handshake_done = True
            self._destroyer()
            print("握手成功，加密通信建立")
            print("=" * 30)
        else:
            raise Exception("握手失败")

    def connect(self):
        self.sock.connect((self.host, self.port))
        print("连接成功")
        self._auth()
        self._handshake()

    def send(self, data):
        if not self.handshake_done or not self.aes_key:
            raise Exception("没有完成加密握手")
        if isinstance(data, str):
            data = data.encode(self.encoding)
        elif isinstance(data, bytes):
            pass
        else:
            data = str(data).encode(self.encoding)
        edata = CryptoUtils.aes_encrypt(self.aes_key, data, self.seq)
        # 发送已加密的数据
        self._send_raw(edata)
        self.seq += 1

    def receive(self):
        if not self.handshake_done or not self.aes_key:
            raise Exception("没有完成加密握手")
        raw_data = self._recv_raw()
        try:
            data = CryptoUtils.aes_decrypt(self.aes_key, raw_data, self.seq)
            self.seq += 1
            return data.decode(self.encoding)
        except Exception as e:
            print("服务端发送了不正确的数据包:", e)

    def close(self):
        super().close()
        ba = bytearray(self.aes_key)
        ba[:] = b"\x00" * len(ba)
        del ba
        self.aes_key = None
