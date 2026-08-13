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

class Server(NetworkBase):
    def __init__(self, host: str, port: int, key_file: str, is_padding: bool = False, encoding: str = "utf-8"):
        super().__init__()
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.bind((host, port))
        self.listen_sock.listen(1)
        self.conn = None
        self.addr = None
        self.aes_key = None
        self.handshake_done = False
        self.is_padding = is_padding
        self.private_key, self.pub = CryptoUtils.generate_ecc_keypair()
        self.seq = 1
        self.encoding = encoding
        self.shared_key = None
        self.key_file = key_file
        try:
            with open(key_file, "rb") as r:
                self.shared_key = bytearray(r.read())
        except Exception as e:
            raise Exception("读取 PSK 密钥文件失败:", e)
        if self.shared_key:
            print(f"PSK 密钥读取完毕，共{len(self.shared_key)}字节")
        else:
            raise Exception("PSK 密钥读取失败")
        print("ECC 密钥对生成成功")
        print(f"\t私钥:{len(self.private_key)}字节")
        print(f"\t公钥:{len(self.pub)}字节")

    def _destroyer(self):
        """从内存中销毁 PSK 密钥和 RSA 密钥"""
        if hasattr(self, "shared_key") and self.shared_key is not None:
            self.shared_key[:] = b"\x00" * len(self.shared_key)
            self.shared_key = None
            print("PSK 密钥已从内存中销毁")
        for key_name in ["pub", "private_key"]:
            if hasattr(self, key_name):
                key = getattr(self, key_name)
                if key is not None:
                    ba = bytearray(key.encode(self.encoding))
                    ba[:] = b"\x00" * len(ba)
                    del ba, key
                    setattr(self, key_name, None)
        gc.collect()
        gc.collect()
        print("ECC 密钥已全部从内存中销毁")

    def _auth(self):
        """进行 PSK 密钥认证"""
        if not self.shared_key:
            raise Exception("PSK 密钥读取失败")
        print("开始进行 PSK 密钥认证")
        message = self._recv_raw()
        print("接收到客户端消息")
        client_signature = self._recv_raw()
        print("接收到客户端签名")
        hmac_obj = HMAC.new(self.shared_key, digestmod=SHA256)
        hmac_obj.update(message)
        try:
            hmac_obj.verify(client_signature)
            print("PSK 密钥认证通过!")
            self._send_raw(b"OK")
        except ValueError:
            raise ValueError("PSK 密钥认证失败！")


    def _handshake(self):
        """加密握手实现"""
        print("开始加密握手")
        self._send_raw(self.pub)
        print("公钥已发送")
        ekd = self._recv_raw()
        if ekd is None:
            raise Exception("接收 AES 密钥失败")
        try:
            print("AES 密钥接收完毕")
            self.aes_key = CryptoUtils.ecc_decrypt(self.private_key, ekd)
            print(f"AES 密钥解密成功，共{len(self.aes_key)}字节")
            response = self._recv_raw()
            if response == b"Client Hello":
                self._send_raw(b"Server Hello")
                self.handshake_done = True
                self._destroyer()
                print("握手成功，加密通信建立")
                print("="*30)
            else:
                raise Exception("握手失败")
        except Exception as e:
            print("解密 AES 密钥失败:", e)

    def accept(self):
        print("服务器启动，等待客户端连接")
        self.conn, self.addr = self.listen_sock.accept()
        self.sock = self.conn
        print(f"{self.addr[0]}:{self.addr[1]} 连接到本服务器")
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
