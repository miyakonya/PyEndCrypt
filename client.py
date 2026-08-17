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
import gc
from Logger import Logger

class Client(NetworkBase):
    def __init__(self, host: str,
                 port: int,
                 certfile: str,
                 ssl_key: str,
                 ca_file:str,
                 padding: int = 0,
                 encoding: str = "utf-8"):
        """
        创建客户端
        :param host: 主机
        :param port: 端口
        :param certfile: 客户端证书文件
        :param ssl_key: 客户端私钥文件
        :param ca_file: CA证书文件
        :param padding: 设定数据包填充级别
        :param encoding: 编码格式
        """
        super().__init__(certfile,
                         ssl_key,
                         False,
                         ca_file,
                         padding,
                         encoding)
        self.logger = Logger(__name__).getLogger()
        self.ssl_sock = self.context.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=host)
        self.ssl_sock.settimeout(300)
        self.host = host
        self.port = port
        self.aes_key = None
        self.nonce = None
        self.handshake_done = False
        self.seq = 1
        self.encoding = encoding
        self.pub = None

    def _handshake(self):
        """建立加密连接"""
        self.logger.info("开始加密握手")
        private_key, client_public_bytes = CryptoUtils.generate_x25519_keypair()
        self.logger.info(f"生成 X25519 临时公钥，长度{len(client_public_bytes)}字节")
        self._send_raw(client_public_bytes)
        self.logger.info("发送临时公钥给服务器")
        server_public_bytes = self._recv_raw()
        if not server_public_bytes or len(server_public_bytes) != 32:
            raise Exception("接收服务器临时公钥失败")
        self.logger.info(f"接收到服务器临时公钥，长度{len(server_public_bytes)}字节")
        # 根据临时私钥和服务端公钥派生出共享密钥
        shared_key = CryptoUtils.x25519_derive_shared_key(
            private_key,
            server_public_bytes
        )
        # 根据共享密钥派生出 AES 密钥
        self.aes_key = CryptoUtils.shared_key_derive_aes_key(shared_key)
        self.logger.info(f"AES 密钥派生成功，共{len(self.aes_key)}字节")
        del private_key
        self._send_raw(b"Client Hello")
        response = self._recv_raw()
        if response == b"Server Hello":
            self.handshake_done = True
            self.logger.info("握手成功，加密通信建立")
        else:
            raise Exception("握手失败")

    def connect(self):
        self.ssl_sock.connect((self.host, self.port))
        self.logger.info("连接成功")
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
            self.logger.error("服务端发送了不正确的数据包:", e)

    def close(self):
        """销毁 AES 密钥"""
        super().close()
        if self.aes_key:
            ba = bytearray(self.aes_key)
            ba[:] = b"\x00" * len(ba)
            del ba
            self.aes_key = None
        self.seq = 0
        gc.collect()
        gc.collect()
