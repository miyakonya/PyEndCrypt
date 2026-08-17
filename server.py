# encoding: UTF-8
# Python 3.10.6

"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

import socket
from tools.NetworkBase import NetworkBase
from tools.crypto_utils import CryptoUtils
import gc
from tools.Logger import Logger

class Server(NetworkBase):
    def __init__(self, host: str,
                 port: int,
                 certfile: str,
                 ssl_key: str,
                 ca_file:str,
                 padding: int = 0,
                 encoding: str = "utf-8"):
        """
        创建服务端
        :param host: 主机
        :param port: 端口
        :param certfile: 服务端证书文件
        :param ssl_key: 服务端私钥文件
        :param ca_file: CA证书文件
        :param padding: 设定数据包填充级别
        :param encoding: 编码格式
        """
        super().__init__(certfile,
                         ssl_key,
                         True,
                         ca_file,
                         padding,
                         encoding)
        self.logger = Logger(__name__).getLogger()
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.bind((host, port))
        self.listen_sock.listen(1)
        self.ssl_sock = self.context.wrap_socket(self.listen_sock, server_side=True)
        self.conn = None
        self.addr = None
        self.aes_key = None
        self.handshake_done = False
        self.seq = 1
        self.encoding = encoding

    def _handshake(self):
        """加密握手实现"""
        self.logger.info("开始加密握手")
        # 每次连接单独生成新的临时公私钥
        private_key, public_key = CryptoUtils.generate_x25519_keypair()
        client_public_bytes = self._recv_raw()
        if not client_public_bytes or len(client_public_bytes) != 32:
            raise Exception("接收客户端临时公钥失败")
        try:
            self.logger.info(f"接收到客户端临时公钥，长度{len(client_public_bytes)}字节")
            self._send_raw(public_key)
            self.logger.info("发送临时公钥给客户端")
            # 根据临时私钥和客户端公钥派生出共享密钥
            shared_key = CryptoUtils.x25519_derive_shared_key(
                private_key,
                client_public_bytes
            )
            # 根据公钥密钥派生出 AES 密钥
            self.aes_key = CryptoUtils.shared_key_derive_aes_key(shared_key)
            self.logger.info(f"AES 密钥派生成功，共{len(self.aes_key)}字节")
            del private_key
            response = self._recv_raw()
            if response == b"Client Hello":
                self._send_raw(b"Server Hello")
                self.handshake_done = True
                self.logger.info("握手成功，加密通信建立")
            else:
                raise Exception("握手失败")
        except Exception as e:
            self.logger.error(f"解密 AES 密钥失败:{e}")

    def accept(self):
        self.logger.info("服务器启动，等待客户端连接")
        self.conn, self.addr = self.ssl_sock.accept()
        self.ssl_sock = self.conn
        self.logger.info(f"{self.addr[0]}:{self.addr[1]} 连接到本服务器")
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
