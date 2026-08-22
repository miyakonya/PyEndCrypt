"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

# coding: UTF-8
# Python 3.14.7

import socket

from tools.NetworkBase import NetworkBase
from tools.CryptoUtils import CryptoUtils
from tools.Logger import Logger
from tools.SSLBuilder import Builder
from shutil import rmtree
import os
import gc

class Client(NetworkBase, Builder):
    def __init__(self, host: str,
                 port: int,
                 ca_cert: str,
                 padding: int = 0,
                 encoding: str = "utf-8"):
        """
        创建客户端
        :param host: 主机
        :param port: 端口
        :param ca_cert: 客户端证书文件
        :param padding: 设定数据包填充级别
        :param encoding: 编码格式
        """
        NetworkBase.__init__(self, padding, encoding)
        self.logger = Logger(__name__).getLogger()
        self.ca_cert = ca_cert
        self.ssl_sock = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_cert = None
        self.client_key = None
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

    def _handshake_ssl(self):
        """SSL 连接上的加密握手（直接使用 ssl_sock）"""
        self.logger.info("开始 SSL 加密握手")
        private_key, client_public_bytes = CryptoUtils.generate_x25519_keypair()
        self.logger.info(f"生成 X25519 临时公钥，长度{len(client_public_bytes)}字节")

        # 直接通过 ssl_sock 发送公钥（不加长度头）
        self.ssl_sock.sendall(client_public_bytes)
        self.logger.info("发送临时公钥给服务器")

        # 直接接收 32 字节公钥
        server_public_bytes = self.ssl_sock.recv(32)
        if not server_public_bytes or len(server_public_bytes) != 32:
            raise Exception("接收服务器临时公钥失败")
        self.logger.info(f"接收到服务器临时公钥，长度{len(server_public_bytes)}字节")

        shared_key = CryptoUtils.x25519_derive_shared_key(private_key, server_public_bytes)
        self.aes_key = CryptoUtils.shared_key_derive_aes_key(shared_key)
        self.logger.info(f"AES 密钥派生成功，共{len(self.aes_key)}字节")
        del private_key

        # 发送确认
        self.ssl_sock.sendall(b"Client Hello")
        response = self.ssl_sock.recv(12)  # "Server Hello" 是 12 字节
        if response == b"Server Hello":
            self.handshake_done = True
            self.logger.info("SSL 握手成功，加密通信建立")
        else:
            raise Exception("握手失败")

    def connect(self):
        # 暂时使用普通套接字连接服务端获取证书密钥
        self.sock.connect((self.host, self.port))
        self.logger.info("连接成功")
        self._handshake()
        self.client_key = self.receive()
        self.client_cert = self.receive()
        if not self.client_cert or not self.client_key:
            raise Exception("无法接收到证书密钥")
        self.logger.info(f"密钥接收完毕，共{len(self.client_key)}字节")
        self.logger.info(f"证书接收完毕，共{len(self.client_cert)}字节")
        os.mkdir("tmp_cert_key")
        with open("tmp_cert_key/client.key", "w+") as kw:
            kw.write(self.client_key)
        with open("tmp_cert_key/client.crt", "w+") as cw:
            cw.write(self.client_cert)
        if not self.client_cert or not self.client_key:
            raise Exception("无法接收到证书和密钥")
        # 初始化 SSL 构建器
        Builder.__init__(self,
                         "tmp_cert_key/client.crt",
                         "tmp_cert_key/client.key",
                         self.ca_cert,
                         False)
        # 删除临时目录
        rmtree("tmp_cert_key")
        self.sock.close()
        self.sock = None

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 开始使用 SSL 套接字进行正式通信
        self.ssl_sock = self.context.wrap_socket(self.sock, server_hostname=self.host)
        self.ssl_sock.settimeout(300)
        self.ssl_sock.connect((self.host, self.port))
        # self.sock = None
        self.logger.info("SSL连接成功")
        self._handshake_ssl()
        self.logger.info("预先验证全部完成")

    def send(self, data):
        if not self.handshake_done or not self.aes_key:
            raise Exception("没有完成加密握手")
        if isinstance(data, str):
            data = data.encode(self.encoding)
        elif isinstance(data, bytes):
            pass
        else:
            data = str(data).encode(self.encoding)
        if self.padding != 0:
            data = self._add_padding(data)
        edata = CryptoUtils.aes_encrypt(self.aes_key, data, self.seq)
        # 发送已加密的数据
        self._send_raw(edata)
        self.logger.info(f"当前序列号: {self.seq}")
        self.logger.info(f"[Client]->[Server]: 发送{len(data)}字节")
        self.seq += 1

    def receive(self):
        if not self.handshake_done or not self.aes_key:
            raise Exception("没有完成加密握手")
        raw_data = self._recv_raw()
        try:
            data = CryptoUtils.aes_decrypt(self.aes_key, raw_data, self.seq)
            if self.padding != 0:
                data = self._remove_padding(data)
            self.logger.info(f"当前序列号: {self.seq}")
            self.logger.info(f"[Server]->[Client]: 接收{len(data)}字节")
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
