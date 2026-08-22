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
from tools.CredentialProvisioner import Generator
import gc

class Server(NetworkBase, Builder):
    def __init__(self, host: str,
                 port: int,
                 listen: int,
                 server_cert: str,
                 server_key: str,
                 ca_cert:str,
                 ca_key: str,
                 padding: int = 0,
                 encoding: str = "utf-8"):
        """
        创建服务端
        :param host: 主机
        :param port: 端口
        :param server_cert: 服务端证书文件
        :param server_key: 服务端私钥文件
        :param ca_cert: CA 证书文件
        :param ca_key: CA 密钥文件
        :param padding: 设定数据包填充级别
        :param encoding: 编码格式
        """
        NetworkBase.__init__(self, padding, encoding)
        Builder.__init__(self, server_cert, server_key, ca_cert, True)
        self.logger = Logger(__name__).getLogger()
        if listen > 0:
            self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_sock.bind((host, port))
            self.listen_sock.listen(listen)
        else:
            self.listen_sock = None
        self.conn = None
        self.addr = None
        self.aes_key = None
        self.handshake_done = False
        self.seq = 1
        self.encoding = encoding
        self.ca_key = ca_key
        self.host = host
        self.port = port
        self.server_cert = server_cert
        self.server_key = server_key

    def handle_client(self, conn, addr):
        """
        处理已连接的客户端（用于多客户端场景）
        :param conn: 已建立的 socket 连接
        :param addr: 客户端地址
        """
        self.conn = conn
        self.addr = addr
        self.sock = conn

        self.seq = 1
        self.handshake_done = False
        self.aes_key = None

        self.logger.info(f"开始处理客户端 {addr}")

        try:
            self._handshake()
            self.logger.info("准备向客户端发送证书密钥文件")

            g = Generator(self.ca_cert, self.ca_key)
            client_key, path = g.generate_key()
            client_cert = g.generate_cert(path)
            self.send(client_key)
            self.send(client_cert)
            self.logger.info("证书和密钥已发送")

            self.sock.close()
            self.sock = None
            self.conn = None
            self.logger.info("证书分发完成")

            self.logger.info(f"客户端 {addr} 处理完成")
            return self.sock, self.addr

        except Exception as e:
            self.logger.error(f"处理客户端 {addr} 错误: {e}")
            raise

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

    def _handshake_ssl(self):
        """SSL 连接上的加密握手（直接使用 ssl_sock）"""
        self.logger.info("开始 SSL 加密握手")

        # 直接接收 32 字节公钥
        client_public_bytes = self.ssl_sock.recv(32)
        if not client_public_bytes or len(client_public_bytes) != 32:
            raise Exception("接收客户端临时公钥失败")
        self.logger.info(f"接收到客户端临时公钥，长度{len(client_public_bytes)}字节")

        private_key, public_key = CryptoUtils.generate_x25519_keypair()
        self.ssl_sock.sendall(public_key)
        self.logger.info("发送临时公钥给客户端")

        shared_key = CryptoUtils.x25519_derive_shared_key(private_key, client_public_bytes)
        self.aes_key = CryptoUtils.shared_key_derive_aes_key(shared_key)
        self.logger.info(f"AES 密钥派生成功，共{len(self.aes_key)}字节")
        del private_key

        response = self.ssl_sock.recv(12)  # "Client Hello" 是 12 字节
        if response == b"Client Hello":
            self.ssl_sock.sendall(b"Server Hello")
            self.handshake_done = True
            self.logger.info("SSL 握手成功，加密通信建立")
        else:
            raise Exception("握手失败")

    def accept(self):
        self.logger.info("服务器启动，等待客户端连接")
        # 暂时使用普通套接字给客户端发送证书密钥文件
        self.conn, self.addr = self.listen_sock.accept()
        self.logger.info(f"{self.addr[0]}:{self.addr[1]} 连接到本服务器")
        self.sock = self.conn
        self._handshake()
        self.logger.info("准备向客户端发送证书密钥文件")
        g = Generator(self.ca_cert, self.ca_key)
        client_key, path = g.generate_key()
        client_cert = g.generate_cert(path)
        self.send(client_key)
        self.send(client_cert)
        self.logger.info("发送完毕")

        # 关闭普通套接字，开始使用 SSL 套接字进行正式通信
        self.conn.close()
        self.conn = None
        self.sock = None
        self.conn, self.addr = self.listen_sock.accept()
        self.ssl_sock = self.context.wrap_socket(self.conn, server_side=True)
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
        self._send_raw(edata)
        self.logger.info(f"当前序列号: {self.seq}")
        self.logger.info(f"[Server]->[Client]: 发送{len(data)}字节")
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
            self.logger.info(f"[Client]->[Server]: 接收{len(data)}字节")
            self.seq += 1
            return data.decode(self.encoding)
        except Exception as e:
            self.logger.error("服务端发送了不正确的数据包:", e)

    def create_new_instance(self):
        """创建新的 Server 实例（用于多客户端）"""
        return Server(
            host=self.host,
            port=self.port,
            listen=0,  # 不监听
            server_cert=self.server_cert,
            server_key=self.server_key,
            ca_cert=self.ca_cert,
            ca_key=self.ca_key,
            padding=self.padding,
            encoding=self.encoding
        )

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
