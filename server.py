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
from tools.exceptions import HandshakeError
import gc
class Server(NetworkBase, Builder):
    def __init__(self, host: str,
                 port: int,
                 server_cert: str,
                 server_key: str,
                 ca_cert:str,
                 ca_key: str,
                 asy_mod: str,
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
        :param asy_mod: 非对称加密算法
        :param padding: 数据包填充级别
        :param encoding: 编码格式
        """
        NetworkBase.__init__(self, padding, encoding)
        Builder.__init__(self, server_cert, server_key, ca_cert, True)
        self.logger = Logger(__name__).getLogger()
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_sock.bind((host, port))
        self.listen_sock.listen(1)
        self.conn = None
        self.addr = None
        self.aes_key = None
        self.handshake_done = False
        self.seq = 1
        self.encoding = encoding
        self.padding = padding
        self.ca_key = ca_key
        self.host = host
        self.port = port
        self.server_cert = server_cert
        self.server_key = server_key
        self.asy_mod = asy_mod
        if self.asy_mod not in ["kyber", "x25519"]:
            self.logger.error("不支持的非对称加密算法")
            raise Exception("不支持的非对称加密算法")

    def _negotiate(self):
        """预先协商"""
        self.logger.info("开始和客户端协商")
        self._send_raw(self.encoding.encode("utf-8"))
        self._send_raw(self.asy_mod)
        self._send_raw(self.padding)
        response = self._recv_raw().decode(self.encoding)
        if response == "OK":
            self.logger.info(f"协商完毕，非对称加密算法: {self.asy_mod}\t填充方式: {self.encoding}\t编码格式: {self.padding}")
        else:
            self.logger.error("协商失败")
            raise ConnectionError("协商失败")

    def _handshake(self):
        """加密握手实现"""
        try:
            self.logger.info("开始加密握手")
            salt = CryptoUtils.generate_salt()
            # 每次连接单独生成新的临时公私钥
            if self.asy_mod == "x25519":
                private_key, public_key = CryptoUtils.generate_x25519_keypair()
                client_public_bytes = self._recv_raw()
                if not client_public_bytes or len(client_public_bytes) != 32:
                    self.logger.error("接收客户端临时公钥失败")
                    raise HandshakeError("接收客户端临时公钥失败")
                self.logger.info(f"接收到客户端临时公钥，长度{len(client_public_bytes)}字节")
                self._send_raw(public_key)
                self._send_raw(salt)
                self.logger.info("发送临时公钥给客户端")
                # 根据临时私钥和客户端公钥派生出共享密钥
                shared_key = CryptoUtils.x25519_derive_shared_key(
                    private_key,
                    client_public_bytes
                )
            else:
                public_key, private_key = CryptoUtils.generate_kyber_keypair()
                self._send_raw(public_key)
                self._send_raw(salt)
                self.logger.info(f"发送 kyber 公钥给客户端，长度{len(public_key)}字节")
                ciphertext = self._recv_raw()
                self.logger.info(f"接收到客户端的密文，长度{len(ciphertext)}字节")
                shared_key = CryptoUtils.decaps(private_key, ciphertext)
            # 根据公钥密钥派生出 AES 密钥
            self.aes_key = CryptoUtils.shared_key_derive_aes_key(shared_key, salt)
            self.logger.info(f"AES 密钥派生成功，共{len(self.aes_key)}字节")
            response = self._recv_raw()
            if response == b"Client Hello":
                self._send_raw(b"Server Hello")
                self.handshake_done = True
                self.logger.info("握手成功，加密通信建立")
            else:
                self.logger.error("握手失败")
                raise HandshakeError("握手失败")
        except Exception as e:
            self.logger.error(f"握手失败: {e}")
            raise HandshakeError(f"握手失败: {e}") from e

    def accept(self):
        self.logger.info("服务器启动，等待客户端连接")
        # 暂时使用普通套接字给客户端发送证书密钥文件
        self.conn, self.addr = self.listen_sock.accept()
        self.logger.info(f"{self.addr[0]}:{self.addr[1]} 连接到本服务器")
        self.sock = self.conn
        self._negotiate()
        self.logger.info("===== 预先握手开始 =====")
        self._handshake()
        self.logger.info("===== 预先握手结束 =====")
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
        self.sock = None    # 设为None，以便父类能获取正确的 SSL 套接字
        self.conn, self.addr = self.listen_sock.accept()
        self.ssl_sock = self.context.wrap_socket(self.conn, server_side=True)
        self.logger.info("SSL 加密完毕")
        self.logger.info("===== 端到端加密握手开始 =====")
        self._handshake()
        self.logger.info("===== 端到端加密握手结束 =====")
        self.logger.info("===== 预先验证全部完成 =====")

    def send(self, data):
        if not self.handshake_done or not self.aes_key:
            raise HandshakeError("没有完成加密握手")
        if not isinstance(data, bytes):
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
            self.logger.error("没有完成加密握手")
            raise HandshakeError("没有完成加密握手")
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
            self.logger.error("服务端发送了不正确的数据包: %s", e)
            return ""#数据包格式不对哦，宝宝，只能return下""了

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
