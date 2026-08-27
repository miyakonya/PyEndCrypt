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
from tools.exceptions import HandshakeError
from shutil import rmtree
import os
import gc

class Client(NetworkBase, Builder):
    def __init__(self, host: str,
                 port: int,
                 ca_cert: str):
        """
        创建客户端
        :param host: 主机
        :param port: 端口
        :param ca_cert: CA 证书文件
        """
        NetworkBase.__init__(self, 0, "utf-8")
        self.logger = Logger(__name__).getLogger()
        self.ca_cert = ca_cert
        self.ssl_sock = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_cert = None
        self.client_key = None
        self.host = host
        self.port = port
        self.nonce = None
        self.handshake_done = False
        self.seq = 1
        self.encoding = None
        self.padding = None
        self.pub = None
        self.asy_mod = None
        self.server_public_key = None
        self.private_key = None
        self.is_refreshing = False
        self.pending_refresh = False

    def _negotiate(self):
        """预先协商"""
        self.logger.info("开始和服务端协商")
        self.encoding = self._recv_raw().decode("utf-8")
        try:
            self.padding = int(self._recv_raw().decode(self.encoding))
        except ValueError:
            self.logger.error("服务端发送的填充方式不正确")
            raise ValueError("服务端发送的填充方式不正确")
        self._send_raw("OK")
        self.logger.info(f"协商完毕，填充方式: {self.padding}\t编码格式: {self.encoding}")

    def _handshake(self):
        """建立加密连接"""
        self.logger.info("开始加密握手")
        self.private_key, public_key = CryptoUtils.generate_keypair()
        self.logger.info(f"生成临时公钥，长度{len(public_key)}字节")
        self._send_raw(public_key)
        self.logger.info("发送临时公钥给服务器")
        self.server_public_key = self._recv_raw()
        if not self.server_public_key or len(self.server_public_key) != 32:
            self.logger.error("接收服务器临时公钥失败")
            raise HandshakeError("接收服务器临时公钥失败")
        self.logger.info(f"接收到服务器临时公钥，长度{len(self.server_public_key)}字节")
        shared_key = CryptoUtils.derive_shared_key(self.private_key, self.server_public_key)
        root_key = CryptoUtils.shared_key_derive_aes_key(shared_key, b"session_root")

        CryptoUtils._session_root_key = root_key
        CryptoUtils._session_private_key = self.private_key
        CryptoUtils._session_public_key = public_key
        CryptoUtils._session_peer_public = self.server_public_key
        CryptoUtils._session_seq_limit = 5
        self.logger.info("初始化会话完毕")
        self._send_raw(b"Client Hello")
        response = self._recv_raw()
        if response == b"Server Hello":
            self.handshake_done = True
            self.logger.info("握手成功，加密通信建立")
        else:
            self.logger.error("握手失败")
            raise HandshakeError("握手失败")

    def connect(self):
        # 暂时使用普通套接字连接服务端获取证书密钥
        self.sock.connect((self.host, self.port))
        self.logger.info("连接成功")
        self._negotiate()
        self.logger.info("===== 预先握手开始 =====")
        self._handshake()
        self.logger.info("===== 预先握手结束 =====")
        self.client_key = self.receive()
        self.client_cert = self.receive()
        if not self.client_cert or not self.client_key:
            raise HandshakeError("无法接收到证书密钥")
        self.logger.info(f"密钥接收完毕，共{len(self.client_key)}字节")
        self.logger.info(f"证书接收完毕，共{len(self.client_cert)}字节")
        os.mkdir("tmp_cert_key")
        with open("tmp_cert_key/client.key", "w+") as kw:
            kw.write(self.client_key)
        with open("tmp_cert_key/client.crt", "w+") as cw:
            cw.write(self.client_cert)
        if not self.client_cert or not self.client_key:
            raise HandshakeError("无法接收到证书和密钥")
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
        self.sock = None    # 设为None，以便父类能获取正确的 SSL 套接字
        self.logger.info("SSL 加密完毕")
        self.logger.info("===== 端到端加密握手开始 =====")
        self._handshake()
        self.logger.info("===== 端到端加密握手结束 =====")
        self.logger.info("===== 预先验证全部完成 =====")

    def _refresh_keypair(self):
        """刷新会话根密钥"""
        if self.is_refreshing:
            self.logger.warning("密钥刷新进行中，跳过")
            return
        self.is_refreshing = True
        try:
            self.logger.info("开始刷新会话根密钥")
            self._send_raw(b"REFRESH_KEY")
            self.logger.info("等待 REFRESH_ACK...")
            response = self._recv_raw()
            self.logger.info("收到响应")
            if response != b"REFRESH_ACK":
                raise Exception(f"服务端未确认刷新: {response[:20]}...")
            CryptoUtils.refresh_session(self.server_public_key)
            CryptoUtils._session_seq_limit += 5
            self.logger.info("密钥刷新完成")
            self.pending_refresh = False
        except Exception as e:
            self.logger.error(f"密钥刷新失败: {e}")
            raise
        finally:
            self.is_refreshing = False

    def send(self, data):
        if not self.handshake_done:
            raise HandshakeError("没有完成加密握手")
        if self.seq > CryptoUtils._session_seq_limit and not self.is_refreshing:
            self.pending_refresh = True
        # 如果有待处理的刷新，先执行刷新
        if self.pending_refresh and not self.is_refreshing:
            self.logger.info("执行待处理的密钥刷新")
            self._refresh_keypair()
            self.pending_refresh = False
        if not isinstance(data, bytes):
            data = str(data).encode(self.encoding)
        if self.padding != 0:
            data = self._add_padding(data)
        edata = CryptoUtils.aes_encrypt(self.server_public_key, data, self.seq)
        # 发送已加密的数据
        self._send_raw(edata)
        self.logger.info(f"当前序列号: {self.seq}")
        self.logger.info(f"[Client]->[Server]: 发送{len(data)}字节")
        self.seq += 1

    def receive(self):
        if not self.handshake_done:
            raise HandshakeError("没有完成加密握手")
        if self.seq > CryptoUtils._session_seq_limit and not self.is_refreshing:
            self.pending_refresh = True
        raw_data = self._recv_raw()
        if raw_data == b"REFRESH_KEY":
            self.logger.info("收到服务端刷新请求")
            self._send_raw(b"REFRESH_ACK")
            CryptoUtils.refresh_session(self.server_public_key)
            CryptoUtils._session_seq_limit += 5
            self.pending_refresh = False
            self.logger.info("密钥刷新完成")
            raw_data = self._recv_raw()
        try:
            data = CryptoUtils.aes_decrypt(raw_data, self.seq, self.private_key)
            if self.padding != 0:
                data = self._remove_padding(data)
            self.logger.info(f"当前序列号: {self.seq}")
            self.logger.info(f"[Server]->[Client]: 接收{len(data)}字节")
            self.seq += 1
            return data.decode(self.encoding)
        except Exception as e:
            self.logger.error(f"服务端发送了不正确的数据包:{e}")
            return ""

    def close(self):
        super().close()
        self.seq = 0
        gc.collect()
        gc.collect()
