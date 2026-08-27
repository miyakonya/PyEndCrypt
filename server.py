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
        self.handshake_done = False
        self.seq = 1
        self.encoding = encoding
        self.padding = padding
        self.ca_key = ca_key
        self.host = host
        self.port = port
        self.server_cert = server_cert
        self.server_key = server_key
        self.client_public_key = None
        self.private_key = None
        self.pending_refresh = False
        self.is_refreshing = False

    def _negotiate(self):
        """预先协商"""
        self.logger.info("开始和客户端协商")
        self._send_raw(self.encoding.encode("utf-8"))
        self._send_raw(self.padding)
        response = self._recv_raw().decode(self.encoding)
        if response == "OK":
            self.logger.info(f"协商完毕，填充方式: {self.encoding}\t编码格式: {self.padding}")
        else:
            self.logger.error("协商失败")
            raise ConnectionError("协商失败")

    def _handshake(self):
        """加密握手实现"""
        try:
            self.logger.info("开始加密握手")
            self.private_key, public_key = CryptoUtils.generate_keypair()
            self.logger.info(f"生成临时公钥，长度{len(public_key)}字节")
            self.client_public_key = self._recv_raw()
            if not self.client_public_key or len(self.client_public_key) != 32:
                self.logger.error("接收客户端临时公钥失败")
                raise HandshakeError("接收客户端临时公钥失败")
            self.logger.info(f"接收到客户端临时公钥，长度{len(self.client_public_key)}字节")
            self._send_raw(public_key)
            self.logger.info("发送临时公钥给客户端")
            CryptoUtils.init_session(self.client_public_key)
            self.logger.info("初始化会话完毕")
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

    def _refresh_keypair(self):
        """刷新会话根密钥"""
        if self.is_refreshing:
            self.logger.warning("密钥刷新进行中，跳过")
            return
        self.is_refreshing = True
        try:
            self.logger.info("开始刷新会话根密钥")
            CryptoUtils.refresh_session(self.client_public_key)
            CryptoUtils._session_seq_limit += 5
            self.pending_refresh = False
        except Exception as e:
            self.logger.error(f"密钥刷新失败: {e}")
            raise
        finally:
            self.is_refreshing = False

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
        if not self.handshake_done:
            raise HandshakeError("没有完成加密握手")
        if self.seq > CryptoUtils._session_seq_limit and not self.is_refreshing:
            self.pending_refresh = True
        if self.pending_refresh and not self.is_refreshing:
            self.logger.info("执行待处理的密钥刷新")
            self._refresh_keypair()
            self.pending_refresh = False
        if not isinstance(data, bytes):
            data = str(data).encode(self.encoding)
        if self.padding != 0:
            data = self._add_padding(data)
        edata = CryptoUtils.aes_encrypt(self.client_public_key, data, self.seq)
        self._send_raw(edata)
        self.logger.info(f"当前序列号: {self.seq}")
        self.logger.info(f"[Server]->[Client]: 发送{len(data)}字节")
        self.seq += 1

    def receive(self):
        if not self.handshake_done:
            self.logger.error("没有完成加密握手")
            raise HandshakeError("没有完成加密握手")
        if self.seq > CryptoUtils._session_seq_limit and not self.is_refreshing:
            self.pending_refresh = True
        raw_data = self._recv_raw()
        if raw_data == b"REFRESH_KEY":
            self.logger.info("检测到刷新请求")
            self._send_raw(b"REFRESH_ACK")
            self.logger.info("已发送刷新确认")
            self.logger.info("收到客户端刷新请求")
            CryptoUtils.refresh_session(self.client_public_key)
            CryptoUtils._session_seq_limit += 5
            self.logger.info("密钥刷新完成")
            raw_data = self._recv_raw()
        try:
            data = CryptoUtils.aes_decrypt(raw_data, self.seq, self.private_key)
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
        super().close()
        self.seq = 0
        gc.collect()
        gc.collect()
