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

from tools.NetworkBase import NetworkBase
from tools.CryptoUtils import CryptoUtils
from tools.Logger import Logger
from tools.exceptions import HandshakeError
from tools.secure_memory import clear, clear_key
from tools.CredentialProvisioner import Generator
import ssl
import gc
import asyncio

class ClientHandler(NetworkBase):
    """客户端处理器"""

    def __init__(self, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter,
                 padding: int, encoding: str,
                 generator: Generator,
                 ssl_context: ssl.SSLContext):
        super().__init__(padding, encoding)
        self.reader: asyncio.StreamReader = reader
        self.writer: asyncio.StreamWriter = writer
        self.generator = generator
        self.ssl_context = ssl_context
        self.logger = Logger(__name__).getLogger()
        self.handshake_done = False
        self.seq = 1
        self.client_public_key = None
        self.private_key = None
        self.pending_refresh = False
        self.is_refreshing = False
        self.is_ssl = False
        self.is_ready = False
        self._closed = False
        self.crypto = CryptoUtils()

    async def _negotiate(self):
        """预先协商"""
        self.logger.info("开始和客户端协商")
        await self._send_raw(self.encoding.encode("utf-8"))
        await self._send_raw(str(self.padding).encode(self.encoding))
        response = (await self._recv_raw()).decode(self.encoding)
        if response == "OK":
            self.logger.info(f"协商完毕，填充方式: {self.padding}\t编码格式: {self.encoding}")
        else:
            self.logger.error("协商失败")
            raise ConnectionError("协商失败")

    async def _handshake(self):
        """加密握手实现"""
        try:
            self.logger.info("开始加密握手")
            self.private_key, public_key = self.crypto.generate_keypair()
            self.logger.info(f"生成临时公钥，长度{len(public_key)}字节")

            self.client_public_key = await self._recv_raw()
            if not self.client_public_key or len(self.client_public_key) != 32:
                self.logger.error("接收客户端临时公钥失败")
                raise HandshakeError("接收客户端临时公钥失败")
            self.logger.info(f"接收到客户端临时公钥，长度{len(self.client_public_key)}字节")

            await self._send_raw(public_key)
            self.logger.info("发送临时公钥给客户端")

            self.crypto.init_session(self.client_public_key)
            self.logger.info("初始化会话完毕")

            response = await self._recv_raw()
            if response == b"Client Hello":
                await self._send_raw(b"Server Hello")
                self.handshake_done = True
                self.logger.info("握手成功，加密通信建立")
            else:
                self.logger.error("握手失败")
                raise HandshakeError("握手失败")
        except Exception as e:
            self.logger.error(f"握手失败: {e}")
            raise HandshakeError(f"握手失败: {e}") from e

    async def _refresh_keypair(self):
        """刷新会话根密钥"""
        if self.is_refreshing:
            return
        self.is_refreshing = True
        try:
            self.logger.info("开始刷新会话根密钥")
            self.crypto.refresh_session(self.client_public_key)
            self.crypto._session_seq_limit += 5
            self.pending_refresh = False
        except Exception as e:
            self.logger.error(f"密钥刷新失败: {e}")
            raise
        finally:
            self.is_refreshing = False

    async def _upgrade_ssl(self):
        """升级当前连接为 SSL"""
        self.logger.info("开始升级为 SSL...")

        await self.writer.start_tls(
            self.ssl_context
        )
        self.is_ssl = True
        self.logger.info("SSL 升级完成")

    async def pre_handshake(self):
        """处理客户端连接"""
        await self._negotiate()
        self.logger.info("===== 预先握手开始 =====")
        await self._handshake()
        self.logger.info("===== 预先握手结束 =====")

        self.logger.info("准备向客户端发送证书密钥文件")
        client_key, path = self.generator.generate_key()
        client_cert = self.generator.generate_cert(path)

        await self.send(client_key, is_handshake=True)
        await self.send(client_cert, is_handshake=True)
        self.logger.info("证书发送完毕")

        self.logger.info("等待 STARTTLS 命令...")
        try:
            raw_data = await self._recv_raw()
            if raw_data == b"STARTTLS":
                self.logger.info("收到 STARTTLS 请求")
                await self._send_raw(b"READY")

                await self._upgrade_ssl()
            else:
                self.logger.warning(f"未收到 STARTTLS，收到: {raw_data[:20]}")
                await self._send_raw(b"NO_STARTTLS")
                return
        except Exception as e:
            self.logger.error(f"STARTTLS 处理失败: {e}")
            return

        self.logger.info("===== 端到端加密握手开始 =====")
        await self._handshake()
        self.logger.info("===== 端到端加密握手结束 =====")
        self.logger.info("===== 预先验证全部完成 =====")
        self.seq = 1
        self.is_ready = True

    async def send(self, data, is_handshake: bool = False):
        """发送数据"""
        if not self.is_ready and not is_handshake:
            raise HandshakeError("连接尚未准备好，请先完成握手")

        if self._closed:
            raise ConnectionError("连接已关闭")

        if self.seq > self.crypto._session_seq_limit and not self.is_refreshing:
            self.pending_refresh = True

        if self.pending_refresh and not self.is_refreshing:
            self.logger.info("执行待处理的密钥刷新")
            await self._refresh_keypair()
            self.pending_refresh = False

        if not isinstance(data, bytes):
            data = str(data).encode(self.encoding)
        if self.padding != 0:
            data = await self._add_padding(data)

        edata = self.crypto.aes_encrypt(self.client_public_key, data, self.seq)
        await self._send_raw(edata)
        self.logger.info(f"当前序列号: {self.seq}")
        self.logger.info(f"[Server]->[Client]: 发送{len(data)}字节")
        self.seq += 1

    async def receive(self):
        """接收数据"""
        if not self.is_ready:
            raise HandshakeError("连接尚未准备好，请先完成握手")
        if self._closed:
            raise ConnectionError("连接已关闭")
        if not self.handshake_done:
            self.logger.error("没有完成加密握手")
            raise HandshakeError("没有完成加密握手")

        if self.seq > self.crypto._session_seq_limit and not self.is_refreshing:
            self.pending_refresh = True
        try:
            raw_data = await self._recv_raw()
        except ConnectionError:
            self.logger.info("客户端断开连接")
            return None

        if raw_data == b"REFRESH_KEY":
            self.logger.info("检测到刷新请求")
            await self._send_raw(b"REFRESH_ACK")
            self.crypto.refresh_session(self.client_public_key)
            self.crypto._session_seq_limit += 5
            self.logger.info("密钥刷新完成")
            raw_data = await self._recv_raw()

        try:
            data = self.crypto.aes_decrypt(raw_data, self.seq, self.private_key)
            if self.padding != 0:
                data = await self._remove_padding(data)
            self.logger.info(f"当前序列号: {self.seq}")
            self.logger.info(f"[Client]->[Server]: 接收{len(data)}字节")
            self.seq += 1
            return data.decode(self.encoding)
        except Exception as e:
            self.logger.error("解密失败: %s", e)
            return None

    async def close(self):
        if self._closed:
            return
        self._closed = True
        await super().close()
        self.crypto.clear_session()
        if self.private_key:
            clear_key(self.private_key)
        if self.client_public_key:
            clear(self.client_public_key)
        gc.collect()
        gc.collect()