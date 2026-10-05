"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

# coding: UTF-8
# Python 3.14.7

from tools.NetworkBase import NetworkBase
from tools.Logger import Logger
from tools.ClientHandler import ClientHandler
import ssl
import asyncio

class Server(NetworkBase):
    def __init__(self, host: str,
                 port: int,
                 psk_key: bytes,
                 padding: int = 0,
                 encoding: str = "utf-8"):
        """
        创建服务端
        :param host: 主机
        :param port: 端口
        :param psk_key: psk 密钥
        :param padding: 数据包填充级别
        :param encoding: 编码格式
        """
        super().__init__(padding, encoding)
        self.logger = Logger(__name__).getLogger()
        self.encoding = encoding
        self.padding = padding
        self.host = host
        self.port = port
        self.ssl_context = None
        self._server = None
        self._pending_connections = None
        self.psk_key = psk_key
        if len(self.psk_key) < 1 or len(self.psk_key) > 64:
            raise Exception("PSK 密钥不合规，应为1~64字节")

    def _setup_ssl_context(self):
        """设置 SSL 上下文"""
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.ssl_context.set_psk_server_callback(lambda x: self.psk_key, None)

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_addr = writer.get_extra_info("peername")
        self.logger.info(f"{client_addr[0]}:{client_addr[1]} 连接到本服务器")
        handler = ClientHandler(
            reader,
            writer,
            self.padding,
            self.encoding,
            self.ssl_context
        )
        try:
            await handler.handshake()
            if self._pending_connections is not None:
                await self._pending_connections.put(handler)
        except Exception as e:
            self.logger.error(f"客户端 {client_addr} 处理失败: {e}")
            await handler.close()
            raise

    async def accept(self):
        if self._server is None:
            self._setup_ssl_context()
            self._pending_connections = asyncio.Queue()
            self._server = await asyncio.start_server(
                self._handle_connection,
                self.host,
                self.port
            )
            self.logger.info(f"服务器启动，监听 {self.host}:{self.port}")
            asyncio.create_task(self._server.serve_forever())

        handler = await self._pending_connections.get()
        return handler

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
