"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

# coding: UTF-8
# Python 3.14.7

from tools.NetworkBase import NetworkBase
from tools.Logger import Logger
from tools.CredentialProvisioner import Generator
from tools.ClientHandler import ClientHandler
import ssl
import asyncio

class Server(NetworkBase):
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
        super().__init__(padding, encoding)
        self.logger = Logger(__name__).getLogger()
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
        self.running = False
        self.clients: dict[str, ClientHandler] = {}
        self.ssl_context = None
        self.generator = Generator(ca_cert, ca_key)
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self._server = None
        self._pending_connections = None

    def _setup_ssl_context(self):
        """设置 SSL 上下文"""
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.ssl_context.load_cert_chain(self.server_cert, self.server_key)
        self.ssl_context.load_verify_locations(self.ca_cert)
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_addr = writer.get_extra_info("peername")
        self.logger.info(f"{client_addr[0]}:{client_addr[1]} 连接到本服务器")
        handler = ClientHandler(
            reader,
            writer,
            self.padding,
            self.encoding,
            self.generator,
            self.ssl_context
        )
        try:
            await handler.pre_handshake()
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
        self.running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self.clients.clear()