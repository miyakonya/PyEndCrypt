"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

"""客户端处理器"""

# coding: UTF-8
# Python 3.14.7

from tools.NetworkBase import NetworkBase
from tools.CryptoUtils import CryptoUtils
from tools.Logger import Logger
from tools.exceptions import HandshakeError
from tools.secure_memory import clear, clear_key
from tools.Refresher import Refresher
import ssl
import gc
import asyncio

class ClientHandler(NetworkBase):
    def __init__(self, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter,
                 padding: int, encoding: str,
                 ssl_context: ssl.SSLContext):
        super().__init__(padding, encoding)
        self.reader: asyncio.StreamReader = reader
        self.writer: asyncio.StreamWriter = writer
        self.ssl_context = ssl_context
        self.logger = Logger(__name__).getLogger()
        self.handshake_done = False
        self.client_public_key = None
        self.private_key = None
        self.is_ready = False
        self._closed = False
        self.crypto = CryptoUtils()
        self._write_lock = asyncio.Lock()
        self.send_seq = 1
        self.recv_seq = 1
        # 读循环：唯一的读协程 + 控制帧/数据帧分流
        self._data_queue = asyncio.Queue()
        self._ctrl_queue = asyncio.Queue()
        self._reader_task = None
        self._ctrl_task = None
        self._disconnected = False
        self.refresher = Refresher(
            self.logger,
            self.crypto,
            self._write_lock,
            self._send_raw,
            self._on_key_refreshed,
        )

    def _on_key_refreshed(self, new_private_key, peer_public_key) -> None:
        """Refresher 提交新密钥后回调：更新本类持有的解密所需密钥。"""
        self.private_key = new_private_key
        self.client_public_key = peer_public_key

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

    async def handshake(self):
        """加密握手实现"""
        try:
            await self._negotiate()
            self.logger.info("开始加密握手")
            self.logger.info("开始建立 TLS")
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
                raise
            self.private_key, public_key = self.crypto.generate_keypair()
            self.logger.info(f"生成临时公钥，长度{len(public_key)}字节")

            self.client_public_key = await self._recv_raw()
            if not self.client_public_key or len(self.client_public_key) != 32:
                self.logger.error("接收客户端临时公钥失败")
                raise HandshakeError("接收客户端临时公钥失败")
            self.logger.info(f"接收到客户端临时公钥，长度{len(self.client_public_key)}字节")

            await self._send_raw(public_key)
            self.logger.info("发送临时公钥给客户端")

            self.crypto.init_session(self.private_key, self.client_public_key)
            self.logger.info("初始化会话完毕")

            response = await self._recv_raw()
            if response == b"Client Hello":
                await self._send_raw(b"Server Hello")
                self.handshake_done = True
                self.send_seq = 1
                self.recv_seq = 1
                self.is_ready = True
                self._reader_task = asyncio.create_task(self._read_loop())
                self._ctrl_task = asyncio.create_task(self._ctrl_loop())
                self.logger.info("握手成功，加密通信建立")
            else:
                self.logger.error("握手失败")
                raise HandshakeError("握手失败")
        except Exception as e:
            self.logger.error(f"握手失败: {e}")
            raise HandshakeError(f"握手失败: {e}") from e

    async def _respond_key_refresh(self, raw: bytes):
        """响应对方的会话根密钥刷新"""
        await self.refresher.respond_key_refresh(raw[11:43])

    async def _refresh_keypair(self):
        """刷新会话根密钥（双方交换新公钥后再提交）"""
        await self.refresher.refresh_keypair()

    async def _upgrade_ssl(self):
        """升级当前连接为 SSL"""
        self.logger.info("开始升级为 SSL...")

        await self.writer.start_tls(
            self.ssl_context
        )
        self.logger.info("SSL 升级完成")

    async def _fatal_disconnect(self):
        """当读循环退出时，标记断开并唤醒阻塞中的 receive()"""
        self._disconnected = True
        self._data_queue.put_nowait(None)

    async def _read_loop(self):
        """唯一的读协程：收帧并分流，数据帧在这里解密"""
        while True:
            try:
                raw = await self._recv_raw()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.logger.info(f"连接读取结束: {e}")
                self._disconnected = True
                await self._data_queue.put(None)      # 通知业务层断开
                return

            # 控制帧（REFRESH_KEY / REFRESH_ACK）：交给 _ctrl_loop，绝不落到业务层
            if raw.startswith(b"REFRESH_"):
                await self._ctrl_queue.put(raw)
                continue

            # 数据帧：序列号只在这里推进
            try:
                data = self.crypto.aes_decrypt(raw, self.recv_seq, self.private_key)
                if self.padding != 0:
                    data = await self._remove_padding(data)
                self.logger.info(f"当前序列号: {self.recv_seq}")
                self.logger.info(f"[Client]->[Server]: 接收{len(data)}字节")
                self.recv_seq += 1
                await self._data_queue.put(data.decode(self.encoding))
            except Exception as e:
                self.logger.error(f"解密失败: {e}，连接已终止")
                await self._fatal_disconnect()
                return

    async def _ctrl_loop(self):
        """唯一消费控制帧的地方：请求交给响应方，响应交给发起方"""
        while True:
            raw = await self._ctrl_queue.get()
            if len(raw) != 11 + 32:
                self.logger.error("刷新帧格式不正确，忽略")
                continue

            if raw.startswith(b"REFRESH_ACK"):
                # ACK 必须交给 Refresher 的 waiter，否则发起方会一直等到 10 秒超时
                self.refresher.handle_refresh_ack(raw)
                continue

            # REFRESH_KEY：交给响应方；若我方也正在刷新，它会复用已发出的公钥
            try:
                self.logger.info("检测到刷新请求")
                await self._respond_key_refresh(raw)
            except Exception as e:
                self.logger.error(f"响应密钥刷新失败: {e}")

    async def send(self, data):
        """发送数据"""
        if not self.is_ready:
            raise HandshakeError("连接尚未准备好，请先完成握手")
        if self._closed:
            raise ConnectionError("连接已关闭")

        refresher = self.refresher
        if self.send_seq > self.crypto._session_seq_limit and not refresher.is_refreshing:
            refresher.request_pending_refresh()

        # 检查是否需要刷新密钥
        while True:
            await refresher.wait_until_idle()
            if refresher.is_refreshing:
                continue
            if refresher.pending_refresh:
                self.logger.info("执行待处理的密钥刷新")
                await self._refresh_keypair()
                continue
            break

        if not isinstance(data, bytes):
            data = str(data).encode(self.encoding)
        if self.padding != 0:
            data = await self._add_padding(data)

        edata = self.crypto.aes_encrypt(data, self.send_seq)
        async with self._write_lock:
            await self._send_raw(edata)
        self.logger.info(f"当前序列号: {self.send_seq}")
        self.logger.info(f"[Server]->[Client]: 发送{len(data)}字节")
        self.send_seq += 1

    async def receive(self):
        """接收数据"""
        if not self.is_ready:
            raise HandshakeError("连接尚未准备好，请先完成握手")
        if self._closed:
            raise ConnectionError("连接已关闭")
        if not self.handshake_done:
            self.logger.error("没有完成加密握手")
            raise HandshakeError("没有完成加密握手")

        if self._disconnected and self._data_queue.empty():
            return None
        data = await self._data_queue.get()
        if data is None:
            self.logger.info("客户端断开连接")
        return data

    async def close(self):
        if self._closed:
            return
        for task in (self._reader_task, self._ctrl_task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self._reader_task = None
        self._ctrl_task = None
        self.send_seq = 1
        self.recv_seq = 1
        self._closed = True
        self.refresher.wipe()
        await super().close()
        self.crypto.clear_session()
        if self.private_key:
            clear_key(self.private_key)
        if self.client_public_key:
            clear(self.client_public_key)
        gc.collect()
        gc.collect()