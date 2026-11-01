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
from tools.Refresher import Refresher
import ssl
import gc
import asyncio
import struct

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
        self.is_ready = False
        self._closed = False
        self.crypto = CryptoUtils()
        self._write_lock = asyncio.Lock()
        self.send_seq = 1
        self.recv_seq = 1
        # 读循环：唯一的读协程 + 控制帧/数据帧分流
        self._data_queue = asyncio.Queue()
        self._reader_task = None
        self._disconnected = False
        # 刷新相关的全部状态都由 Refresher 持有
        self.refresher = Refresher(self.logger, self.crypto, self._send_frame)
        self.ctrl_frame = [0x11, 0x12, 0x13, 0x14]

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
            private_key, public_key = self.crypto.generate_keypair()
            self.logger.info(f"生成临时公钥，长度{len(public_key)}字节")

            peer_public_key = await self._recv_raw()
            if not peer_public_key or len(peer_public_key) != 32:
                self.logger.error("接收客户端临时公钥失败")
                raise HandshakeError("接收客户端临时公钥失败")
            self.logger.info(f"接收到客户端临时公钥，长度{len(peer_public_key)}字节")

            await self._send_raw(public_key)
            self.logger.info("发送临时公钥给客户端")

            self.crypto.init_session(private_key, peer_public_key)
            self.logger.info("初始化会话完毕")

            response = await self._recv_raw()
            if response == b"Client Hello":
                await self._send_raw(b"Server Hello")
                self.send_seq = 1
                self.recv_seq = 1
                self.is_ready = True
                self._reader_task = asyncio.create_task(self._read_loop())
                self.logger.info("握手成功，加密通信建立")
            else:
                self.logger.error("握手失败")
                raise HandshakeError("握手失败")
        except Exception as e:
            self.logger.error(f"握手失败: {e}")
            raise HandshakeError(f"握手失败: {e}") from e

    async def _upgrade_ssl(self):
        """升级当前连接为 SSL"""
        self.logger.info("开始升级为 SSL...")

        await self.writer.start_tls(
            self.ssl_context
        )
        self.logger.info("SSL 升级完成")

    def _fatal_disconnect(self):
        """标记断开并唤醒阻塞中的 receive()"""
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
                self._fatal_disconnect()
                return

            try:
                msg = self.crypto.aes_decrypt(raw[12:], self.recv_seq, raw[:12])
                frame_type = struct.unpack("!I", msg[:4])[0]
                payload = msg[4:]
                self.recv_seq += 1
            except Exception as e:
                self.logger.error(f"解密失败: {e}，连接已终止")
                self._fatal_disconnect()
                return

            # 填充在 _send_frame 里统一添加，这里对所有帧统一去除
            if self.padding != 0:
                payload = await self._remove_padding(payload)

            if frame_type in self.ctrl_frame:
                await self._handle_ctrl(frame_type, payload)
                continue

            await self._data_queue.put(payload.decode(self.encoding))

    async def _handle_ctrl(self, frame_type: int, payload: bytes):
        """控制帧处理"""
        if frame_type == 0x12:
            self.refresher.handle_refresh_ack(payload)
        elif frame_type == 0x11:
            await self.refresher.respond_key_refresh(payload)
        else:
            self.logger.warning(f"未实现的控制帧: 0x{frame_type:02x}")

    async def _send_frame(self, frame_type: int, payload: bytes) -> None:
        """统一的加密发送路径：填充、分配 seq、加密、写入在同一把锁内完成。

        业务帧与控制帧都走这里，因此两者的填充规则完全一致。
        """
        async with self._write_lock:
            seq = self.send_seq
            self.send_seq += 1          # 先占号再 await，避免并发拿到同一个 seq
            if self.padding != 0:
                payload = await self._add_padding(payload)
            edata = self.crypto.aes_encrypt(payload, seq, frame_type)
            await self._send_raw(edata)

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
                await refresher.refresh_keypair()
                continue
            break

        if not isinstance(data, bytes):
            data = str(data).encode(self.encoding)
        await self._send_frame(0x01, data)
        self.logger.info(f"[Server]->[Client]: 发送{len(data)}字节")

    async def receive(self):
        if self._disconnected and self._data_queue.empty():
            return None
        return await self._data_queue.get()

    async def close(self):
        if self._closed:
            return
        task, self._reader_task = self._reader_task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self.send_seq = 1
        self.recv_seq = 1
        self._closed = True
        self.refresher.wipe()
        await super().close()
        self.crypto.clear_session()      # 会话密钥由 CryptoUtils 独占持有并清理
        gc.collect()
        gc.collect()