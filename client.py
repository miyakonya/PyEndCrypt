"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

# coding: UTF-8
# Python 3.14.7

import ssl
import struct

from tools.NetworkBase import NetworkBase
from tools.CryptoUtils import CryptoUtils
from tools.Logger import Logger
from tools.exceptions import HandshakeError
from tools.secure_memory import clear, clear_key
from tools.Refresher import Refresher
import gc
import asyncio

class Client(NetworkBase):
    def __init__(self, host: str,
                 port: int,
                 psk_key: bytes):
        """
        创建客户端
        :param host: 主机
        :param port: 端口
        :param psk_key: psk 密钥
        """
        super().__init__( 0, "utf-8")
        self.logger = Logger(__name__).getLogger()
        self.client_cert = None
        self.client_key = None
        self.host = host
        self.port = port
        self.handshake_done = False
        self.encoding = None
        self.padding = None
        self.server_public_key = None
        self.private_key = None
        self.ssl_context = None
        self.crypto = CryptoUtils()
        self._write_lock = asyncio.Lock()
        self.send_seq = 1
        self.recv_seq = 1
        # 读循环：唯一的读协程 + 控制帧/数据帧分流
        self._data_queue = asyncio.Queue()
        self._reader_task = None
        self._disconnected = False
        self.psk_key = psk_key
        self.padding = 0
        # 刷新相关的全部状态都由 Refresher 持有（不要再在本类里留副本）。
        # on_commit 负责把刷新后的新私钥/对方公钥同步回本类 —— 读循环解密要用。
        self.refresher = Refresher(
            self.logger,
            self.crypto,
            self._write_lock,
            self._send_frame,
            self._on_key_refreshed
        )
        self.ctrl_frame = [0x11, 0x12, 0x13, 0x14]

    def _on_key_refreshed(self, new_private_key, peer_public_key) -> None:
        """Refresher 提交新密钥后回调：更新本类持有的解密所需密钥。"""
        self.private_key = new_private_key
        self.server_public_key = peer_public_key

    async def _negotiate(self):
        """预先协商"""
        self.logger.info("开始和服务端协商")
        self.encoding = (await self._recv_raw()).decode("utf-8")
        try:
            self.padding = int((await self._recv_raw()).decode(self.encoding))
        except ValueError:
            self.logger.error("服务端发送的数据格式不正确")
            raise ValueError("服务端发送的数据格式不正确")
        await self._send_raw("OK")
        self.logger.info(f"协商完毕，填充方式: {self.padding}\t编码格式: {self.encoding}")

    async def handshake(self):
        """建立加密连接"""
        self.logger.info("开始加密握手")
        self.private_key, public_key = self.crypto.generate_keypair()
        self.logger.info(f"生成临时公钥，长度{len(public_key)}字节")
        await self._send_raw(public_key)
        self.logger.info("发送临时公钥给服务器")
        self.server_public_key = await self._recv_raw()
        if not self.server_public_key or len(self.server_public_key) != 32:
            self.logger.error("接收服务器临时公钥失败")
            raise HandshakeError("接收服务器临时公钥失败")
        self.logger.info(f"接收到服务器临时公钥，长度{len(self.server_public_key)}字节")
        self.crypto.init_session(self.private_key, self.server_public_key)
        self.logger.info("初始化会话完毕")
        await self._send_raw(b"Client Hello")
        response = await self._recv_raw()
        if response == b"Server Hello":
            self.handshake_done = True
            self.logger.info("握手成功，加密通信建立")
        else:
            self.logger.error("握手失败")
            raise HandshakeError("握手失败")

    async def _upgrade_ssl(self):
        self.logger.info("开始升级为 SSL...")
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.ssl_context.check_hostname = False
        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.ssl_context.set_psk_client_callback(lambda x: ("psk-key", self.psk_key))
        await self.writer.start_tls(
            self.ssl_context,
            server_hostname=self.host
        )
        self.logger.info("SSL 升级完成")

    async def connect(self):
        reader, writer = await asyncio.open_connection(
            self.host, self.port
        )
        self.reader = reader
        self.writer = writer
        self.logger.info("连接成功")
        await self._negotiate()
        self.logger.info("发送 STARTTLS")
        await self._send_raw(b"STARTTLS")
        response = await self._recv_raw()
        if response != b"READY":
            raise Exception(f"服务端拒绝升级 SSL: {response}")
        await self._upgrade_ssl()

        self.logger.info("===== 端到端加密握手开始 =====")
        await self.handshake()
        self.logger.info("===== 端到端加密握手结束 =====")
        self.send_seq = 1
        self.recv_seq = 1
        self.logger.info("===== 预先验证全部完成 =====")
        self._start_loops()

    def _start_loops(self):
        """启动唯一的读循环"""
        if self._reader_task is not None:
            return
        self._reader_task = asyncio.create_task(self._read_loop())

    async def _stop_loops(self):
        """停止读循环"""
        task, self._reader_task = self._reader_task, None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

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
        if not self.handshake_done:
            raise HandshakeError("没有完成加密握手")
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
        self.logger.info(f"[Client]->[Server]: 发送{len(data)}字节")

    async def receive(self):
        if self._disconnected and self._data_queue.empty():
            return None
        return await self._data_queue.get()

    async def close(self):
        await self._stop_loops()
        await super().close()
        self.send_seq = 1
        self.recv_seq = 1
        self.refresher.wipe()
        self.crypto.clear_session()
        if self.private_key:
            clear_key(self.private_key)
        if self.server_public_key:
            clear(self.server_public_key)
        gc.collect()
        gc.collect()
