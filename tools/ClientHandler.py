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
from tools.CredentialProvisioner import Generator
import ssl
import gc
import asyncio
import secrets

class ClientHandler(NetworkBase):
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
        self.client_public_key = None
        self.private_key = None
        self.pending_refresh = False
        self.is_refreshing = False
        self.is_ready = False
        self._closed = False
        self.crypto = CryptoUtils()
        self._write_lock = asyncio.Lock()
        self._refresh_done = asyncio.Event()
        self._refresh_done.set()
        self.send_seq = 1
        self.recv_seq = 1
        # 读循环：唯一的读协程 + 控制帧/数据帧分流
        self._data_queue = asyncio.Queue()
        self._ctrl_queue = asyncio.Queue()
        self._reader_task = None
        self._ctrl_task = None
        self._last_committed_peer_pub = None
        self._rekey_priv = None
        self._rekey_pub = None
        self._rekey_waiter = None
        self._disconnected = False

    async def _negotiate(self, auth_mode: int):
        """预先协商"""
        self.logger.info("开始和客户端协商")
        await self._send_raw(self.encoding.encode("utf-8"))
        await self._send_raw(str(self.padding).encode(self.encoding))
        await self._send_raw(str(auth_mode).encode(self.encoding))
        response = (await self._recv_raw()).decode(self.encoding)
        if response == "OK":
            self.logger.info(f"协商完毕，填充方式: {self.padding}\t编码格式: {self.encoding}\t认证模式: {auth_mode}")
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

            self.crypto.init_session(self.private_key, self.client_public_key)
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

    async def _commit_new_keypair(self, new_pri_key, new_pub_key, peer_new_pub_key):
        # 去重：同时发起时同一把对方公钥可能被两处提交，重复提交会让阈值多涨
        if peer_new_pub_key == self._last_committed_peer_pub:
            self.logger.info("该会话对已提交过，跳过重复提交")
            return
        self._last_committed_peer_pub = peer_new_pub_key
        # 双方新公钥到齐，一起提交
        self.crypto.refresh_session(
            new_pri_key,
            new_pub_key,
            peer_new_pub_key
        )
        self.client_public_key = peer_new_pub_key
        self.private_key = new_pri_key
        self.crypto._session_seq_limit += 5
        self.logger.info("密钥刷新完成")
        self.pending_refresh = False

    async def _respond_key_refresh(self, raw: bytes):
        """响应客户端的会话根密钥刷新"""
        peer_new_public_key = raw[11:43]
        if not self.is_refreshing:
            self.is_refreshing = True
            self._refresh_done.clear()
            self._rekey_priv, self._rekey_pub = self.crypto.generate_keypair()
        try:
            self.logger.info("响应刷新会话根密钥")
            new_private_key, new_public_key = self._rekey_priv, self._rekey_pub
            async with self._write_lock:
                await self._send_raw(b"REFRESH_ACK" + new_public_key)

            await self._commit_new_keypair(new_private_key, new_public_key, peer_new_public_key)
        except Exception as e:
            self.logger.error(f"密钥刷新失败: {e}")
            raise
        finally:
            self._rekey_priv = None
            self._rekey_pub = None
            self._refresh_done.set()
            self.is_refreshing = False

    async def _refresh_keypair(self):
        if self.is_refreshing:
            self.logger.warning("密钥刷新进行中，跳过")
            return
        self.is_refreshing = True
        try:
            self._refresh_done.clear()
            self.logger.info("开始刷新会话根密钥")
            # 生成自己的新临时密钥对，把新公钥随刷新请求发给客户端
            new_private_key, new_public_key = self.crypto.generate_keypair()
            self._rekey_priv, self._rekey_pub = new_private_key, new_public_key
            async with self._write_lock:
                await self._send_raw(b"REFRESH_KEY" + new_public_key)

            self.logger.info("等待客户端的新公钥...")
            self._rekey_waiter = loop = asyncio.get_running_loop().create_future()
            raw = await asyncio.wait_for(loop, timeout=10)
            peer_new_public_key = raw[11:43]
            await self._commit_new_keypair(new_private_key, new_public_key, peer_new_public_key)
        except Exception as e:
            self.logger.error(f"密钥刷新失败: {e}")
            raise
        finally:
            self._rekey_waiter = None
            self._rekey_priv = None
            self._rekey_pub = None
            self._refresh_done.set()
            self.is_refreshing = False

    async def _upgrade_ssl(self):
        """升级当前连接为 SSL"""
        self.logger.info("开始升级为 SSL...")

        await self.writer.start_tls(
            self.ssl_context
        )
        self.logger.info("SSL 升级完成")

    async def pre_handshake(self, auth_mode: int, psk: str):
        """处理客户端连接"""
        await self._negotiate(auth_mode)
        self.logger.info("===== 开始进行 PSK 密钥认证 =====")
        challenge = secrets.token_bytes(32)
        await self._send_raw(challenge)
        self.logger.info("向客户端发送挑战")
        challenge_response = await self._recv_raw()
        verify = self.crypto.verify_response(psk, challenge, challenge_response)
        if verify:
            self.logger.info("PSK 密钥认证成功")
            await self._send_raw("OK")
        else:
            await self._send_raw("AuthFailed")
            self.logger.error("PSK 密钥认证失败")
            await self.close()
            return
        self.logger.info("===== PSK 密钥认证结束 =====")
        self.logger.info("===== 预先握手开始 =====")
        await self._handshake()
        self.logger.info("===== 预先握手结束 =====")

        if auth_mode == 0:
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
        self.send_seq = 1
        self.recv_seq = 1
        self.is_ready = True
        # 所有握手（含 start_tls 升级）结束后才启动读循环
        self._reader_task = asyncio.create_task(self._read_loop())
        self._ctrl_task = asyncio.create_task(self._ctrl_loop())

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
                waiter = self._rekey_waiter
                if waiter is not None and not waiter.done():
                    waiter.set_result(raw)
                else:
                    self.logger.info("收到无人等待的刷新响应，忽略")
                continue

            # REFRESH_KEY：交给响应方；若我方也正在刷新，它会复用已发出的公钥
            try:
                self.logger.info("检测到刷新请求")
                await self._respond_key_refresh(raw)
            except Exception as e:
                self.logger.error(f"响应密钥刷新失败: {e}")

    async def send(self, data, is_handshake: bool = False):
        """发送数据"""
        if not self.is_ready and not is_handshake:
            raise HandshakeError("连接尚未准备好，请先完成握手")
        if self._closed:
            raise ConnectionError("连接已关闭")

        if self.send_seq > self.crypto._session_seq_limit and not self.is_refreshing:
            self.pending_refresh = True

        # 检查是否需要刷新密钥
        while True:
            await self._refresh_done.wait()
            if self.is_refreshing:
                continue
            if self.pending_refresh:
                self.logger.info("执行待处理的密钥刷新")
                await self._refresh_keypair()
                self.pending_refresh = False
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
        await super().close()
        self.crypto.clear_session()
        if self.private_key:
            clear_key(self.private_key)
        if self.client_public_key:
            clear(self.client_public_key)
        gc.collect()
        gc.collect()