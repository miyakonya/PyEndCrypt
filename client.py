"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

# coding: UTF-8
# Python 3.14.7

import ssl
from tools.NetworkBase import NetworkBase
from tools.CryptoUtils import CryptoUtils
from tools.Logger import Logger
from tools.exceptions import HandshakeError
from tools.secure_memory import clear, clear_key
from shutil import rmtree
import os
import gc
import asyncio
import tempfile

class Client(NetworkBase):
    def __init__(self, host: str,
                 port: int,
                 ca_cert: str,
                 psk_key: str):
        """
        创建客户端
        :param host: 主机
        :param port: 端口
        :param ca_cert: CA 证书文件
        :param psk_key: PSK 密钥
        """
        super().__init__( 0, "utf-8")
        self.logger = Logger(__name__).getLogger()
        self.ca_cert = ca_cert
        self.client_cert = None
        self.client_key = None
        self.host = host
        self.port = port
        self.handshake_done = False
        self.encoding = None
        self.padding = None
        self.server_public_key = None
        self.private_key = None
        self.is_refreshing = False
        self.pending_refresh = False
        self.ssl_context = None
        self.crypto = CryptoUtils()
        self._write_lock = asyncio.Lock()
        self._refresh_done = asyncio.Event()
        self._refresh_done.set()    # 密钥刷新完毕标志位
        self.tmp_dir = os.path.join(tempfile.gettempdir(), "tmp_cert_key")
        self.auth_mode = None
        self.psk_key = psk_key
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

    async def _negotiate(self):
        """预先协商"""
        self.logger.info("开始和服务端协商")
        self.encoding = (await self._recv_raw()).decode("utf-8")
        try:
            self.padding = int((await self._recv_raw()).decode(self.encoding))
            self.auth_mode = int((await self._recv_raw()).decode(self.encoding))
        except ValueError:
            self.logger.error("服务端发送的数据格式不正确")
            raise ValueError("服务端发送的数据格式不正确")
        await self._send_raw("OK")
        self.psk_key = self.psk_key.encode(self.encoding)
        self.logger.info(f"协商完毕，填充方式: {self.padding}\t编码格式: {self.encoding}\t认证模式: {self.auth_mode}")

    async def _handshake(self):
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
        self.ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.ssl_context.check_hostname = False
        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        if self.auth_mode == 0:
            self.ssl_context.load_verify_locations(self.ca_cert)
            self.ssl_context.load_cert_chain(f"{self.tmp_dir}\\client.crt", f"{self.tmp_dir}\\client.key")
            self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        else:
            self.ssl_context.verify_mode = ssl.CERT_NONE
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
        self.logger.info("===== 开始进行 PSK 密钥认证 =====")
        challenge = await self._recv_raw()
        self.logger.info("接收到挑战")
        challenge_response = self.crypto.get_challenge_response(self.psk_key, challenge)
        await self._send_raw(challenge_response)
        self.logger.info("发送挑战响应")
        auth_msg = await self._recv_raw()
        if auth_msg == b"OK":
            self.logger.info("PSK 认证成功")
        else:
            self.logger.error("PSK 认证失败")
            await self.close()
            raise Exception("PSK 认证失败")
        self.logger.info("===== PSK 密钥认证结束 =====")
        self.logger.info("===== 预先握手开始 =====")
        await self._handshake()
        self.logger.info("===== 预先握手结束 =====")
        # 第一次握手已建立会话密钥，而证书要经 receive() 读取，
        # 所以读循环必须在这里就启动
        self._start_loops()

        if self.auth_mode == 0:
            # 证书经读循环解密后由 receive() 取出
            self.client_key = await self.receive()
            self.client_cert = await self.receive()
            if not self.client_cert or not self.client_key:
                raise HandshakeError("无法接收到证书密钥")
            self.logger.info(f"密钥接收完毕，共{len(self.client_key)}字节")
            self.logger.info(f"证书接收完毕，共{len(self.client_cert)}字节")

            os.makedirs(self.tmp_dir, exist_ok=True)
            with open(f"{self.tmp_dir}\\client.key", "w+") as kw:
                kw.write(self.client_key)
            with open(f"{self.tmp_dir}\\client.crt", "w+") as cw:
                cw.write(self.client_cert)
            if not self.client_cert or not self.client_key:
                raise HandshakeError("无法接收到证书和密钥")

        self.logger.info("发送 STARTTLS")
        # 下面要直接读原始 READY 和第二次握手的公钥，先把读循环停掉
        await self._stop_loops()
        await self._send_raw(b"STARTTLS")
        response = await self._recv_raw()
        if response != b"READY":
            raise Exception(f"服务端拒绝升级 SSL: {response}")
        await self._upgrade_ssl()

        if self.auth_mode == 0:
            rmtree(self.tmp_dir)

        self.logger.info("SSL 加密完毕")
        self.logger.info("===== 端到端加密握手开始 =====")
        await self._handshake()
        self.logger.info("===== 端到端加密握手结束 =====")
        self.send_seq = 1
        self.recv_seq = 1
        self.logger.info("===== 预先验证全部完成 =====")
        # 握手期读取全部结束，重启唯一的读循环
        self._start_loops()

    def _start_loops(self):
        """启动唯一的读循环与控制帧循环"""
        if self._reader_task is not None:
            return
        self._reader_task = asyncio.create_task(self._read_loop())
        self._ctrl_task = asyncio.create_task(self._ctrl_loop())

    async def _stop_loops(self):
        """停止读循环与控制帧循环"""
        for task in (self._reader_task, self._ctrl_task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self._reader_task = None
        self._ctrl_task = None

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
                self.logger.info(f"[Server]->[Client]: 接收{len(data)}字节")
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
        self.server_public_key = peer_new_pub_key
        self.private_key = new_pri_key
        self.crypto._session_seq_limit += 5
        self.logger.info("密钥刷新完成")
        self.pending_refresh = False

    async def _respond_key_refresh(self, raw: bytes):
        """响应对方的会话根密钥刷新"""
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
        """刷新会话根密钥（双方交换新公钥后再提交）"""
        if self.is_refreshing:
            self.logger.warning("密钥刷新进行中，跳过")
            return
        self.is_refreshing = True
        try:
            self._refresh_done.clear()
            self.logger.info("开始刷新会话根密钥")
            # 生成自己的新临时密钥对，把新公钥随刷新请求发给服务端
            new_private_key, new_public_key = self.crypto.generate_keypair()
            self._rekey_priv, self._rekey_pub = new_private_key, new_public_key
            async with self._write_lock:
                await self._send_raw(b"REFRESH_KEY" + new_public_key)

            self.logger.info("等待服务端的新公钥...")
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

    async def send(self, data):
        if not self.handshake_done:
            raise HandshakeError("没有完成加密握手")
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
        # 发送已加密的数据
        async with self._write_lock:
            await self._send_raw(edata)
        self.logger.info(f"当前序列号: {self.send_seq}")
        self.logger.info(f"[Client]->[Server]: 发送{len(data)}字节")
        self.send_seq += 1

    async def receive(self):
        if not self.handshake_done:
            raise HandshakeError("没有完成加密握手")
        if self._disconnected and self._data_queue.empty():
            return None
        data = await self._data_queue.get()
        if data is None:
            self.logger.info("服务端断开连接")
        return data

    async def close(self):
        await self._stop_loops()
        await super().close()
        self.send_seq = 1
        self.recv_seq = 1
        self.crypto.clear_session()
        if self.private_key:
            clear_key(self.private_key)
        if self.server_public_key:
            clear(self.server_public_key)
        gc.collect()
        gc.collect()
