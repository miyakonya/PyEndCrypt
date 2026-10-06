"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

"""
会话根密钥刷新器
"""

# coding: UTF-8
# Python 3.14.7

import asyncio

class Refresher:
    def __init__(self, logger, crypto, write_lock, send_raw, on_commit=None):
        """
        :param logger: 宿主使用的 logger
        :param crypto: CryptoUtils 实例（会话根密钥由它持有）
        :param write_lock: 宿主的 asyncio.Lock，用于串行化控制帧写入
        :param send_raw: 宿主发送原始帧的方法（NetworkBase._send_raw）
        :param on_commit: 提交新密钥后的回调 (new_private_key, peer_public_key) -> None
        """
        self.logger = logger
        self.crypto = crypto
        self._write_lock = write_lock
        self.send_raw = send_raw
        self._on_commit = on_commit

        self._rekey_waiter = None
        self._rekey_priv = None
        self._rekey_pub = None
        self._refresh_done = asyncio.Event()
        self._refresh_done.set()
        self.is_refreshing = False
        self.pending_refresh = False
        self._last_committed_peer_pub = None

    @property
    def waiter(self):
        """等待 REFRESH_ACK 的 future（宿主 _ctrl_loop 用）"""
        return self._rekey_waiter

    def request_pending_refresh(self):
        """宿主发现 send_seq 超过阈值时调用。"""
        self.pending_refresh = True

    def handle_refresh_ack(self, raw: bytes) -> bool:
        """宿主收到 REFRESH_ACK 时调用；返回是否成功交付给等待者。"""
        waiter = self._rekey_waiter
        if waiter is not None and not waiter.done():
            waiter.set_result(raw)
            return True
        self.logger.info("收到无人等待的刷新响应，忽略")
        return False


    async def _commit_new_keypair(self, new_pri_key, new_pub_key, peer_new_pub_key):
        # 去重：同时发起时同一把对方公钥可能被两处提交，重复提交会让阈值多涨
        if peer_new_pub_key == self._last_committed_peer_pub:
            self.logger.info("该会话对已提交过，跳过重复提交")
            self.pending_refresh = False
            return
        self._last_committed_peer_pub = peer_new_pub_key
        # 双方新公钥到齐，一起提交
        self.crypto.refresh_session(
            new_pri_key,
            new_pub_key,
            peer_new_pub_key
        )
        self.crypto._session_seq_limit += 5
        # 关键：宿主的读循环用「自己的私钥 + 对方公钥」解密，
        # 因此必须把新密钥交回宿主，不能只留在本类里。
        if self._on_commit is not None:
            self._on_commit(new_pri_key, peer_new_pub_key)
        self.pending_refresh = False
        self.logger.info("密钥刷新完成")

    async def respond_key_refresh(self, peer_new_pub_key: bytes):
        """
        响应对方的刷新请求
        :param peer_new_pub_key: 对方 REFRESH_KEY 帧里带的、它这次用的新公钥
        """
        if not self.is_refreshing:
            self.is_refreshing = True
            self._refresh_done.clear()
            self._rekey_priv, self._rekey_pub = self.crypto.generate_keypair()
        try:
            self.logger.info("响应刷新会话根密钥")
            new_private_key, new_public_key = self._rekey_priv, self._rekey_pub
            async with self._write_lock:
                await self.send_raw(b"REFRESH_ACK" + new_public_key)

            await self._commit_new_keypair(new_private_key, new_public_key,
                                           peer_new_pub_key)
            return True
        except Exception as e:
            self.logger.error(f"响应密钥刷新失败: {type(e).__name__}: {e}")
            return None
        finally:
            self._rekey_priv = None
            self._rekey_pub = None
            self._refresh_done.set()
            self.is_refreshing = False

    async def refresh_keypair(self):
        """主动发起刷新：发 REFRESH_KEY + 本方新公钥，等对方 ACK 后提交。"""
        if self.is_refreshing:
            self.logger.warning("密钥刷新进行中，跳过")
            return
        self.is_refreshing = True
        try:
            self._refresh_done.clear()
            self.logger.info("开始刷新会话根密钥")
            # 生成自己的新临时密钥对，把新公钥随刷新请求发给对方
            new_private_key, new_public_key = self.crypto.generate_keypair()
            self._rekey_priv, self._rekey_pub = new_private_key, new_public_key
            async with self._write_lock:
                await self.send_raw(b"REFRESH_KEY" + new_public_key)

            self.logger.info("等待对方的新公钥...")
            self._rekey_waiter = asyncio.get_running_loop().create_future()
            raw = await asyncio.wait_for(self._rekey_waiter, timeout=10)
            peer_new_public_key = raw[11:43]
            await self._commit_new_keypair(new_private_key, new_public_key,
                                           peer_new_public_key)
        except Exception as e:
            self.logger.error(f"密钥刷新失败: {type(e).__name__}: {e}")
            raise
        finally:
            self._rekey_waiter = None
            self._rekey_priv = None
            self._rekey_pub = None
            self._refresh_done.set()
            self.is_refreshing = False

    async def wait_until_idle(self):
        """等待当前刷新结束（宿主 send() 的等待循环用）。"""
        await self._refresh_done.wait()

    def wipe(self) -> None:
        """连接关闭时清理临时密钥。"""
        self._rekey_priv = None
        self._rekey_pub = None
        self._rekey_waiter = None
        self._last_committed_peer_pub = None
