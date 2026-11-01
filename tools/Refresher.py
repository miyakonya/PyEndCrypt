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
    def __init__(self, logger, crypto, send_frame):
        """
        :param logger: 宿主使用的 logger
        :param crypto: CryptoUtils 实例（会话根密钥由它持有）
        :param send_frame: 宿主发送加密帧的方法
                           ``async (frame_type: int, payload: bytes) -> None``
        """
        self.logger = logger
        self.crypto = crypto
        self.send_frame = send_frame

        self._rekey_waiter = None
        self._rekey_priv = None
        self._rekey_pub = None
        self._refresh_done = asyncio.Event()
        self._refresh_done.set()
        self.is_refreshing = False
        self.pending_refresh = False
        self._last_committed_peer_pub = None

    def request_pending_refresh(self):
        """宿主发现 send_seq 超过阈值时调用。"""
        self.pending_refresh = True

    def handle_refresh_ack(self, payload: bytes) -> bool:
        """宿主收到 0x12 帧时调用。

        :param payload: 解密后的明文（对方的新临时公钥，32 字节）
        :return: 是否成功交付给等待者
        """
        waiter = self._rekey_waiter
        if waiter is not None and not waiter.done():
            waiter.set_result(payload)
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
        self.pending_refresh = False
        self.logger.info("密钥刷新完成")

    async def respond_key_refresh(self, peer_new_pub_key: bytes):
        """响应对手的刷新请求：回一帧 0x12（本方新公钥），然后提交。
        :param peer_new_pub_key: 对方 0x11 帧 payload 里的新公钥
        """
        if len(peer_new_pub_key) != 32:
            self.logger.error(f"刷新请求公钥长度异常: {len(peer_new_pub_key)}")
            return None

        if not self.is_refreshing:
            self.is_refreshing = True
            self._refresh_done.clear()
            self._rekey_priv, self._rekey_pub = self.crypto.generate_keypair()
        try:
            self.logger.info("响应刷新会话根密钥")
            new_private_key, new_public_key = self._rekey_priv, self._rekey_pub
            await self.send_frame(0x12, new_public_key)

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
        """主动发起刷新：发 0x11，等对方的 0x12 后提交。"""
        if self.is_refreshing:
            self.logger.warning("密钥刷新进行中，跳过")
            return
        self.is_refreshing = True
        try:
            self._refresh_done.clear()
            self.logger.info("开始刷新会话根密钥")
            new_private_key, new_public_key = self.crypto.generate_keypair()
            self._rekey_priv, self._rekey_pub = new_private_key, new_public_key

            # 先挂好等待者再发请求，避免 ACK 先到而无人接收
            self._rekey_waiter = asyncio.get_running_loop().create_future()
            await self.send_frame(0x11, new_public_key)

            self.logger.info("等待对方的新公钥...")
            payload = await asyncio.wait_for(self._rekey_waiter, timeout=10)
            if len(payload) != 32:
                raise ValueError(f"收到的新公钥长度异常: {len(payload)}")
            await self._commit_new_keypair(new_private_key, new_public_key, payload)
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
