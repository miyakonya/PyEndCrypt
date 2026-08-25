"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

"""
网络通信基类，包括发送和接收数据，关闭连接
"""

# coding: UTF-8
# Python 3.14.7

import struct
from Crypto.Random import get_random_bytes
from .exceptions import *
import random

class NetworkBase:
    def __init__(self, padding: int,
                 encoding: str):
        """
        数据包填充级别：
            0：不填充
            1：固定大小填充
            2：随机大小填充
        :param padding: 设定数据包填充级别
        :param encoding: 编码格式
        """
        if padding < 0 or padding > 2:
            raise PaddingError("填充方式不存在")
        self.encoding = encoding
        self.ssl_sock = None
        self.sock = None
        self.MAX_SIZE = 1024 * 1024 # 最大包大小为1MB
        self.padding = padding
        self.padding_size = 128 # 设定填充块大小为128字节

    def setEncoding(self, encoding: str):
        self.encoding = encoding

    def setPadding(self, padding: int):
        self.padding = padding

    def _get_socket(self):
        if self.ssl_sock:
            return self.ssl_sock
        return self.sock

    def _recv_exact(self, n: int) -> bytes:
        """
        精确接收n个字节的数据
        :param n: 接收字节
        :return: 数据
        """
        sock = self._get_socket()
        if n > self.MAX_SIZE:
            raise PacketTooLargeError("接收到了过大的数据包！")

        if not self.ssl_sock and not self.sock:
            raise SocketNotInitializedError("Socket没有初始化")
        data = b''
        while (len(data)) < n:
            chunk = sock.recv(n - len(data))
            data += chunk
            if not chunk:
                raise ConnectionLostError("连接已断开")
        return data

    def _add_padding(self, data: bytes) -> bytes:
        """
        填充数据
        数据格式：[总长度(4字节)] + [数据实际总长(4字节)] + 数据 + 填充
        :param data: 需要填充的数据
        :return: 填充完毕的数据
        """
        length = struct.pack("!I", len(data))
        data = length + data
        padding_len = 0
        if self.padding == 0:
            padding_len = 0
        elif self.padding == 1:
            # 固定大小填充
            remainder = len(data) % self.padding_size
            padding_len = 0 if remainder == 0 else self.padding_size - remainder
        elif self.padding == 2:
            # 随机大小填充，填充范围1~(256和剩余最大可用大小间的最小值)
            max_padding = min(256, self.MAX_SIZE - len(data))
            padding_len = random.randint(1, max_padding) if max_padding > 0 else 0
        if padding_len > 0:
            data += get_random_bytes(padding_len)
        return data

    def _remove_padding(self, data: bytes) -> bytes:
        """
        去除填充的数据
        :param data: 需要去除填充的数据
        :return: 去除填充完毕的数据
        """
        if len(data) < 4:
            raise PaddingError("数据太短，无法解析")
        original_len = struct.unpack("!I", data[:4])[0]
        if 4 + original_len > len(data):
            raise PaddingError("原始长度超过数据总长！")
        result = data[4:4 + original_len]
        return result

    def _send_raw(self, data) -> None:
        """
        发送数据
        :param data:要发送的数据
        :return: 无
        """
        if not self.ssl_sock and not self.sock:
            raise SocketNotInitializedError("Socket没有初始化")
        sock = self._get_socket()
        if isinstance(data, str):
            data = data.encode(self.encoding)
        elif isinstance(data, bytes):
            pass
        else:
            data = str(data).encode(self.encoding)
        length = len(data)
        if length > self.MAX_SIZE:
            raise PacketTooLargeError("发送的数据包太大！")
        header = struct.pack("!I", length)
        data = header + data
        sock.sendall(data)

    def _recv_raw(self) -> bytes:
        """
        接收数据
        :return: 接收到的数据
        """
        if not self.ssl_sock and not self.sock:
            raise SocketNotInitializedError("Socket没有初始化")
        try:
            # 接收数据总长度
            header = self._recv_exact(4)
            length = struct.unpack("!I", header)[0]
            body = self._recv_exact(length)
            if len(body) > self.MAX_SIZE:
                raise PacketTooLargeError("接收到了过大的数据包！")
            return body
        except (PacketTooLargeError, ConnectionLostError, SocketNotInitializedError):
            raise
        except Exception as e:
            raise ConnectionLostError(f"接收数据包失败: {e}") from e
    def close(self):
        if self.ssl_sock:
            self.ssl_sock.close()
            self.ssl_sock = None
