# coding: UTF-8
# Python 3.10.6

"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

"""
网络通信基类，包括发送和接收数据，关闭连接
"""

import struct
from Crypto.Random import get_random_bytes

class NetworkBase:
    def __init__(self):
        self.encoding = "utf-8"
        self.sock = None
        self.MAX_SIZE = 1024 * 1024 # 最大包大小为1MB
        self.is_padding = False # 是否启用数据包填充
        self.padding_size = 128 # 设定填充块大小为128字节

    def _recv_exact(self, n: int) -> bytes:
        """
        精确接收n个字节的数据
        :param n: 接收字节
        :return: 数据
        """
        if n > self.MAX_SIZE:
            raise ConnectionError("接收到了过大的数据包！")

        if not self.sock:
            raise ConnectionError("Socket没有初始化")
        data = b''
        while (len(data)) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("连接已断开")
            data += chunk
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
        diff = (self.padding_size - (
                    len(data) % self.padding_size)) % self.padding_size - 4
        if diff > 0:
            data += get_random_bytes(diff)
        total_length = struct.pack("!I", len(data))
        data = total_length + data
        return data

    def _remove_padding(self, data: bytes) -> bytes:
        """
        去除填充的数据
        :param data: 需要去除填充的数据
        :return: 去除填充完毕的数据
        """
        if len(data) < 4:
            raise ValueError("数据太短，无法解析")
        original_len = struct.unpack("!I", data[:4])[0]
        if 4 + original_len > len(data):
            raise ValueError("原始长度超过数据总长！")
        return data[4:4 + original_len]

    def _send_raw(self, data) -> None:
        """
        发送数据
        :param data:要发送的数据
        :return: 无
        """
        if not self.sock:
            raise ConnectionError("Socket没有初始化")
        if isinstance(data, str):
            data = data.encode(self.encoding)
        elif isinstance(data, bytes):
            pass
        else:
            data = str(data).encode(self.encoding)
        length = len(data)
        # 打包数据
        if length > self.MAX_SIZE:
            raise ConnectionError("发送的数据包太大！")
        if self.is_padding:
            padded_data = self._add_padding(data)
            self.sock.sendall(padded_data)
        else:
            header = struct.pack("!I", length)
            self.sock.sendall(header)
            self.sock.sendall(data)

    def _recv_raw(self) -> bytes:
        """
        接收数据
        :return: 接收到的数据
        """
        if not self.sock:
            raise ConnectionError("Socket没有初始化")
        try:
            if self.is_padding:
                # 接收数据总长度
                header = self._recv_exact(4)
                total_length = struct.unpack("!I", header)[0]
                if total_length > self.MAX_SIZE:
                    raise ConnectionError("接收到了过大的数据包！")
                data = self._recv_exact(total_length)
                # 返回去除填充后的数据
                return self._remove_padding(data)
            header = self._recv_exact(4)
            length = struct.unpack("!I", header)[0]
            body = self._recv_exact(length)
            if len(body) > self.MAX_SIZE:
                raise ConnectionError("接收到了过大的数据包！")
            return body
        except BaseException as e:
            raise ConnectionError(f"接收数据包失败:{e}")

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None
