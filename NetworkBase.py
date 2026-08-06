# coding: UTF-8
# Python 3.10.6

"""
网络通信基类，包括发送和接收数据，关闭连接
"""

import struct

class NetworkBase:
    def __init__(self, encoding: str = "utf-8"):
        self.encoding = encoding
        self.sock = None

    def _recv_exact(self, n: int) -> bytes:
        """
        精确接收n个字节的数据
        :param n: 接收字节
        :return: 数据
        """
        if not self.sock:
            raise ConnectionError("Socket没有初始化")
        data = b''
        while (len(data)) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("连接已断开")
            data += chunk
        return data

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
        header = struct.pack("!I", length)
        self.sock.sendall(header)
        self.sock.sendall(data)

    def _recv_raw(self) -> bytes:
        """
        接收数据
        :return:
        """
        if not self.sock:
            raise ConnectionError("Socket没有初始化")
        try:
            # 接收头部
            header = self._recv_exact(4)
            # 解包数据长度
            length = struct.unpack("!I", header)[0]
            # 接收数据
            body = self._recv_exact(length)
            return body
        except BaseException as e:
            raise ConnectionError(f"接收数据包失败{e}")

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None
