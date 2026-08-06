# encoding: UTF-8
# Python 3.10.6

import socket
from NetworkBase import NetworkBase
from crypto_utils import CryptoUtils

class Server(NetworkBase):
    def __init__(self, host: str, port: int):
        super().__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen(1)
        self.conn = None
        self.addr = None
        self.aes_key = None
        self.handshake_done = False
        self.private_key, self.pub = CryptoUtils.generate_rsa_keypair()
        print("服务器启动，等待客户端连接")
        print("RSA 密钥对生成成功")

    def _handshake(self):
        print("开始加密握手")
        self._send_raw(self.pub)
        print("公钥已发送")
        ekd = self._recv_raw()
        if ekd is None:
            raise Exception("接收 AES 密钥失败")
        try:
            self.aes_key = CryptoUtils.rsa_decrypt(self.private_key, ekd)
            print("AES 密钥解密成功")
            self._send_raw(b"OK")
            self.handshake_done = True
            print("握手成功，加密通信建立")
            print("="*20)
        except BaseException as e:
            print("解密 AES 密钥失败:", e)

    def accept(self):
        self.conn, self.addr = self.sock.accept()
        self.sock = self.conn
        print(f"{self.addr[0]}:{self.addr[1]} 连接到本服务器")
        self._handshake()

    def send(self, data):
        if not self.handshake_done:
            raise Exception("没有完成加密握手")
        if isinstance(data, str):
            data = data.encode(self.encoding)
        elif isinstance(data, bytes):
            pass
        else:
            data = str(data).encode(self.encoding)
        edata = CryptoUtils.aes_encrypt(self.aes_key, data)
        self._send_raw(edata)

    def receive(self):
        if not self.handshake_done:
            raise Exception("没有完成加密握手")
        raw_data = self._recv_raw()
        try:
            data = CryptoUtils.aes_decrypt(self.aes_key, raw_data)
            return data.decode(self.encoding)
        except BaseException as e:
            print("服务端发送了不正确的数据包:", e)
        
