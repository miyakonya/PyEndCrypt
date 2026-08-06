# encoding: UTF-8
# Python 3.10.6

import socket
from NetworkBase import NetworkBase
from crypto_utils import CryptoUtils

class Client(NetworkBase):
    def __init__(self, host: str, port: int):
        super().__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(3)
        self.host = host
        self.port = port
        self.aes_key = None
        self.handshake_done = False

    def _handshake(self):
        """建立加密连接"""
        print("开始加密握手")
        pub = self._recv_raw()
        if not pub:
            raise Exception("公钥接收失败")
        print(f"接收到服务器公钥，长度{len(pub)}字节")
        self.aes_key = CryptoUtils.generate_aes_key()
        print("生成 AES 密钥")
        eak = CryptoUtils.rsa_encrypt(pub, self.aes_key)
        print("发送加密的 AES 密钥")
        self._send_raw(eak)
        response = self._recv_raw()
        if response == b"OK":
            self.handshake_done = True
            print("握手成功，加密通信建立")
            print("=" * 20)
        else:
            raise Exception("握手失败")

    def connect(self):
        self.sock.connect((self.host, self.port))
        print("连接成功")
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
        # 发送已加密的数据
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

        
