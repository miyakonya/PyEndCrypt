# PyEndCrypt
用Python写的端到端加密工具，采用混合加密，对数据进行双重校验，使用简单，和平常使用socket套接字步骤差不多。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 特点
- 端到端加密，X25519 + AES 混合加密。
- 服务端和客户端强制加密，没有明文传输。
- 自动握手。
- 使用简单，代码简洁。
- 时间戳和消息序列号双重校验，防止重放攻击。
- 自动校验数据，保障安全性和完整性。
- 可以根据API自行进行拓展。
- 支持数据包大小伪造。
- 自动从内存中销毁密钥数据。
- 使用mTLS认证，保护服务端和客户端，杜绝中间人攻击。
- 采用TLS加密传输层，保障传输层安全。

## 加密方案
密钥交换阶段：X25519 256位<br>
数据加密：AES-GCM 128位<br>

## 依赖安装
```bash
pip install pycryptodome
pip install eciespy
```

## 快速开始
服务端
```python
from server import Server

crt = "" # 服务端证书路径
key = "" # 服务端密钥路径
ca_crt = "" # CA证书路径
padding = False # 是否开启数据包大小伪造

server = Server("127.0.0.1",
                  5555,
                  crt,
                  key,
                  ca_crt,
                  padding)
server.accept()
server.send("Hello From Server")
data = server.receive()
print(data)
server.accept()
server.close()
```

客户端
```python
from client import Client

crt = "" # 客户端证书路径
key = "" # 客户端密钥路径
ca_crt = "" # CA证书路径
padding = False # 是否开启数据包大小伪造

client = Client("127.0.0.1",
                  5555,
                  crt,
                  key,
                  ca_crt,
                  padding)
client.connect()
data = client.receive()
print(data)
client.send("Hello From Client")
client.close()
```

## API
### NetworkBase
网络通信基类，包含数据发送和接收，以及socket套接字的关闭处理<br>
方法:
- `_recv_exact(n)`: 精确接收数据
- `_send_raw(data)`: 发送原始数据包
- `_recv_raw()`: 接收原始数据包
- `close`: 关闭连接

---

### crypto_untils
加密工具类，所有加密和加密，以及密钥生成均在这里实现<br>
方法:
- `generate_x25519_keypair()`: 生成 X25519 临时密钥对
- `x25519_derive_shared_key(private_key: X25519PrivateKey, peer_public_bytes: bytes)`: 用 X25519 密钥派生出共享密钥
- `shared_key_derive_aes_key(shared_key: bytes)`: 从共享密钥中派生出 AES 密钥
- `_pack(data: bytes, seq: int)`: 将8字节时间戳和4字节序列号打包进数据中
- `_unpack(data: bytes)`: 解包数据
- `_verify(timestamp: int, seq: int, data_seq: int, window=TIMEOUT)`: 数据校验
- `aes_encrypt(aes_key: bytes, data: bytes)`: 使用 AES 私钥加密数据
- `aes_decrypt(aes_key: bytes, data: bytes)`: 使用 AES 私钥解密数据

---

### Client
加密客户端<br>
方法:
- `Client(self, host: str, port: int, certfile: str, ssl_key: str, ca_file:str, is_padding: bool = False, encoding: str = "utf-8")`: 创建客户端
- `_destroyer()`: 从内存中销毁密钥
- `_handshake()`: 建立加密握手
- `connect()`: 连接服务器并完成握手
- `send(data)`: 加密数据并发送
- `receive()`: 接收数据并解密
- `close()`: 关闭连接

---

### Server
加密服务端<br>
方法:
- `Server(self, host: str, port: int, certfile: str, ssl_key: str, ca_file:str, is_padding: bool = False, encoding: str = "utf-8")`: 创建服务端
- `_destroyer()`: 从内存中销毁密钥
- `_handshake()`: 建立加密握手
- `accept()`: 接受连接并完成握手
- `send(data)`: 加密数据并发送
- `receive()`: 接收数据并解密
- `close()`: 关闭连接

## 项目结构
```
PyEndCrypt/
├── README.md        # 自述文件
├── NetworkBase.py   # 网络通信基类
├── crypto_utils.py  # 加密工具类
├── LICENSE          # 开源许可证
├── client.py        # 加密客户端
└── server.py        # 加密服务器
```

## 工作清单
如果你想参与开发，可以依据这个清单改进(颜色代表优先级)

- ⚪️ ~~实现服务器公钥指纹验证~~（已由TLS和mTLS替代）
- ⚪️ ~~添加客户端身份验证~~（已由TLS和mTLS替代）
- 🟡 增加心跳机制
- 🟡 添加客户端自动重连
- 🟡 将`print()`替换为日志记录系统
- 🟡 添加配置文件系统
- 🟢 做一个简易的，基于`Websocket`的Web聊天室
- 🟢 优化异常处理
