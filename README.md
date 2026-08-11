# PyEndCrypt
用Python写的端到端加密工具

## 快速开始
服务端
```python
from server import Server

server = Server("127.0.0.1", 5555)
server.send("Hello From Server")
data = server.receive()
print(data)
server.accept()
server.close()
```

客户端
```python
from client import Client

client = Client("127.0.0.1", 5555)
client.connect()
data = client.receive()
print(data)
client.send("Hello From Client")
client.close()
```

## 依赖安装
```bash
pip install pycryptodome
```

## 特点
- 端到端加密，RSA+AES混合加密。
- 服务端和客户端强制加密，没有明文传输。
- 自动握手。
- 使用简单，代码简洁。

## API
### NetworkBase
网络通信基类，包含数据发送和接收，以及socket套接字的关闭处理
方法:
- `_recv_exact(n)`: 精确接收数据
- `_send_raw(data)`: 发送原始数据包
- `_recv_raw()`: 接收原始数据包
- `close`: 关闭连接

---

### crypto_untils
加密工具类，所有加密和加密，以及密钥生成均在这里实现
方法:
- `generate_rsa_keypair()`: 生成 RSA 密钥对
- `generate_aes_key()`: 生成 AES 密钥
- `rsa_encrypt(public_key: bytes, data: bytes)`: 使用 RSA 公钥加密数据
- `rsa_decrypt(private_key: bytes, encrypted_data: bytes)`: 使用 RSA 私钥解密数据
- `_pack_with_timestamp(data: bytes)`: 将8位时间戳打包进数据中
- `_unpack_with_timestamp(data: bytes)`: 解包数据
- `_verify_time(timestamp, window=TIMEOUT)`: 时间戳校验
- `aes_encrypt(aes_key: bytes, data: bytes)`: 使用 AES 私钥加密数据
- `aes_decrypt(aes_key: bytes, data: bytes)`: 使用 AES 私钥解密数据

---

### Client
加密客户端
方法:
- `connect()`: 连接服务器并完成握手
- `send(data)`: 加密数据并发送
- `receive()`: 接收数据并解密
- `close`: 关闭连接

---

### Server
加密服务端
方法:
- `accept()`: 接受连接并完成握手
- `send(data)`: 加密数据并发送
- `receive()`: 接收数据并解密
- `close`: 关闭连接

## 加密方案
密钥交换阶段：RSA 2048位<br>
数据加密：AES 128位 GCM<br>

## 项目结构
```
PyEndCrypt/
├── README.md
├── __init__.py
├── base.py          # 网络通信基类
├── crypto_utils.py  # 加密工具
├── client.py        # 加密客户端
└── server.py        # 加密服务器
```

## 加密数据结构
***Nonce(12字节) + [timestamp(8字节) + data] + tag(16字节)***

## 加密流程
发送端:
```
┌────────────┐
│  原始数据   │
│  "Hello"   │
│  (5B)      │
└──────┬─────┘
       │
       ▼
┌────────────────────────────────┐
│  步骤1: 打包时间戳 + 数据      │
│  ┌──────────┬────────────────┐│
│  │timestamp │    "Hello"     ││
│  │  (8B)    │    (5B)        ││
│  └──────────┴────────────────┘│
│  = 13 字节                     │
└──────┬─────────────────────────┘
       │
       ▼
┌────────────────────────────────────────────┐
│  步骤2: AES-GCM 加密                       │
│  ┌──────┬────────────────┬──────┐         │
│  │nonce │  encrypted     │ tag  │         │
│  │(12B) │  (13B)         │(16B) │         │
│  └──────┴────────────────┴──────┘         │
│  = 41 字节                                │
└────────────────────────────────────────────┘

接收端:
┌────────────────────────────────────────────┐
│  步骤3: 接收数据包                        │
│  ┌──────┬────────────────┬──────┐         │
│  │nonce │  encrypted     │ tag  │         │
│  │(12B) │  (13B)         │(16B) │         │
│  └──────┴────────────────┴──────┘         │
└──────┬─────────────────────────────────────┘
       │
       ▼
┌────────────────────────────────────────────┐
│  步骤4: AES-GCM 解密                      │
│  ┌──────────┬────────────────┐             │
│  │timestamp │    "Hello"     │             │
│  │  (8B)    │    (5B)        │             │
│  └──────────┴────────────────┘             │
│  = 13 字节                                 │
└──────┬─────────────────────────────────────┘
       │
       ▼
┌────────────────────────────────────────────┐
│  步骤5: 验证时间戳并返回数据              │
│  ✅ 验证通过                              │
│  📨 返回: "Hello"                         │
└────────────────────────────────────────────┘
```