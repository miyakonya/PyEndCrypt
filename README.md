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
数据加密：AES 256位 CBC<br>
填充模式：PKCS7<br>

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