# PyEndCrypt
用Python写的端到端加密工具，采用混合加密，对数据进行双重校验，使用简单，和平常使用socket套接字步骤差不多。

本项目适合想了解密码学的开发人员，提供有ECC、kyber和AES加解密供研究。如果你想，可以根据下文[API](#api)进行二次开发。

项目目前仍处于开发阶段，如果你想参与开发请看下文[工作清单](#工作清单)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 💡特点
- 端到端加密，X25519 / kyber + AES 混合加密。
- 非对称加密可自选x25519或kyber。
- 服务端和客户端强制加密，没有明文传输。
- 自动握手。
- 使用简单，代码简洁。
- ***时间戳和消息序列号双重校验***，防止重放攻击。
- 自动校验数据，保障安全性和完整性。
- 可以根据API自行进行拓展。
- ***支持数据包大小伪造***。
- ***使用mTLS认证***，保护服务端和客户端，杜绝中间人攻击。
- ***采用TLS加密传输层***，保障传输层安全。
- ***支持动态客户端证书签发***，客户端只需要 CA 证书即可

---

## 🔐加密方案
认证：mTLS<br>
传输层：TLSv1.3<br>
密钥交换阶段：ECC X25519 256位 / kyber 768位<br>
数据加密：AES-GCM 256位<br>

> **⚠️ 加密算法风险警告**
> 
> kyber算法使用的库为`kyber-py`，虽然目前没有已知漏洞，
> 但是官方文档已经给出明确警告：没有针对任何形式的侧信道攻击进行安全设计。
> 这里只用于后量子密码学学习研究。
> ***建议使用x25519算法***。

---

## ⚙️依赖安装
```bash
pip install cryptography
pip install kyber-py
```

---

## 🚀快速开始
服务端
```python
from server import Server

crt = "" # 服务端证书路径
key = "" # 服务端密钥路径
ca_crt = "" # CA 证书路径
ca_key = "" # CA 密钥路径
padding = 0 # 数据包填充级别
asy_mod = ""    # 非对称加密算法("x25519"或"kyber")

server = Server("127.0.0.1",
                5555,
                crt,
                key,
                ca_crt, 
                ca_key, 
                asy_mod,
                padding)
server.accept()
server.send("Hello From Server")
data = server.receive()
print(data)
server.close()
```

客户端
```python
from client import Client

ca_crt = "" # CA 证书路径

client = Client("127.0.0.1",
                5555,
                ca_crt)
client.connect()
data = client.receive()
print(data)
client.send("Hello From Client")
client.close()
```

关于各个证书和密钥，如果是测试环境，可以使用`tools/generator.py`一键生成。

---

## 数据包伪造
通过设定padding参数开启数据包大小伪造，其原理是在密文末尾填充无意义垃圾数据，共两个级别:
```text
数据包填充级别:
    0：不填充
    1：固定大小填充
    2：随机大小填充
固定大小填充可以使数据包长度始终为128的倍数(由于使用TLSv1.3，实际大小会大一些)
随机大小填充可以使数据包增加一个随机长度，范围: 1~(256和剩余最大可用大小间的最小值)
```

---

## 数据结构
```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    应用层 (AES-GCM 加密前)                                   │
├──────────┬──────────┬──────────────────────┬───────────────────────────────┤
│ 总长度头 │ 原始长度头│         数据         │           填充                 │
│  4 字节  │  4 字节  │       变长          │          变长                  │
├──────────┴──────────┴──────────────────────┴───────────────────────────────┤
│                          AES-256-GCM 加密                                   │
├──────────┬──────────────────────────────────────────────┬───────────────────┤
│  Nonce   │                密文                          │       Tag         │
│ 12 字节  │              变长                           │     16 字节       │
├──────────┴──────────────────────────────────────────────┴───────────────────┤
│                          TLS 传输层封装                                     │
├──────────┬──────────┬──────────┬───────────────────────────────────────────┤
│  TLS类型 │ TLS版本  │ TLS长度 │              TLS加密数据                   │
│  1 字节  │  2 字节  │  2 字节 │              变长                         │
└──────────┴──────────┴──────────┴───────────────────────────────────────────┘
```

---

## 🔌API
### NetworkBase
网络通信基类，包含数据发送和接收，以及socket套接字的关闭处理<br>
方法:
- `_recv_exact(self, n: int)`: 精确接收n个字节数据
- `_send_raw(self, data)`: 发送原始数据包
- `_recv_raw(self)`: 接收原始数据包
- `_add_padding(self, data: bytes)`: 填充数据
- `_remove_padding(self, data: bytes)`: 移除填充的数据
- `close(self)`: 关闭连接

---

### CryptoUntils
加密工具类，所有加密和解密，以及密钥生成均在这里实现<br>
方法:
- `generate_x25519_keypair()`: 生成 X25519 临时密钥对
- `x25519_derive_shared_key(private_key: X25519PrivateKey, peer_public_bytes: bytes)`: 用 X25519 密钥派生出共享密钥
- `generate_kyber_keypair()`: 生成 kyber 密钥对
- `encaps(public_key: bytes)`: 用 kyber 公钥封装共享密钥
- `decaps(private_key: bytes, ciphertext: bytes)`: 用 kyber 私钥解封装共享密钥
- `generate_salt()`: 生成256位随机盐值
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
- `Client(self, host: str, port: int, ca_cert: str, padding: int = 0, encoding: str = "utf-8")`: 创建客户端
- `_negotiate()`: 预先协商
- `_handshake()`: 建立加密握手
- `connect()`: 连接服务器并完成握手
- `send(data)`: 加密数据并发送
- `receive()`: 接收数据并解密
- `close()`: 关闭连接

---

### Server
加密服务端<br>
方法:
- `Server(self, host: str, port: int, listen: int, server_cert: str, server_key: str, ca_cert:str, ca_key: str, padding: int = 0, encoding: str = "utf-8")`: 创建服务端
- `_negotiate()`: 预先协商
- `_handshake()`: 建立加密握手
- `accept()`: 接受连接并完成握手
- `send(data)`: 加密数据并发送
- `receive()`: 接收数据并解密
- `close()`: 关闭连接

---

### CredentialProvisioner
证书密钥生成器<br>
方法:
- `Generator(self, ca_cert: str, ca_key: str)`: 创建生成器
- `generate_cert(self, client_key)`: 生成客户端证书文件
- `generate_key(self)`: 生成客户端密钥文件

---

### SSLBuilder
SSL 连接构建器<br>
方法:
- `Builder(self, cert: str, key: str, ca_cert: str, is_server)`: 创建构建器

---

## 🏗️项目结构
```
PyEndCrypt/
├── README.md           # 自述文件
├── LICENSE             # 开源许可证
├── server.py           # 加密服务端
├── client.py           # 加密客户端
└── tools
    ├── CryptoUtils.py   # 加密工具类
    ├── Logger.py        # 日志记录器
    ├── NetworkBase.py   # 网络通信基类
    ├── CredentialProvisioner.py    # 客户端证书和密钥生成器
    ├── SSLBuilder.py    # SSL 连接构建器
    ├── generator.py     # 证书密钥全生成器
    ├── exceptions.py    # 所有异常的基类
    └── __init__.py
```

---

## 📝工作清单
如果你想参与开发，可以依据这个清单改进(颜色代表优先级)

- ⚫ ~~实现服务器公钥指纹验证~~（已由TLS和mTLS替代）
- ⚫ ~~添加客户端身份验证~~（已由TLS和mTLS替代）
- ⚫ ~~将`print()`替换为日志记录系统~~（完成）
- ⚫ ~~添加服务端自动生成证书和密钥返回给客户端~~（完成）
- ⚫ ~~优化异常处理~~（完成）
- 🟡 增加心跳机制
- 🟡 从内存中销毁密钥
- 🟡 添加客户端自动重连

---

## ***⚠️免责声明***
> 本项目仅用于学习和技术研究，严禁用于任何违法犯罪活动。
> 使用者必须遵守当地法律法规，并承担使用责任。
> 本项目开发者不承担因该项目引起的任何法律责任。
