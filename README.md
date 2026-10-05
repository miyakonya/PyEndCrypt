# PyEndCrypt

用 Python 写的端到端加密通信工具。**TLS 1.3 + external PSK 认证**，在认证通道内再叠一层应用层 AES-256-GCM（X25519 交换 + 每条消息独立密钥 + 双向自动轮换）。

定位是**端到端加密的临时通信通道**，用于在互相信任的少数几方之间传输敏感数据。

项目目前仍处于开发阶段，如果你想参与开发请看下文[工作清单](#-工作清单)

> 本项目适合想了解密码工程实践、或需要一条「开箱即用的加密信道」的开发者。全部加密逻辑集中在 `tools/CryptoUtils.py`，TLS 与 PSK 认证集中在 `Server` / `Client` / `ClientHandler`，可以按下面的 [API](#-api) 自行二次开发。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 💡特点

- **PSK 就是唯一凭据**：双方预共享一个 PSK，认证在 TLS 握手内部完成（TLS 1.3 external PSK）。
- **认证失败发生在握手阶段**：PSK 不对，TLS 握手直接失败，攻击者拿不到任何已认证的连接。
- **应用层再加密**：TLS 之上叠一层独立密钥来源的 AES-256-GCM（X25519 + HKDF），两层密钥完全独立。
- **每条消息独立密钥**：由「会话根密钥 + 序列号」通过 HKDF-SHA256 派生。
- **双向自动密钥轮换**：任意一方发满 5 条消息即触发一次重新交换临时密钥，双方同时切换；同时发起也能正确收敛。
- **双重重放防护**：密文内打包 8 字节时间戳 + 4 字节序列号，接收端两者都校验。
- **数据包大小伪造**：可选的固定长度填充 / 随机长度填充，掩盖真实报文长度。
- **失败即断开**：任一条消息解密或校验失败，立即终止该连接。
- **内存清理**：敏感字节尽力清零并主动触发 GC。

## 🚨 已知局限

请在采用前读完这一节。

- **不能真正从内存中清除敏感数据**。Python 的 `bytes` 不可变，`tools/secure_memory.py` 对 `bytes` 入参只能清零一个临时副本；只有 `bytearray` 才能真正被覆盖。代码里已尽量用 `bytearray` 承载密钥，但无法覆盖全部路径。
- **不支持乱序与丢包恢复**。序列号必须严格连续，收到断裂的序列号会按重放攻击处理并终止连接。底层是 TCP/TLS，正常不会乱序。
- **没有断线重连**。`Client` 断开后需要重新 `connect()`。
- **没有心跳机制**。空闲连接不会自动探测存活。

---

## 🔐加密方案

| 环节     | 算法                                                   |
| -------- | ------------------------------------------------------ |
| 准入认证 | TLS 1.3 external PSK（身份 + 预共享密钥，binder 校验） |
| 传输层   | TLS 1.3（`psk_dhe_ke`，带 ECDHE，具备前向安全）        |
| 密钥交换 | X25519（应用层，256 位临时密钥）                       |
| 密钥派生 | HKDF-SHA256                                            |
| 数据加密 | AES-256-GCM                                            |
| 完整性   | TLS 记录层 + AES-GCM 认证标签 + 时间戳/序列号校验      |

> **关于两层的关系**：TLS 1.3 + PSK 已经提供了经过认证的加密通道；应用层的 X25519 + AES-GCM 是**额外**的一层（密钥来源与 TLS 完全独立），主要用于防止 TLS 被中途终结。如果你只信任一条链路，可以把应用层看作冗余。

---

## 🔑密钥层级

```text
PSK (双方带外共享, 1..64 字节)
   ↓ TLS 1.3 external PSK 握手（binder 校验）
经过认证的 TLS 通道
   ↓ 通道内交换 X25519 临时公钥
临时密钥对 (X25519, 每次握手/轮换重新生成)
   ↓ DH(自己的新私钥, 对方的新公钥)
共享密钥 (Shared Secret)
   ↓ HKDF-SHA256(salt="session_root")
会话根密钥 (Root Key)          ← 每 5 条消息双方重新交换临时密钥
   ↓ HKDF-SHA256(salt="message_salt", info=seq)
消息密钥₁  消息密钥₂  消息密钥₃ ...
   ↓          ↓          ↓
AES-GCM   AES-GCM   AES-GCM     ← 每条消息一个密钥 + 独立随机 nonce
```

两端的**收发各自一条独立序列号链**：`send_seq` 只在自己发送时递增，`recv_seq` 只在收到消息时递增。因此收发交替、任意方向连发都不会错位。

---

## 📦依赖安装

```bash
pip install cryptography
```

---

## 🚀快速开始

### 1. 生成 PSK

没有任何证书要生成。PSK 由你自己生成（或由服务端生成后带外交给客户端）：

```python
import secrets
psk = secrets.token_bytes(32)      # TLS 1.3 要求 1..64 字节
```

### 服务端

```python
import asyncio
from server import Server

PSK = b"\x01\x02..."     # 与服务端共享的那个 PSK，务必带外安全传递

async def main():
    server = Server(
        host="127.0.0.1",
        port=5555,
        psk_key=PSK,
        padding=1,        # 数据包填充级别：0 不填充 / 1 固定 / 2 随机
    )

    conn = await server.accept()          # 阻塞直到有客户端通过 PSK 认证
    print("客户端已连接")

    data = await conn.receive()           # 收到字符串；None 表示断开
    print(f"收到: {data}")

    await conn.send("Hello From Server")
    await conn.close()

    await server.stop()

if __name__ == "__main__":
    asyncio.run(main())
```

### 客户端

```python
import asyncio
from client import Client

PSK = b"\x01\x02..."     # 与服务端一致

async def main():
    client = Client(
        host="127.0.0.1",
        port=5555,
        psk_key=PSK,
    )

    await client.connect()                # PSK 不对会在这里直接失败

    await client.send("Hello From Client")
    print(await client.receive())

    await client.close()

if __name__ == "__main__":
    asyncio.run(main())
```

> **关于 PSK 认证**：认证发生在 `writer.start_tls()` 那一刻。PSK 不一致时 TLS 握手失败，
> 客户端抛 `ssl.SSLError`，服务端日志记录握手失败。**没有「握手成功后才发现 PSK 不对」的路径。**

---

## 📐数据结构

### 一个数据包（应用层加密前）

```text
┌──────────┬──────────────┬──────────┬──────────┐
│ 总长度头 │  原文长度头  │   原文   │   填充   │
│  4 字节  │   4 字节     │   变长   │   变长   │
└──────────┴──────────────┴──────────┴──────────┘
```

- **总长度头**：由 `NetworkBase._send_raw()` / `_recv_exact()` 使用，保证按帧读取。
- **填充**：仅在 `padding != 0` 时存在。

**原文**在 `CryptoUtils._pack()` 里还会前置 12 字节校验数据：

```text
┌──────────────┬──────────────┬──────────┐
│ 时间戳(8)    │ 序列号(4)    │  业务数据 │
└──────────────┴──────────────┴──────────┘
```

### 一个数据包（应用层加密后）

```text
┌──────────┬────────────────────┬──────────────────────┐
│  Nonce   │ 发送方当前临时公钥 │  AES-GCM 密文与标签  │
│  12 字节 │       32 字节      │        变长          │
└──────────┴────────────────────┴──────────────────────┘
```

接收端从包内取出发送方公钥，与自己的临时私钥现算共享密钥 —— 因此**密钥轮换期间即使双方切换时机有细微交错，也能正确解密**。

### 填充级别

```text
0：不填充
1：固定大小填充，补到 128 字节的整数倍
2：随机大小填充，增加 1 ~ min(256, 剩余可用空间) 字节
```

---

## 🔄连接与消息流程

```text
客户端                                        服务端
  │                                             │
  │ ── TCP 连接 ──────────────────────────────> │
  │                                             │
  │ ── 阶段 1：协商（明文）───────────────────> │
  │ <─ 编码格式 / 填充级别 ──────────────────── │
  │ ── "OK" ──────────────────────────────────> │
  │                                             │
  │ ── 阶段 2：STARTTLS ───────────────────────> │
  │ <─ "READY" ──────────────────────────────── │
  │                                             │
  │ ══ 阶段 3：TLS 1.3 + PSK 认证 ═════════════ │
  │    writer.start_tls(带 PSK 回调的 context)  │
  │    ← PSK 不对就在这里失败，后面的阶段不会发生 │
  │                                             │
  │ ── 阶段 4：应用层 X25519 握手（TLS 通道内）─> │
  │ <─ 交换临时公钥，双方各自 init_session ──── │
  │ ── "Client Hello" ────────────────────────> │
  │ <─ "Server Hello" ───────────────────────── │
  │                                             │
  │ ══ 阶段 5：加密通信 ═══════════════════════ │
  │ ── 每条消息独立密钥的 AES-GCM ────────────> │
  │ <─ 双方各自发满 5 条即自动轮换密钥 ─────── │
  │                                             │
  │ ── 关闭 ──────────────────────────────────> │
```

**控制帧**（密钥轮换）走明文长度帧，因此不消耗应用层序列号：

```text
REFRESH_KEY  + 我方新公钥(32)      # 发起轮换
REFRESH_ACK  + 我方新公钥(32)      # 响应轮换
```

任一方都可发起；若双方恰好同时发起，两端会复用各自已发出的公钥完成提交，收敛到同一会话（这一点有专门的回归验证覆盖）。

> 注意：控制帧不受 TLS 记录层之外的额外保护；在 TLS 之内传输，因此依赖 TLS 保证完整性。

---

## 🔌API

### `NetworkBase` — 通信基类

底层定长收发与填充处理。

| 方法                                           | 说明                     |
| ---------------------------------------------- | ------------------------ |
| `_recv_exact(n)`                               | 精确接收 n 字节          |
| `_send_raw(data)`                              | 发送一个带长度头的原始帧 |
| `_recv_raw()`                                  | 接收一个原始帧           |
| `_add_padding(data)` / `_remove_padding(data)` | 填充与去填充             |
| `close()`                                      | 关闭底层连接             |

### `CryptoUtils` — 应用层加密逻辑

| 方法                                                                | 说明                                           |
| ------------------------------------------------------------------- | ---------------------------------------------- |
| `generate_keypair()`                                                | 生成 X25519 临时密钥对                         |
| `init_session(private_key, peer_public_key)`                        | 用**已交换**的临时私钥建立会话，返回自己的公钥 |
| `refresh_session(own_private_key, own_public_key, peer_public_key)` | 双方新公钥到齐后提交一次会话轮换               |
| `derive_message_key(seq)`                                           | 由根密钥派生某序列号的消息密钥                 |
| `derive_shared_key(private_key, peer_public_bytes)`                 | X25519 交换出共享密钥                          |
| `shared_key_derive_aes_key(shared_key, salt)`                       | 由共享密钥派生 AES 密钥                        |
| `aes_encrypt(data, seq)`                                            | 加密，返回 `nonce + 公钥 + 密文`               |
| `aes_decrypt(data, seq, private_key)`                               | 解密并校验时间戳与序列号                       |
| `clear_session()`                                                   | 清除会话密钥                                   |


### `Client` — 客户端

```python
Client(host: str, port: int, psk_key: bytes)
```

| 方法               | 说明                                     |
| ------------------ | ---------------------------------------- |
| `await connect()`  | 连接并完成协商、TLS-PSK 认证与应用层握手 |
| `await send(data)` | 加密并发送（发满 5 条自动触发一次轮换）  |
| `await receive()`  | 接收并解密；返回 `None` 表示对端已断开   |
| `await close()`    | 关闭连接并清理密钥                       |

### `Server` — 服务端

```python
Server(host, port, psk_key: bytes, padding=0, encoding="utf-8")
```

| 方法             | 说明                                                        |
| ---------------- | ----------------------------------------------------------- |
| `await accept()` | 启动监听并等待一个通过 PSK 认证的连接，返回 `ClientHandler` |
| `await stop()`   | 停止监听（不关闭已建立的连接）                              |

### `ClientHandler` — 服务端每个连接的处理器

由 `Server.accept()` 返回，接口与 `Client` 对称：

| 方法               | 说明                            |
|--------------------|---------------------------------|
| `await send(data)` | 加密并发送                      |
| `await receive()`  | 接收并解密；`None` 表示对端断开 |
| `await close()`    | 关闭连接                        |

---

## 🏗️项目结构

```text
PyEndCrypt/
├── README.md
├── LICENSE
├── server.py                        # 服务端：监听、PSK 认证、接受连接
├── client.py                        # 客户端：连接、STARTTLS、PSK 认证、收发
└── tools/
    ├── CryptoUtils.py               # 应用层加解密与密钥派生
    ├── NetworkBase.py               # 定长收发基类 + 填充
    ├── ClientHandler.py             # 服务端单连接处理器
    ├── secure_memory.py             # 敏感内存清理
    ├── Logger.py                    # 日志（文件 + 控制台，同名复用）
    ├── exceptions.py                # 异常体系
    └── __init__.py
```

---

## 📝工作清单

已完成：

- ⚫ ~~添加客户端身份验证~~（已改为 TLS 1.3 external PSK）
- ⚫ ~~将 `print()` 替换为日志系统~~
- ⚫ ~~服务端自动生成证书和密钥返回给客户端~~（证书体系已整体移除）
- ⚫ ~~优化异常处理~~
- ⚫ ~~从内存中销毁密钥~~（受 Python 限制，见[已知局限](#-已知局限)）
- ⚫ ~~实现异步~~
- ⚫ ~~实现多客户端并发处理~~
- ⚫ ~~每条消息独立密钥 + 双向自动密钥轮换~~
- ⚫ ~~移除 mTLS，改用 PSK 作为唯一凭据~~

待办：

- 🟡 `Server.stop()` 关闭已建立的客户端连接
- 🟡 主动关闭指定客户端（`Server.close_client()`）
- 🟡 断线重连
- 🟡 心跳机制
- 🟡 中转服务器

---

## ⚠️免责声明

> 本项目仅用于学习和技术研究，严禁用于任何违法犯罪活动。
> 使用者必须遵守当地法律法规，并承担使用责任。
> 本项目开发者不承担因该项目引起的任何法律责任。
