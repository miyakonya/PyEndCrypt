# PyEndCrypt

用 Python 写的端到端加密通信工具。基于 X25519 + AES-256-GCM 的混合加密，在 TLS 之上再叠一层应用层加密，双向密钥自动轮换，每条消息使用独立派生的密钥。

定位是**端到端加密的临时通信通道**，用于传输敏感数据。

项目目前仍处于开发阶段，如果你想参与开发请看下文[工作清单](#工作清单)

> 本项目适合想了解密码工程实践、或需要一条「开箱即用的加密信道」的开发者。全部加密逻辑集中在 `tools/CryptoUtils.py`，可以按下面的 [API](#-api) 自行二次开发。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 💡特点

- **端到端加密**：X25519 密钥交换 + AES-256-GCM 认证加密。
- **双层加密**：传输层 TLS 1.3，应用层再套一层独立密钥的 AES-GCM。两层密钥来源完全独立。
- **可选 mTLS**：`auth_mode=0` 时启用双向证书认证，客户端证书由服务端在连接建立时动态签发。
- **PSK 准入认证**：TLS 之前先做一次 HMAC-SHA256 挑战应答，没有正确 PSK 连不上。
- **每条消息独立密钥**：由「会话根密钥 + 序列号」通过 HKDF-SHA256 派生。
- **双向自动密钥轮换**：任意一方发满 5 条消息即触发一次重新交换临时密钥，双方同时切换；同时发起也能正确收敛。
- **双重重放防护**：密文内打包 8 字节时间戳 + 4 字节序列号，接收端两者都校验。
- **数据包大小伪造**：可选的固定长度填充 / 随机长度填充，掩盖真实报文长度。
- **失败即断开**：任一条消息解密或校验失败，立即终止该连接，不留下「还连着但读不出数据」的中间状态。
- **内存清理**：敏感字节尽力清零并主动触发 GC。

## 🚨 已知局限

请在采用前读完这一节。

- **不能真正从内存中清除敏感数据**。Python 的 `bytes` 不可变，`tools/secure_memory.py` 对 `bytes` 入参只能清零一个临时副本；只有 `bytearray` 才能真正被覆盖。代码里已尽量用 `bytearray` 承载密钥，但无法覆盖全部路径。
- **不是完整的双棘轮**。「每条消息独立密钥 + 定期重新交换临时密钥」实现了棘轮的核心效果（前向安全 + 刷新后的后向安全），但没有对称棘轮的链式推进。
- **不支持乱序与丢包恢复**。序列号必须严格连续，收到断裂的序列号会按重放攻击处理并终止连接。底层是 TCP/TLS，正常不会乱序。
- **没有断线重连**。`Client` 断开后需要重新 `connect()`。
- **`Server.stop()` 目前不会关闭已建立的客户端连接**（只关闭监听）。已知问题，见[工作清单](#-工作清单)。
- **动态签发的客户端证书序列号固定为 `02`**，不支持按证书吊销。
- **PSK 需要带外传递**。服务端生成后写进日志，代码里没有分发通道，需要你自己传给客户端。

---

## 🔐加密方案

| 环节     | 算法                                 |
| -------- | ------------------------------------ |
| 准入认证 | HMAC-SHA256 挑战应答（PSK）          |
| 传输层   | TLS 1.3（可选 mTLS）                 |
| 密钥交换 | X25519（256 位临时密钥）             |
| 密钥派生 | HKDF-SHA256                          |
| 数据加密 | AES-256-GCM                          |
| 完整性   | AES-GCM 认证标签 + 时间戳/序列号校验 |

---

## 🔑密钥层级

```text
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

`auth_mode=0` 需要系统中有 `openssl` 可执行文件（用于动态签发客户端证书）。

---

## 🚀快速开始

先生成一套测试用证书：

```bash
python tools/generator.py
```

### 服务端

```python
import asyncio
from server import Server

async def main():
    server = Server(
        host="127.0.0.1",
        port=5555,
        server_cert="keys/server/server.crt",
        server_key="keys/server/server.key",
        ca_cert="keys/ca.crt",
        ca_key="keys/ca.key",
        padding=1,        # 数据包填充级别：0 不填充 / 1 固定 / 2 随机
        auth_mode=1       # 0 = 证书 + PSK ，1 = 仅 PSK
    )

    conn = await server.accept()          # 阻塞直到有客户端连入并完成握手
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

async def main():
    client = Client(
        host="127.0.0.1",
        port=5555,
        ca_cert="keys/ca.crt",
        psk_key="把服务端日志里的 PSK 填这里"
    )

    await client.connect()

    await client.send("Hello From Client")
    print(await client.receive())

    await client.close()

if __name__ == "__main__":
    asyncio.run(main())
```

> **关于 PSK**：服务端启动时用 `secrets.token_urlsafe(32)` 生成，并打印在日志里（`PSK 密钥已生成: ...`），同时在 `server.psk_key` 上可读。目前需要你把它带外交给客户端。

### 用 `auth_mode=0` 时会多发生什么

服务端会在握手后动态签发一份客户端证书，通过已加密的应用层通道下发给客户端；客户端写入临时目录、用它完成 mTLS，随后删除临时文件。你不需要预先准备客户端证书，只要有 CA 证书即可。

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
  │ ── 阶段 1：协商 ───────────────────────────> │
  │ <─ 编码格式 / 填充级别 / 认证模式 ────────── │
  │ ── "OK" ──────────────────────────────────> │
  │                                             │
  │ ── 阶段 2：PSK 准入认证（TLS 之前，明文）──> │
  │ <─ 32 字节随机挑战 ──────────────────────── │
  │ ── HMAC-SHA256(PSK, challenge) ───────────> │
  │ <─ "OK" / "AuthFailed" ─────────────────── │
  │                                             │
  │ ── 阶段 3：第一次 X25519 握手 ─────────────> │
  │ <─ 交换临时公钥，双方各自 init_session ──── │
  │                                             │
  │ ── 阶段 4：证书分发（仅 auth_mode=0）──────> │
  │ <─ 加密下发的 client.key / client.crt ──── │
  │                                             │
  │ ── 阶段 5：STARTTLS 原位升级 ──────────────> │
  │ <─ "READY"，随后 writer.start_tls() ────── │
  │                                             │
  │ ── 阶段 6：第二次 X25519 握手（TLS 内）───> │
  │ <─ 重新交换临时公钥，序列号归 1 ────────── │
  │                                             │
  │ ══ 阶段 7：加密通信 ═══════════════════════ │
  │ ── 每条消息独立密钥的 AES-GCM ────────────> │
  │ <─ 双方各自发满 5 条即自动轮换密钥 ─────── │
  │                                             │
  │ ── 关闭 ──────────────────────────────────> │
```

**密钥轮换的控制帧**走明文长度帧（不经应用层加密），因此不消耗序列号：

```text
REFRESH_KEY  + 我方新公钥(32)      # 发起轮换
REFRESH_ACK  + 我方新公钥(32)      # 响应轮换
```

任一方都可发起；若双方恰好同时发起，两端会复用各自已发出的公钥完成提交，收敛到同一会话（这一点有专门的回归测试覆盖）。

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

### `CryptoUtils` — 全部加密逻辑

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
| `get_challenge_response(psk, challenge)`                            | 计算 PSK 挑战应答                              |
| `verify_response(psk, challenge, response)`                         | 恒定时间比较应答                               |
| `clear_session()`                                                   | 清除会话密钥                                   |

### `Client` — 客户端

```python
Client(host: str, port: int, ca_cert: str, psk_key: str)
```

| 方法               | 说明                                    |
| ------------------ | --------------------------------------- |
| `await connect()`  | 连接并完成全部握手                      |
| `await send(data)` | 加密并发送（发满 5 条自动触发一次轮换） |
| `await receive()`  | 接收并解密；返回 `None` 表示对端已断开  |
| `await close()`    | 关闭连接并清理密钥                      |

### `Server` — 服务端

```python
Server(host, port, server_cert="", server_key="",
       ca_cert="", ca_key="", padding=0, auth_mode=0, encoding="utf-8")
```

| 方法             | 说明                                                     |
| ---------------- | -------------------------------------------------------- |
| `await accept()` | 启动监听并等待一个已完成握手的连接，返回 `ClientHandler` |
| `await stop()`   | 停止监听                                                 |

`auth_mode`：`0` = 证书 + PSK 双重认证（启用 mTLS）；`1` = 仅 PSK（关闭 mTLS）。传入其他值会抛 `ValueError`。

### `ClientHandler` — 服务端每个连接的处理器

由 `Server.accept()` 返回，接口与 `Client` 对称：

| 方法                                   | 说明                            |
| -------------------------------------- | ------------------------------- |
| `await send(data, is_handshake=False)` | 加密并发送                      |
| `await receive()`                      | 接收并解密；`None` 表示对端断开 |
| `await close()`                        | 关闭连接                        |

### `Generator` — 客户端证书签发

```python
Generator(ca_cert: str, ca_key: str)   # 需要系统中存在 openssl
```

| 方法                        | 说明                                |
| --------------------------- | ----------------------------------- |
| `generate_key()`            | 生成客户端私钥，返回 `(内容, 路径)` |
| `generate_cert(client_key)` | 用 CA 签发客户端证书，返回内容      |

---

## 🏗️项目结构

```text
PyEndCrypt/
├── README.md
├── LICENSE
├── server.py                        # 服务端：监听、接受连接
├── client.py                        # 客户端：连接、握手、收发
└── tools/
    ├── CryptoUtils.py               # 全部加解密与密钥派生
    ├── NetworkBase.py               # 定长收发基类 + 填充
    ├── ClientHandler.py             # 服务端单连接处理器
    ├── CredentialProvisioner.py     # 动态签发客户端证书（依赖 openssl）
    ├── secure_memory.py             # 敏感内存清理
    ├── Logger.py                    # 日志（文件 + 控制台，同名复用）
    ├── generator.py                 # 一键生成 CA / 服务端证书
    ├── exceptions.py                # 异常体系
    └── __init__.py
```

---

## 📝工作清单

已完成：

- ⚫ ~~添加客户端身份验证~~（已由 TLS / mTLS + PSK 替代）
- ⚫ ~~将 `print()` 替换为日志系统~~
- ⚫ ~~服务端自动生成证书和密钥返回给客户端~~
- ⚫ ~~优化异常处理~~
- ⚫ ~~从内存中销毁密钥~~（受 Python 限制，见[已知局限](#-已知局限)）
- ⚫ ~~实现异步~~
- ⚫ ~~实现多客户端并发处理~~
- ⚫ ~~每条消息独立密钥 + 双向自动密钥轮换~~

待办：

- 🟡 `Server.stop()` 关闭已建立的客户端连接
- 🟡 主动关闭指定客户端（`Server.close_client()`）
- 🟡 动态签发证书的序列号唯一化（当前固定为 `02`）
- 🟡 客户端证书临时文件的并发隔离（当前使用固定相对路径）
- 🟡 断线重连
- 🟡 心跳机制
- 🟡 中转服务器

---

## ⚠️免责声明

> 本项目仅用于学习和技术研究，严禁用于任何违法犯罪活动。
> 使用者必须遵守当地法律法规，并承担使用责任。
> 本项目开发者不承担因该项目引起的任何法律责任。
