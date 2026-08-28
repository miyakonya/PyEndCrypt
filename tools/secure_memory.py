"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

"""
内存清理工具
"""

# coding: UTF-8
# Python 3.14.7

import gc
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

def clear(data: bytes | bytearray) -> None:
    try:
        if isinstance(data, bytearray):
            data[:] = b"\x00" * len(data)
            data.clear()
        elif isinstance(data, bytes):
            """bytes对象不可变，先创建可变的bytearray类型副本清除，再等待gc回收"""
            tmp = bytearray(data)
            tmp[:] = b"\x00" * len(tmp)
            tmp.clear()
    except:
        pass
    finally:
        gc.collect()
        gc.collect()

def clear_key(private_key: X25519PrivateKey) -> None:
    """清除 X25519 私钥"""
    if private_key:
        try:
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            clear(private_bytes)
        except:
            pass
    del private_key
    gc.collect()
    gc.collect()