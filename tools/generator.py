"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

"""
生成 CA 证书密钥和服务端证书密钥(生产环境请勿使用)
"""

# coding: UTF-8
# Python 3.14.7

import subprocess
import os


def generate_all_certs():
    os.makedirs("keys/server", exist_ok=True)
    os.makedirs("keys/client", exist_ok=True)
    # 创建 OpenSSL 配置文件
    openssl_config = """
[ req ]
distinguished_name     = req_distinguished_name
prompt                 = no

[ req_distinguished_name ]
CN                     = PyEndCrypt Root CA

[ ca_ext ]
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always

[ server_ext ]
basicConstraints       = CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth, clientAuth
subjectAltName         = DNS:localhost, IP:127.0.0.1
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always

[ client_ext ]
basicConstraints       = CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = clientAuth, serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
"""

    with open("openssl.cnf", "w") as f:
        f.write(openssl_config)

    try:
        print("开始生成 CA 证书...")
        subprocess.run(["openssl", "genrsa", "-out", "keys/ca.key", "2048"], check=True)
        subprocess.run([
            "openssl", "req", "-new", "-x509", "-days", "3650",
            "-key", "keys/ca.key",
            "-out", "keys/ca.crt",
            "-config", "openssl.cnf",
            "-extensions", "ca_ext"
        ], check=True)
        print("CA 证书生成完毕: keys/ca.crt")

        print("开始生成服务器私钥...")
        subprocess.run(["openssl", "genrsa", "-out", "keys/server/server.key", "2048"], check=True)
        print("keys/server/server.key")

        print("开始生成服务器 CSR...")
        subprocess.run([
            "openssl", "req", "-new",
            "-key", "keys/server/server.key",
            "-out", "keys/server/server.csr",
            "-subj", "/CN=localhost"
        ], check=True)

        print("开始生成签发服务器证书...")
        subprocess.run([
            "openssl", "x509", "-req", "-days", "365",
            "-in", "keys/server/server.csr",
            "-CA", "keys/ca.crt",
            "-CAkey", "keys/ca.key",
            "-set_serial", "01",
            "-out", "keys/server/server.crt",
            "-extfile", "openssl.cnf",
            "-extensions", "server_ext"
        ], check=True)
        print("  ✅ keys/server/server.crt")

        # 清理临时文件
        for f in ["keys/server/server.csr", "keys/client/client.csr", "openssl.cnf"]:
            if os.path.exists(f):
                os.remove(f)

        print("\n" + "=" * 60)
        print("所有证书生成成功！")
    except subprocess.CalledProcessError as e:
        print(f"\n证书生成失败: {e}")
        raise
    except Exception as e:
        print(f"\n错误: {e}")
        raise


if __name__ == "__main__":
    generate_all_certs()