"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

"""
客户端证书和密钥提供器
"""

# coding: UTF-8
# Python 3.14.7

import subprocess
import os
import shutil
from .Logger import Logger

class Generator:
    def __init__(self, ca_cert: str, ca_key: str):
        self.logger = Logger("CredentialProvisioner").getLogger()
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        if not shutil.which("openssl"):
            raise EnvironmentError("尚未安装openssl，请先安装openssl")

    def generate_cert(self, client_key):
        """生成客户端证书"""
        try:
            subprocess.run([
                "openssl", "req", "-new", "-key", f"{client_key}",
                "-out", "certs/client.csr", "-subj", "/CN=client"
            ], check=True)
            subprocess.run([
                "openssl", "x509", "-req", "-days", "365",
                "-in", "certs/client.csr", "-CA", f"{self.ca_cert}",
                "-CAkey", f"{self.ca_key}", "-set_serial", "02",
                "-out", "certs/client.crt"
            ], check=True)

            with open("certs/client.crt", "r") as r:
                client_cert = r.read()
            shutil.rmtree("certs")
            return client_cert

        except subprocess.CalledProcessError as e:
            self.logger.error(f"客户端证书生成失败: {e}")
            raise
    def generate_key(self):
        """生成客户端密钥"""
        try:
            if not os.path.exists("certs") and not os.path.isdir("certs"):
                os.mkdir("certs")
            subprocess.run([
                "openssl", "genrsa", "-out", "certs/client.key", "2048"
            ], check=True)

            with open("certs/client.key", "r") as r:
                client_key = r.read()
            path = os.path.abspath("certs/client.key")
            return client_key, path

        except subprocess.CalledProcessError as e:
            self.logger.error(f"客户端密钥生成失败: {e}")
            raise
        except PermissionError:
            self.logger.error("权限不足")
        except OSError as e:
            self.logger.error(f"生成失败: {e}")
