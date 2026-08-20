"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

"""
SSL 连接构建器
"""

# coding: UTF-8
# Python 3.14.7

import ssl

class Builder:
    def __init__(self, cert: str,
                 key: str,
                 ca_cert: str,
                 is_server):
        self.cert = cert
        self.key = key
        self.ca_cert = ca_cert
        self.is_server = is_server
        if self.is_server:
            self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        else:
            self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            self.context.check_hostname = False
        self.context.load_verify_locations(cafile=self.ca_cert)  # 加载 CA 证书
        self.context.load_cert_chain(certfile=self.cert, keyfile=self.key)    # 加载自己的证书和密钥
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.maximum_version = ssl.TLSVersion.TLSv1_3
