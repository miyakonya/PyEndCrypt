# coding: UTF-8
# Python 3.14.7

"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

"""
日志记录器
"""

import logging
import time
import os
import sys

# 自动刷新
class AutoFlushFileHandler(logging.FileHandler):
    def emit(self, record):
        super().emit(record)
        self.flush()

class Logger:
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)

        # 已经配置过的直接复用
        if self.logger.handlers:
            return
        os.makedirs("logs", exist_ok=True)
        file_name = time.strftime(f"{name}-%Y-%m-%d %H-%M-%S.log", time.localtime())
        formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")

        # 文件处理器
        self.file_handler = AutoFlushFileHandler(f"logs/{file_name}", encoding="utf-8", mode="a")
        self.file_handler.setFormatter(formatter)
        self.logger.addHandler(self.file_handler)

        # 控制台处理器
        self.console_handler = logging.StreamHandler(sys.stderr)
        self.console_handler.setFormatter(formatter)
        self.logger.addHandler(self.console_handler)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

    def getLogger(self):
        return self.logger

