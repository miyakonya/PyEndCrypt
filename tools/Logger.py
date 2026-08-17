# coding: UTF-8
# Python 3.10.6

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

# 自动刷新
class AutoFlushFileHandler(logging.FileHandler):
    def emit(self, record):
        super().emit(record)
        self.flush()

class Logger:
    def __init__(self, name: str):
        if not os.path.exists("logs") and not os.path.isdir("logs"):
            os.mkdir("logs")
        file_name = time.strftime(f"{name}-%Y-%m-%d %H-%M-%S.logs", time.localtime())
        file_handler = AutoFlushFileHandler(f"logs/{file_name}", encoding="utf-8", mode="a")
        formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
        file_handler.setFormatter(formatter)
        logging.basicConfig(
            level=logging.INFO,
            format="[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        self.logger = logging.getLogger(name)
        self.logger.addHandler(file_handler)

    def getLogger(self):
        return self.logger
