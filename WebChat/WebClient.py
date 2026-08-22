"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

# coding: UTF-8
# Python 3.14.7

import sys
sys.path.append("..")

import json
import socket
import threading
import uuid
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room
from client import Client
from tools.CryptoUtils import CryptoUtils
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = "client-secret-key-2024"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

with open("config.json", "r") as r:
    config = json.load(r)

CHAT_SERVER_URL = config["WebClient"]["ChatServerURL"]
RELAY_WS_URL = config["WebClient"]["WebSocketURL"]

# 全局客户端实例
web_client = None

# 房间密钥管理
room_keys = {}  # room_id -> aes_key (bytes)
room_messages = {}  # room_id -> [{"username": str, "message": str, "timestamp": str}]


class WebClient(Client):
    def __init__(self, host: str, port: int, ca_cert: str, padding: int, encoding:str, username: str = None):
        super().__init__(host, port, ca_cert, padding, encoding)

        self.username = username or f"用户_{uuid.uuid4().hex[:6]}"
        self.current_room = None
        self._running = True
        self._receive_thread = None

    def start(self):
        """启动客户端连接"""
        self.connect()
        print(f"WebClient 连接成功 (用户: {self.username})")

        # 启动消息接收线程
        def receive_loop():
            while self._running and self.handshake_done:
                try:
                    if self.ssl_sock:
                        self.ssl_sock.settimeout(0.5)
                    data = self.receive()
                    if data:
                        self._handle_received_data(data)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self._running:
                        print(f"接收错误: {e}")
                    break

        self._receive_thread = threading.Thread(target=receive_loop, daemon=True)
        self._receive_thread.start()
        print("消息接收线程已启动")

    def _handle_received_data(self, data):
        """处理接收到的数据"""
        try:
            if isinstance(data, str):
                data = json.loads(data)

            msg_type = data.get("type")

            if msg_type == "chat_message":
                room_id = data.get("room_id")
                encrypted_hex = data.get("data")
                from_user = data.get("from", "未知")
                timestamp = data.get("timestamp", "")

                if room_id in room_keys:
                    aes_key = room_keys[room_id]
                    encrypted = bytes.fromhex(encrypted_hex)
                    decrypted = CryptoUtils.aes_decrypt(aes_key, encrypted, self.seq)
                    self.seq += 1

                    plaintext = decrypted.decode("utf-8")
                    print(f"[{room_id}] {from_user}: {plaintext}")

                    if room_id not in room_messages:
                        room_messages[room_id] = []
                    room_messages[room_id].append({
                        "username": from_user,
                        "message": plaintext,
                        "timestamp": timestamp or "--:--:--"
                    })

                    socketio.emit("new_message", {
                        "username": from_user,
                        "message": plaintext,
                        "timestamp": timestamp or "--:--:--"
                    })
                else:
                    print(f"房间 {room_id} 没有密钥")

            elif msg_type == "key_distribution":
                room_id = data.get("room_id")
                encrypted_key_hex = data.get("encrypted_key")

                encrypted_key = bytes.fromhex(encrypted_key_hex)
                room_aes_key = CryptoUtils.ecc_decrypt(self.client_key, encrypted_key)

                room_keys[room_id] = room_aes_key
                print(f"房间 {room_id} 密钥已接收")

                socketio.emit("key_ready", {
                    "room_id": room_id,
                    "message": "房间密钥已就绪，可以开始加密通信"
                })

            elif msg_type == "user_joined":
                room_id = data.get("room_id")
                username = data.get("username")
                socketio.emit("system_message", {
                    "message": f"{username} 加入了房间"
                })

            elif msg_type == "user_left":
                room_id = data.get("room_id")
                username = data.get("username")
                socketio.emit("system_message", {
                    "message": f"{username} 离开了房间"
                })

            elif msg_type == "join_success":
                room_id = data.get("room_id")
                username = data.get("username")
                self.current_room = room_id
                socketio.emit("join_success", {
                    "room_id": room_id,
                    "username": username,
                    "message": f"已加入房间 {room_id}"
                })

        except Exception as e:
            print(f"处理接收数据错误: {e}")

    def send_encrypted_message(self, room_id: str, message: str):
        """发送加密消息"""
        if room_id not in room_keys:
            print(f"房间 {room_id} 没有密钥")
            return False

        aes_key = room_keys[room_id]
        encrypted = CryptoUtils.aes_encrypt(aes_key, message.encode("utf-8"), self.seq)
        self.seq += 1

        self.send({
            "type": "chat_message",
            "room_id": room_id,
            "from": self.username,
            "data": encrypted.hex(),
            "timestamp": "--:--:--"
        })

        return True

    def stop(self):
        self._running = False
        self.close()

@socketio.on("connect")
def handle_connect():
    print(f"浏览器已连接: {request.sid}")
    emit("connected", {"status": "ok"})


@socketio.on("disconnect")
def handle_disconnect():
    print(f"浏览器已断开: {request.sid}")


@socketio.on("join_room")
def handle_join_room(data):
    """浏览器请求加入房间"""
    room_id = data.get("room_id")
    username = data.get("username", "用户")

    if not room_id:
        emit("error", {"message": "房间号不能为空"})
        return

    if web_client:
        web_client.username = username

    join_room(room_id)

    if room_id in room_messages:
        for msg in room_messages[room_id][-50:]:
            emit("new_message", msg)

    emit("join_success", {
        "room_id": room_id,
        "username": username,
        "history": room_messages.get(room_id, [])[-50:]
    })


@socketio.on("send_message")
def handle_send_message(data):
    """浏览器发送消息"""
    room_id = data.get("room_id")
    message = data.get("message")
    username = data.get("username", "用户")

    if not room_id or not message:
        emit("error", {"message": "消息不能为空"})
        return

    if web_client:
        web_client.username = username

    if web_client:
        success = web_client.send_encrypted_message(room_id, message)
        if not success:
            emit("error", {"message": "房间密钥未就绪"})


@socketio.on("create_room")
def handle_create_room(data):
    """浏览器创建房间"""
    username = data.get("username", "用户")
    room_id = str(uuid.uuid4())[:8]

    if web_client:
        web_client.username = username

    if web_client:
        web_client.send({
            "type": "create_room",
            "room_id": room_id,
            "username": username
        })

    emit("room_created", {
        "room_id": room_id,
        "username": username,
        "message": f"房间 {room_id} 创建成功"
    })


@socketio.on("leave_room")
def handle_leave_room():
    """浏览器离开房间"""
    if web_client:
        web_client.send({
            "type": "leave_room",
            "username": web_client.username
        })

    emit("left_room", {"message": "已离开房间"})


@app.route("/")
def index():
    return render_template("index.html", server_url=CHAT_SERVER_URL)


@app.route("/server_info")
def get_server_info():
    return {
        "status": "online",
        "server": CHAT_SERVER_URL,
        "username": web_client.username if web_client else None,
        "rooms": len(room_keys)
    }

if __name__ == "__main__":
    try:
        host = config["WebClient"]["Host"]
        port = int(config["WebClient"]["Port"])
        ca_cert = config["WebClient"]["CaCert"]
        padding = int(config["WebClient"]["Padding"])
        encoding = config["WebClient"]["Encoding"]
        rhost = config["WebClient"]["RelayServer"]["Host"]
        rwsport = config["WebClient"]["RelayServer"]["WebSocketPort"]
        if not os.path.exists(ca_cert):
            raise FileNotFoundError("没有找到 CA 证书文件")
        print("=" * 60)
        print("正在启动...")
        print(f"Web界面地址: {config["WebClient"]["ChatServerURL"]}")
        print("=" * 60)

        web_client = WebClient(rhost, rwsport, ca_cert, padding, encoding)
        web_client.start()

        socketio.run(app, host=host, port=port, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
    except Exception as e:
        raise Exception(f"配置文件有误，请检查: {e}")