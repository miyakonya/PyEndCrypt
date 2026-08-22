"""
Copyright (c) 2026 super cat
This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""

# coding: UTF-8
# Python 3.14.7

import sys
sys.path.append("..")

from flask_socketio import SocketIO, join_room, leave_room, emit
import uuid
from tools.Logger import Logger
from datetime import datetime
from flask import Flask, request
from server import Server
import shutil
import threading
import json
import os

with open("config.json", "r") as r:
    config = json.load(r)

app = Flask(__name__)
app.config["SECRET_KEY"] = "chat-server-secret-key-2024"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")


class RelayServer(Server):
    """中转服务器 - 处理客户端连接和WebSocket消息转发"""

    _instance = None  # 类变量，保存单例实例

    def __init__(self, host: str,
                 port: int,
                 listen: int,
                 server_cert: str,
                 server_key: str,
                 ca_cert: str,
                 ca_key: str,
                 padding: int = 0,
                 encoding: str = "utf-8"):
        super().__init__(host, port, listen, server_cert, server_key, ca_cert, ca_key, padding, encoding)

        # 保存单例实例
        RelayServer._instance = self

        self.host = host
        self.port = port
        self.server_cert = server_cert
        self.server_key = server_key
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.encoding = encoding
        self.logger = Logger("RelayServer").getLogger()
        self.running = True

        # 客户端连接存储
        self._clients = {}  # addr -> handler

        # 房间信息
        self.rooms = {}  # room_id: {"users": {sid: username}, "messages": []}
        # 用户信息
        self.users = {}  # sid: {"username": str, "room": str}
        # 服务器信息
        self.server_info = {
            "start_time": datetime.now(),
            "total_connections": 0,
            "active_connections": 0
        }

        # 注册 SocketIO 事件处理器
        self._register_socketio_handlers()

    @classmethod
    def get_instance(cls):
        """获取单例实例"""
        return cls._instance

    def _register_socketio_handlers(self):
        """注册所有 SocketIO 事件处理器"""

        @socketio.on("connect")
        def handle_connect():
            """WebSocket 客户端连接"""
            rs = RelayServer.get_instance()
            if rs is None:
                app.logger.warning("RelayServer 未初始化")
                return

            client_ip = request.remote_addr if hasattr(request, "remote_addr") else "unknown"
            app.logger.info(f"🔗 WebSocket 客户端连接: {request.sid} from {client_ip}")

            rs.server_info["total_connections"] += 1
            rs.server_info["active_connections"] += 1

            rs.users[request.sid] = {
                "username": f"用户_{request.sid[:6]}",
                "room": None,
                "ip": client_ip,
                "connected_at": datetime.now()
            }

            emit("connected", {
                "sid": request.sid,
                "message": "连接成功",
                "server_time": datetime.now().isoformat()
            })

        @socketio.on("disconnect")
        def handle_disconnect():
            """WebSocket 客户端断开连接"""
            rs = RelayServer.get_instance()
            if rs is None:
                return

            sid = request.sid
            app.logger.info(f"🔌 WebSocket 客户端断开: {sid}")

            rs.server_info["active_connections"] -= 1

            if sid in rs.users:
                user_info = rs.users[sid]
                room_id = user_info.get("room")
                username = user_info.get("username", "用户")

                if room_id and room_id in rs.rooms:
                    if sid in rs.rooms[room_id]["users"]:
                        del rs.rooms[room_id]["users"][sid]

                    emit("system_message", {
                        "message": f"{username} 离开了房间",
                        "type": "leave",
                        "username": "系统",
                        "timestamp": datetime.now().strftime("%H:%M:%S")
                    }, room=room_id)

                    if not rs.rooms[room_id]["users"]:
                        del rs.rooms[room_id]
                        app.logger.info(f"房间 {room_id} 已删除 (空)")

                del rs.users[sid]

        @socketio.on("create_room")
        def handle_create_room(data):
            """创建房间"""
            rs = RelayServer.get_instance()
            if rs is None:
                return

            sid = request.sid
            username = data.get("username", rs.users.get(sid, {}).get("username", f"用户_{sid[:6]}"))

            room_id = str(uuid.uuid4())[:8]

            rs.rooms[room_id] = {
                "users": {sid: username},
                "messages": [],
                "created_at": datetime.now(),
                "creator": username
            }

            if sid in rs.users:
                rs.users[sid]["username"] = username
                rs.users[sid]["room"] = room_id

            join_room(room_id)

            app.logger.info(f"房间创建: {room_id} by {username}")

            emit("room_created", {
                "room_id": room_id,
                "username": username,
                "message": f"房间 {room_id} 创建成功"
            })

            emit("system_message", {
                "message": f"{username} 创建了房间 {room_id}",
                "type": "create",
                "username": "系统",
                "timestamp": datetime.now().strftime("%H:%M:%S")
            }, room=room_id)

        @socketio.on("join_room")
        def handle_join_room(data):
            """加入房间"""
            rs = RelayServer.get_instance()
            if rs is None:
                return

            sid = request.sid
            room_id = data.get("room_id")
            username = data.get("username", rs.users.get(sid, {}).get("username", f"用户_{sid[:6]}"))

            if not room_id:
                emit("error", {"message": "房间号不能为空"})
                return

            if room_id not in rs.rooms:
                emit("error", {"message": "房间不存在"})
                return

            if sid in rs.users:
                rs.users[sid]["username"] = username
                rs.users[sid]["room"] = room_id

            rs.rooms[room_id]["users"][sid] = username
            join_room(room_id)

            app.logger.info(f"👤 {username} 加入房间 {room_id}")

            emit("room_joined", {
                "room_id": room_id,
                "username": username,
                "history": rs.rooms[room_id]["messages"][-50:],
                "users": list(rs.rooms[room_id]["users"].values())
            })

            emit("system_message", {
                "message": f"{username} 加入了房间",
                "type": "join",
                "username": "系统",
                "timestamp": datetime.now().strftime("%H:%M:%S")
            }, room=room_id, skip_sid=sid)

        @socketio.on("leave_room")
        def handle_leave_room(data):
            """离开房间"""
            rs = RelayServer.get_instance()
            if rs is None:
                return

            sid = request.sid

            if sid not in rs.users:
                return

            user_info = rs.users[sid]
            room_id = user_info.get("room")
            username = user_info.get("username", "用户")

            if not room_id or room_id not in rs.rooms:
                emit("error", {"message": "您不在任何房间中"})
                return

            if sid in rs.rooms[room_id]["users"]:
                del rs.rooms[room_id]["users"][sid]

            leave_room(room_id)
            rs.users[sid]["room"] = None

            emit("system_message", {
                "message": f"{username} 离开了房间",
                "type": "leave",
                "username": "系统",
                "timestamp": datetime.now().strftime("%H:%M:%S")
            }, room=room_id)

            if not rs.rooms[room_id]["users"]:
                del rs.rooms[room_id]
                app.logger.info(f"房间 {room_id} 已删除 (空)")

            emit("left_room", {
                "room_id": room_id,
                "username": username,
                "message": f"已离开房间 {room_id}"
            })

        @socketio.on("send_message")
        def handle_send_message(data):
            """发送普通消息（明文，不加密）"""
            rs = RelayServer.get_instance()
            if rs is None:
                return

            sid = request.sid
            message = data.get("message", "").strip()
            timestamp = data.get("timestamp", datetime.now().strftime("%H:%M:%S"))

            if not message:
                emit("error", {"message": "消息不能为空"})
                return

            if sid not in rs.users:
                emit("error", {"message": "用户未连接"})
                return

            user_info = rs.users[sid]
            room_id = user_info.get("room")
            username = user_info.get("username", "匿名用户")

            if not room_id or room_id not in rs.rooms:
                emit("error", {"message": "请先加入房间"})
                return

            if sid not in rs.rooms[room_id]["users"]:
                emit("error", {"message": "您不在该房间中"})
                return

            msg_data = {
                "username": username,
                "message": message,
                "timestamp": timestamp,
                "sid": sid
            }

            rs.rooms[room_id]["messages"].append(msg_data)

            if len(rs.rooms[room_id]["messages"]) > 1000:
                rs.rooms[room_id]["messages"] = rs.rooms[room_id]["messages"][-500:]

            emit("new_message", msg_data, room=room_id)
            app.logger.debug(f"{username} 在 {room_id}: {message[:50]}")

        @socketio.on("encrypted_message")
        def handle_encrypted_message(data):
            """
            接收加密消息，直接转发（不解密）
            这是端到端加密的核心：中转服务器只转发密文
            """
            rs = RelayServer.get_instance()
            if rs is None:
                return

            room_id = data.get("room_id")
            from_user = data.get("from", "未知")

            if not room_id or room_id not in rs.rooms:
                emit("error", {"message": "房间不存在"})
                return

            app.logger.debug(f"转发加密消息 from {from_user} in {room_id}")

            # 直接转发密文，不解密
            emit("encrypted_message", {
                "from": from_user,
                "data": data.get("data"),
                "iv": data.get("iv"),
                "tag": data.get("tag"),
                "timestamp": data.get("timestamp", datetime.now().strftime("%H:%M:%S"))
            }, room=room_id)

        @socketio.on("get_rooms")
        def handle_get_rooms():
            """获取所有房间列表"""
            rs = RelayServer.get_instance()
            if rs is None:
                return

            room_list = []
            for room_id, room_data in rs.rooms.items():
                room_list.append({
                    "id": room_id,
                    "users_count": len(room_data["users"]),
                    "users": list(room_data["users"].values()),
                    "created_at": room_data.get("created_at", datetime.now()).strftime("%H:%M:%S"),
                    "creator": room_data.get("creator", "未知")
                })

            emit("rooms_list", {
                "rooms": room_list,
                "total": len(room_list),
                "active_users": rs.server_info["active_connections"]
            })

        @socketio.on("get_room_users")
        def handle_get_room_users(data):
            """获取房间内用户列表"""
            rs = RelayServer.get_instance()
            if rs is None:
                return

            room_id = data.get("room_id")

            if not room_id or room_id not in rs.rooms:
                emit("error", {"message": "房间不存在"})
                return

            emit("room_users", {
                "room_id": room_id,
                "users": list(rs.rooms[room_id]["users"].values()),
                "count": len(rs.rooms[room_id]["users"])
            })

        @socketio.on("get_server_info")
        def handle_get_server_info():
            """获取服务器信息"""
            rs = RelayServer.get_instance()
            if rs is None:
                return

            emit("server_info", {
                "start_time": rs.server_info["start_time"].strftime("%Y-%m-%d %H:%M:%S"),
                "total_connections": rs.server_info["total_connections"],
                "active_connections": rs.server_info["active_connections"],
                "total_rooms": len(rs.rooms),
                "total_users": len(rs.users)
            })

    def start(self):
        """循环接受客户端连接"""
        self.logger.info("中转服务器启动，等待客户端连接...")

        while self.running:
            try:
                # ===== 第一次连接：证书分发（普通 socket） =====
                conn1, addr1 = self.listen_sock.accept()
                self.logger.info(f"客户端 {addr1} 第一次连接 (证书分发)")

                def handle_first_connection(conn, addr):
                    try:
                        handler1 = self.create_new_instance()
                        handler1.conn = conn
                        handler1.addr = addr
                        handler1.sock = conn
                        handler1.seq = 1
                        handler1.handshake_done = False
                        handler1.aes_key = None

                        handler1._handshake()

                        from tools.CredentialProvisioner import Generator
                        g = Generator(self.ca_cert, self.ca_key)
                        client_key, path = g.generate_key()
                        client_cert = g.generate_cert(path)
                        handler1.send(client_key)
                        handler1.send(client_cert)
                        handler1.logger.info(f"证书已发送给 {addr}")

                        handler1.sock.close()
                        handler1.sock = None
                        handler1.conn = None
                        self.logger.info(f"证书分发完成 for {addr}")
                    except Exception as e:
                        self.logger.error(f"证书分发失败 {addr}: {e}")

                t1 = threading.Thread(target=handle_first_connection, args=(conn1, addr1), daemon=True)
                t1.start()

                # ===== 第二次连接：SSL 通信 =====
                conn2, addr2 = self.listen_sock.accept()
                self.logger.info(f"客户端 {addr2} 第二次连接 (SSL)")

                def handle_second_connection(conn, addr):
                    try:
                        handler2 = self.create_new_instance()
                        handler2.conn = conn
                        handler2.addr = addr
                        handler2.seq = 1
                        handler2.handshake_done = False
                        handler2.aes_key = None

                        handler2.ssl_sock = handler2.context.wrap_socket(conn, server_side=True)
                        handler2.logger.info("SSL/TLS 握手完成")

                        handler2._handshake_ssl()
                        self.logger.info(f"客户端 {addr} 加密通信已建立")

                        self._clients[addr] = handler2
                    except Exception as e:
                        self.logger.error(f"SSL 握手失败 {addr}: {e}")

                t2 = threading.Thread(target=handle_second_connection, args=(conn2, addr2), daemon=True)
                t2.start()

            except Exception as e:
                if self.running:
                    self.logger.error(f"连接处理错误: {e}")
                    import traceback
                    self.logger.error(traceback.format_exc())
                continue

    def stop(self):
        """停止服务器"""
        self.running = False
        for addr, handler in self._clients.items():
            try:
                handler.close()
            except:
                pass
        self._clients.clear()
        if self.listen_sock:
            try:
                self.listen_sock.close()
            except:
                pass

def environment_check():
    if not shutil.which("openssl"):
        raise EnvironmentError("尚未安装openssl，请先安装openssl")

if __name__ == "__main__":
    environment_check()
    try:
        host = config["RelayServer"]["Host"]
        port = int(config["RelayServer"]["Port"])
        listen = int(config["RelayServer"]["Listen"])
        server_cert = config["RelayServer"]["Certificates"]["ServerCert"]
        server_key = config["RelayServer"]["Certificates"]["ServerKey"]
        ca_cert = config["RelayServer"]["Certificates"]["CaCert"]
        ca_key = config["RelayServer"]["Certificates"]["CaKey"]
        padding = int(config["RelayServer"]["Padding"])
        encoding = config["RelayServer"]["Encoding"]
        if not os.path.exists(server_cert) \
            or not os.path.exists(server_key) \
            or not os.path.exists(ca_cert) \
            or not os.path.exists(ca_key):
            raise FileNotFoundError("文件缺失")
        print("=" * 60)
        print("中转服务器正在开启...")
        print(f"服务器开启于: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}")
        print(f"监听于: {host}:{port}")
        print(f"WebSocket: ws://{host}:{port}")
        print("=" * 60)

        rs = RelayServer(
            host=host,
            port=port,
            listen=10,
            server_cert=server_cert,
            server_key=server_key,
            ca_cert=ca_cert,
            ca_key=ca_key,
            padding=padding,
            encoding=encoding
        )

        t = threading.Thread(target=rs.start, daemon=True)
        t.start()
        socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
    except Exception as e:
        raise Exception(f"配置文件有误，请检查: {e}")