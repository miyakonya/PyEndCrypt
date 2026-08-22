// 聊天室JavaScript逻辑
class ChatRoom {
    constructor(serverUrl) {
        this.serverUrl = serverUrl || 'http://localhost:5000';
        this.socket = null;
        this.currentRoom = null;
        this.username = '';
        this.isConnected = false;

        // DOM元素引用
        this.elements = {
            messages: document.getElementById('messages'),
            messageInput: document.getElementById('messageInput'),
            sendBtn: document.getElementById('sendBtn'),
            usernameInput: document.getElementById('usernameInput'),
            roomInput: document.getElementById('roomInput'),
            roomDisplay: document.getElementById('roomDisplay'),
            userDisplay: document.getElementById('userDisplay'),
            errorMessage: document.getElementById('errorMessage'),
            statusIndicator: document.getElementById('statusIndicator')
        };

        this.init();
    }

    init() {
        // 生成默认用户名
        const defaultUser = '用户_' + Math.random().toString(36).substring(2, 8);
        this.elements.usernameInput.value = defaultUser;

        // 绑定事件
        this.bindEvents();

        // 初始化连接
        this.connect();
    }

    bindEvents() {
        // 发送消息（回车键）
        this.elements.messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.sendMessage();
            }
        });

        // 加入房间（回车键）
        this.elements.roomInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.joinRoom();
            }
        });

        // 创建房间（回车键）
        this.elements.usernameInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.createRoom();
            }
        });

        // 窗口关闭前断开连接
        window.addEventListener('beforeunload', () => {
            if (this.socket) {
                this.socket.disconnect();
            }
        });
    }

    connect() {
        if (this.socket && this.socket.connected) {
            return;
        }

        // 连接到中转服务器
        this.socket = io(this.serverUrl, {
            transports: ['websocket', 'polling'],
            reconnection: true,
            reconnectionAttempts: 10,
            reconnectionDelay: 1000
        });

        this.socket.on('connect', () => {
            console.log('Connected to chat server');
            this.isConnected = true;
            this.updateStatus('已连接', 'online');
            this.showSystemMessage('✅ 已连接到聊天服务器');
        });

        this.socket.on('connected', (data) => {
            console.log('Server confirmation:', data);
            this.showSystemMessage(`服务器连接成功 (SID: ${data.sid})`);
        });

        this.socket.on('disconnect', () => {
            console.log('Disconnected from server');
            this.isConnected = false;
            this.updateStatus('已断开', 'offline');
            this.showSystemMessage('❌ 与服务器断开连接');
            this.enableChat(false);
        });

        this.socket.on('connect_error', (error) => {
            console.error('Connection error:', error);
            this.updateStatus('连接失败', 'error');
            this.showError('无法连接到聊天服务器，请确保服务器正在运行');
        });

        this.socket.on('room_created', (data) => {
            this.currentRoom = data.room_id;
            this.username = data.username;
            this.updateUI();
            this.showSystemMessage(`✅ ${data.message}`);
            this.elements.roomInput.value = data.room_id;
            this.enableChat(true);
        });

        this.socket.on('room_joined', (data) => {
            this.currentRoom = data.room_id;
            this.username = data.username;
            this.updateUI();
            this.showSystemMessage(`✅ 成功加入房间 ${data.room_id}`);
            this.enableChat(true);

            // 清空消息区域
            this.clearMessages();

            // 显示历史消息
            if (data.history && data.history.length > 0) {
                data.history.forEach((msg) => {
                    this.addMessage(msg.username, msg.message, msg.timestamp);
                });
            }
        });

        this.socket.on('left_room', (data) => {
            this.showSystemMessage(`ℹ️ ${data.message}`);
            this.currentRoom = null;
            this.updateUI();
            this.enableChat(false);
            this.clearMessages();
            this.showWelcomeMessage();
        });

        this.socket.on('new_message', (data) => {
            this.addMessage(data.username, data.message, data.timestamp);
        });

        this.socket.on('system_message', (data) => {
            this.showSystemMessage(data.message);
        });

        this.socket.on('error', (data) => {
            this.showError(data.message);
        });

        // 接收房间用户列表
        this.socket.on('room_users', (data) => {
            this.showUserModal(data.users, data.count, data.room_id);
        });
    }

    // 更新连接状态
    updateStatus(text, status) {
        const indicator = this.elements.statusIndicator;
        if (indicator) {
            indicator.textContent = text;
            indicator.className = 'status-' + status;
        }
    }

    // 创建房间
    createRoom() {
        const username = this.elements.usernameInput.value.trim();
        if (!username) {
            this.showError('请输入用户名');
            return;
        }

        if (!this.isConnected) {
            this.showError('未连接到服务器，请检查网络');
            return;
        }

        this.socket.emit('create_room', { username });
    }

    // 加入房间
    joinRoom() {
        const roomId = this.elements.roomInput.value.trim();
        const username = this.elements.usernameInput.value.trim();

        if (!roomId) {
            this.showError('请输入房间号');
            return;
        }

        if (!username) {
            this.showError('请输入用户名');
            return;
        }

        if (!this.isConnected) {
            this.showError('未连接到服务器');
            return;
        }

        this.socket.emit('join_room', { room_id: roomId, username });
    }

    // 退出房间
    leaveRoom() {
        if (this.currentRoom) {
            if (this.isConnected) {
                this.socket.emit('leave_room', {});
            } else {
                this.currentRoom = null;
                this.updateUI();
                this.enableChat(false);
                this.clearMessages();
                this.showWelcomeMessage();
                this.showSystemMessage('已离开房间');
            }
        }
    }

    // 发送消息
    sendMessage() {
        const message = this.elements.messageInput.value.trim();

        if (!message || !this.currentRoom) return;
        if (!this.isConnected) {
            this.showError('未连接到服务器');
            return;
        }

        this.socket.emit('send_message', {
            message: message,
            timestamp: new Date().toLocaleTimeString()
        });

        this.elements.messageInput.value = '';
        this.elements.messageInput.focus();
    }

    // 获取房间用户列表（弹出窗口）
    getRoomUsers() {
        if (!this.currentRoom) {
            this.showError('请先加入房间');
            return;
        }
        if (!this.isConnected) {
            this.showError('未连接到服务器');
            return;
        }
        this.socket.emit('get_room_users', { room_id: this.currentRoom });
    }

    // 显示用户列表弹出窗口
    showUserModal(users, count, roomId) {
        const modal = document.getElementById('userModal');
        const userList = document.getElementById('userList');

        if (!modal || !userList) return;

        // 构建用户列表HTML
        if (!users || users.length === 0) {
            userList.innerHTML = '<div class="empty-users">暂无用户在线</div>';
        } else {
            let html = `<div style="margin-bottom: 10px; color: #999; font-size: 13px;">房间 ${roomId} - 共 ${count} 人在线</div>`;
            users.forEach((username, index) => {
                const avatar = username.charAt(0).toUpperCase();
                html += `
                    <div class="user-item">
                        <div class="avatar">${avatar}</div>
                        <span class="user-name">${this.escapeHtml(username)}</span>
                        <span class="user-status">● 在线</span>
                    </div>
                `;
            });
            userList.innerHTML = html;
        }

        // 显示弹窗
        modal.style.display = 'flex';
    }

    // 关闭用户列表弹出窗口
    closeUserModal() {
        const modal = document.getElementById('userModal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    // 添加消息到界面
    addMessage(username, message, timestamp) {
        const msgDiv = document.createElement('div');
        msgDiv.className = 'message';

        const currentUsername = this.elements.usernameInput.value.trim();
        if (username === currentUsername) {
            msgDiv.classList.add('self');
        } else {
            msgDiv.classList.add('other');
        }

        const timeStr = timestamp || new Date().toLocaleTimeString();

        msgDiv.innerHTML = `
            <div class="msg-header">
                <span class="time">${this.escapeHtml(timeStr)}</span>
                <span class="username">${this.escapeHtml(username)}</span>
            </div>
            <div class="content">${this.escapeHtml(message)}</div>
        `;

        this.elements.messages.appendChild(msgDiv);
        this.scrollToBottom();
    }

    // 显示系统消息
    showSystemMessage(message) {
        const msgDiv = document.createElement('div');
        msgDiv.className = 'message system';
        msgDiv.innerHTML = `<div class="content">${this.escapeHtml(message.replace(/\n/g, '<br>'))}</div>`;
        this.elements.messages.appendChild(msgDiv);
        this.scrollToBottom();
    }

    // 显示欢迎消息
    showWelcomeMessage() {
        const msgDiv = document.createElement('div');
        msgDiv.className = 'message system';
        msgDiv.innerHTML = '<div class="content">欢迎来到聊天室！创建或加入房间开始聊天吧</div>';
        this.elements.messages.appendChild(msgDiv);
    }

    // 显示错误消息
    showError(message) {
        const errorDiv = this.elements.errorMessage;
        errorDiv.textContent = '❌ ' + message;
        errorDiv.style.display = 'block';
        setTimeout(() => {
            errorDiv.style.display = 'none';
        }, 5000);
    }

    // 清空消息
    clearMessages() {
        this.elements.messages.innerHTML = '';
    }

    // 滚动到底部
    scrollToBottom() {
        this.elements.messages.scrollTop = this.elements.messages.scrollHeight;
    }

    // 更新UI状态
    updateUI() {
        this.elements.roomDisplay.textContent = this.currentRoom ? `房间: ${this.currentRoom}` : '未加入房间';
        this.elements.userDisplay.textContent = this.username || '未登录';
    }

    // 启用/禁用聊天功能
    enableChat(enabled) {
        this.elements.messageInput.disabled = !enabled;
        this.elements.sendBtn.disabled = !enabled;
        this.elements.messageInput.placeholder = enabled ? '输入消息...' : '请先加入房间';
    }

    // HTML转义
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// 初始化聊天室
document.addEventListener('DOMContentLoaded', () => {
    const serverUrl = document.getElementById('serverConfig')?.value || 'http://localhost:5000';
    window.chat = new ChatRoom(serverUrl);
});

// 全局函数
function createRoom() {
    if (window.chat) window.chat.createRoom();
}

function joinRoom() {
    if (window.chat) window.chat.joinRoom();
}

function leaveRoom() {
    if (window.chat) window.chat.leaveRoom();
}

function sendMessage() {
    if (window.chat) window.chat.sendMessage();
}

function getRoomUsers() {
    if (window.chat) window.chat.getRoomUsers();
}

function closeUserModal() {
    if (window.chat) window.chat.closeUserModal();
}

// 点击弹窗外部关闭
document.addEventListener('DOMContentLoaded', () => {
    const modal = document.getElementById('userModal');
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                closeUserModal();
            }
        });
    }
});