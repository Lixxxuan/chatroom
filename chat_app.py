from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit
import sqlite3
import os
from datetime import datetime
import random
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # 生产环境中应使用更安全的密钥
socketio = SocketIO(app,
                    async_mode='eventlet',
                    cors_allowed_origins="*",
                    logger=True,
                    engineio_logger=True)

# 配置信息
INVITATION_CODES = ["CHAT2023", "WELCOME123"]
MAX_MESSAGE_LENGTH = 500
MAX_USERNAME_LENGTH = 20

# 存储在线用户信息
users = {}  # {sid: {'username': str, 'color': str}}
online_users = {}  # {username: {'sid': str, 'color': str}}


# 数据库初始化
def init_db():
    with sqlite3.connect('chat.db') as conn:
        c = conn.cursor()

        # 用户表
        c.execute('''CREATE TABLE IF NOT EXISTS users 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     username TEXT UNIQUE,
                     password TEXT,
                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

        # 消息表 - 先创建基本表结构
        c.execute('''CREATE TABLE IF NOT EXISTS messages 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                     username TEXT, 
                     message TEXT, 
                     timestamp TEXT,
                     color TEXT)''')

        # 检查并添加 is_private 列
        c.execute("PRAGMA table_info(messages)")
        columns = [col[1] for col in c.fetchall()]
        if 'is_private' not in columns:
            c.execute("ALTER TABLE messages ADD COLUMN is_private INTEGER DEFAULT 0")
        if 'target_user' not in columns:
            c.execute("ALTER TABLE messages ADD COLUMN target_user TEXT DEFAULT NULL")

        # 现在可以安全地创建索引
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_private ON messages(is_private, target_user)")

        # 创建其他必要的索引
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_username ON messages(username)")


# 生成深色随机颜色
def generate_dark_color():
    r = random.randint(0, 180)
    g = random.randint(0, 180)
    b = random.randint(0, 180)
    return f"#{r:02x}{g:02x}{b:02x}"


# 用户认证
def register_user(username, password, invitation_code):
    if invitation_code not in INVITATION_CODES:
        return False, "邀请码无效"

    if len(username) > MAX_USERNAME_LENGTH:
        return False, f"用户名不能超过{MAX_USERNAME_LENGTH}个字符"

    if len(password) < 6:
        return False, "密码至少需要6个字符"

    try:
        with sqlite3.connect('chat.db') as conn:
            c = conn.cursor()
            hashed_password = generate_password_hash(password)
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                      (username, hashed_password))
            return True, "注册成功"
    except sqlite3.IntegrityError:
        return False, "用户名已存在"


def authenticate_user(username, password):
    with sqlite3.connect('chat.db') as conn:
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = c.fetchone()

    if result and check_password_hash(result[0], password):
        return True
    return False


# 数据库维护
def check_and_clear_db():
    db_size = os.path.getsize('chat.db') if os.path.exists('chat.db') else 0
    if db_size > 2 * 1024 * 1024 * 1024:  # 2GB
        with sqlite3.connect('chat.db') as conn:
            c = conn.cursor()
            # 保留最近30天的消息
            c.execute("DELETE FROM messages WHERE timestamp < datetime('now', '-30 days')")
            # 清理不活跃用户
            c.execute("""
                DELETE FROM users 
                WHERE id NOT IN (
                    SELECT DISTINCT user_id FROM messages
                ) AND created_at < datetime('now', '-90 days')
            """)
        print("执行了数据库维护操作")


# 路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if authenticate_user(username, password):
            session['username'] = username
            return redirect(url_for('index'))
        flash('用户名或密码错误')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        invitation_code = request.form.get('invitation_code', '')

        success, message = register_user(username, password, invitation_code)
        if success:
            flash(message)
            return redirect(url_for('login'))
        flash(message)
    return render_template('register.html', invitation_codes=INVITATION_CODES)


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))

    check_and_clear_db()
    with sqlite3.connect('chat.db') as conn:
        c = conn.cursor()
        c.execute("""
            SELECT username, message, timestamp, color 
            FROM messages 
            WHERE is_private = 0 OR (is_private = 1 AND target_user = ?)
            ORDER BY id DESC LIMIT 50
        """, (session['username'],))
        messages = c.fetchall()[::-1]  # 反转顺序使最新消息在底部

    return render_template('index.html',
                           messages=messages,
                           username=session['username'],
                           max_message_length=MAX_MESSAGE_LENGTH)


# Socket.IO 事件处理
@socketio.on('connect')
def handle_connect():
    if 'username' not in session:
        print("未认证的连接尝试")
        return False
    print(f"新连接: {session['username']}")


@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in users:
        username = users[request.sid]['username']
        del users[request.sid]
        if username in online_users:
            del online_users[username]
        emit('user_left', {'username': username}, broadcast=True)
        emit('update_users', {'users': list(online_users.keys())}, broadcast=True)
        print(f"用户断开: {username}")


@socketio.on('join')
def handle_join(data):
    if 'username' not in session:
        emit('join_error', {'error': '未登录'})
        return

    username = session['username']
    if username != data.get('username'):
        emit('join_error', {'error': '用户名不匹配'})
        return

    color = generate_dark_color()
    users[request.sid] = {'username': username, 'color': color}
    online_users[username] = {'sid': request.sid, 'color': color}

    timestamp = datetime.now().strftime('%H:%M:%S')
    emit('user_joined', {
        'username': username,
        'color': color,
        'timestamp': timestamp
    }, broadcast=True)

    emit('update_users', {'users': list(online_users.keys())}, broadcast=True)
    print(f"用户加入: {username}")


@socketio.on('message')
def handle_message(data):
    if 'username' not in session or request.sid not in users:
        emit('message_error', {'error': '未登录或未加入聊天室'})
        return

    message = data.get('message', '').strip()
    if not message:
        emit('message_error', {'error': '消息不能为空'})
        return

    if len(message) > MAX_MESSAGE_LENGTH:
        emit('message_error', {'error': f'消息长度不能超过{MAX_MESSAGE_LENGTH}个字符'})
        return

    user = users[request.sid]
    timestamp = datetime.now().strftime('%H:%M:%S')

    with sqlite3.connect('chat.db') as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO messages (username, message, timestamp, color, is_private) 
            VALUES (?, ?, ?, ?, 0)
        """, (user['username'], message, timestamp, user['color']))

    emit('new_message', {
        'username': user['username'],
        'message': message,
        'timestamp': timestamp,
        'color': user['color']
    }, broadcast=True)


@socketio.on('private_message')
def handle_private_message(data):
    if 'username' not in session or request.sid not in users:
        emit('private_message_error', {'error': '未登录或未加入聊天室'})
        return

    sender = session['username']
    receiver = data.get('to')
    message = data.get('message', '').strip()

    if not message:
        emit('private_message_error', {'error': '消息不能为空'})
        return

    if len(message) > MAX_MESSAGE_LENGTH:
        emit('private_message_error', {'error': f'消息长度不能超过{MAX_MESSAGE_LENGTH}个字符'})
        return

    if not receiver or receiver not in online_users:
        emit('private_message_error', {'error': '用户不存在或不在线'})
        return

    if receiver == sender:
        emit('private_message_error', {'error': '不能给自己发送私聊消息'})
        return

    timestamp = datetime.now().strftime('%H:%M:%S')
    sender_color = users[request.sid]['color']
    receiver_info = online_users[receiver]

    with sqlite3.connect('chat.db') as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO messages (username, message, timestamp, color, is_private, target_user) 
            VALUES (?, ?, ?, ?, 1, ?)
        """, (sender, message, timestamp, sender_color, receiver))

    # 给接收者发送消息
    emit('private_message_received', {
        'from': sender,
        'message': message,
        'timestamp': timestamp,
        'color': sender_color
    }, room=receiver_info['sid'])

    # 给发送者发送回执
    emit('private_message_sent', {
        'to': receiver,
        'message': message,
        'timestamp': timestamp,
        'color': receiver_info['color']
    }, room=request.sid)


if __name__ == '__main__':
    if not os.path.exists('chat.db'):
        init_db()
    else:
        init_db()  # 确保数据库结构最新

    # 启动前执行数据库维护
    check_and_clear_db()

    socketio.run(app,
                 host='0.0.0.0',
                 port=5000,
                 debug=True,
                 use_reloader=False,
                 allow_unsafe_werkzeug=True)
