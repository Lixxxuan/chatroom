from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit
import sqlite3
import os
from datetime import datetime
import random
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # 生产环境中应该使用更安全的密钥
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*", logger=True, engineio_logger=True)

# 预定义的邀请码 (实际应用中应该存储在数据库或配置中)
INVITATION_CODES = ["CHAT2023", "WELCOME123"]

# 存储在线用户信息
users = {}  # {sid: {'username': str, 'color': str}}
online_users = {}  # {username: {'sid': str, 'color': str}}


# 初始化数据库
def init_db():
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()

    # 创建用户表
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE,
                 password TEXT)''')

    # 创建消息表
    c.execute('''CREATE TABLE IF NOT EXISTS messages 
                (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                 username TEXT, 
                 message TEXT, 
                 timestamp TEXT,
                 color TEXT,
                 is_private INTEGER DEFAULT 0,
                 target_user TEXT DEFAULT NULL)''')

    conn.commit()
    conn.close()


# 生成深色随机颜色
def generate_dark_color():
    # 限制RGB分量在0-180之间以确保颜色较深
    r = random.randint(0, 180)
    g = random.randint(0, 180)
    b = random.randint(0, 180)
    return f"#{r:02x}{g:02x}{b:02x}"


# 用户认证相关函数
def register_user(username, password, invitation_code):
    if invitation_code not in INVITATION_CODES:
        return False, "邀请码无效"

    conn = sqlite3.connect('chat.db')
    c = conn.cursor()

    try:
        hashed_password = generate_password_hash(password)
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                  (username, hashed_password))
        conn.commit()
        return True, "注册成功"
    except sqlite3.IntegrityError:
        return False, "用户名已存在"
    finally:
        conn.close()


def authenticate_user(username, password):
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()

    c.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()

    if result and check_password_hash(result[0], password):
        return True
    return False


# 检查数据库大小并清空
def check_and_clear_db():
    db_size = os.path.getsize('chat.db') if os.path.exists('chat.db') else 0
    if db_size > 2 * 1024 * 1024 * 1024:  # 2GB in bytes
        conn = sqlite3.connect('chat.db')
        c = conn.cursor()
        c.execute("DELETE FROM messages WHERE timestamp < datetime('now', '-30 days')")
        conn.commit()
        conn.close()
        print("清理了30天前的聊天记录")
        return True
    return False


# 路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if authenticate_user(username, password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash('用户名或密码错误')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        invitation_code = request.form['invitation_code']

        success, message = register_user(username, password, invitation_code)
        if success:
            flash(message)
            return redirect(url_for('login'))
        else:
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
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute("""
        SELECT username, message, timestamp, color 
        FROM messages 
        WHERE is_private = 0 OR (is_private = 1 AND target_user = ?)
        ORDER BY id DESC LIMIT 50
    """, (session['username'],))
    messages = c.fetchall()
    conn.close()

    # 反转消息顺序以便最新消息在底部
    messages = messages[::-1]
    return render_template('index.html', messages=messages, username=session['username'])


# Socket.IO 事件处理
@socketio.on('connect')
def handle_connect():
    if 'username' not in session:
        return False
    print(f"新连接建立: {session['username']}")


@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in users:
        username = users[request.sid]['username']
        del users[request.sid]
        if username in online_users:
            del online_users[username]
        emit('user_left', {'username': username}, broadcast=True)
        emit('update_users', {'users': list(online_users.keys())}, broadcast=True)
        print(f"用户断开连接: {username}")


@socketio.on('join')
def handle_join(data, callback):
    if 'username' not in session:
        callback({'error': '未登录'})
        return False

    username = session['username']
    if username != data.get('username'):
        callback({'error': '用户名不匹配'})
        return False

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
    callback({'success': True})
    print(f"用户加入聊天室: {username}")


@socketio.on('message')
def handle_message(data, callback):
    if 'username' not in session or request.sid not in users:
        callback({'error': '未登录或未加入聊天室'})
        return False

    user = users[request.sid]
    username = user['username']
    color = user['color']
    timestamp = datetime.now().strftime('%H:%M:%S')
    message = data.get('message', '').strip()

    if not message:
        callback({'error': '消息不能为空'})
        return False

    # 存储到数据库
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute("""
        INSERT INTO messages (username, message, timestamp, color, is_private) 
        VALUES (?, ?, ?, ?, 0)
    """, (username, message, timestamp, color))
    conn.commit()
    conn.close()

    check_and_clear_db()

    emit('new_message', {
        'username': username,
        'message': message,
        'timestamp': timestamp,
        'color': color
    }, broadcast=True)

    callback({'success': True})
    print(f"新公共消息: {username}: {message}")


@socketio.on('private_message')
def handle_private_message(data, callback):
    if 'username' not in session or request.sid not in users:
        callback({'error': '未登录或未加入聊天室'})
        return False

    sender = session['username']
    receiver = data.get('to')
    message = data.get('message', '').strip()
    timestamp = datetime.now().strftime('%H:%M:%S')

    if not message:
        callback({'error': '消息不能为空'})
        return False

    if not receiver or receiver not in online_users:
        callback({'error': '用户不存在或不在线'})
        return False

    if receiver == sender:
        callback({'error': '不能给自己发送私聊消息'})
        return False

    # 获取发送者和接收者的颜色
    sender_color = users[request.sid]['color']
    receiver_info = online_users[receiver]

    # 存储到数据库
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute("""
        INSERT INTO messages (username, message, timestamp, color, is_private, target_user) 
        VALUES (?, ?, ?, ?, 1, ?)
    """, (sender, message, timestamp, sender_color, receiver))
    conn.commit()
    conn.close()

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

    callback({'success': True})
    print(f"新私聊消息: {sender} -> {receiver}: {message}")


if __name__ == '__main__':
    if not os.path.exists('chat.db'):
        init_db()
    else:
        init_db()  # 确保现有数据库更新结构

    # 清理旧消息
    check_and_clear_db()

    socketio.run(app, host='0.0.0.0', port=5000, debug=True,
                 use_reloader=False, log_output=True)
