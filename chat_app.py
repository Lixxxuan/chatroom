from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit
import sqlite3
import os
from datetime import datetime
import random
import hashlib
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*", logger=False, engineio_logger=False)

# 预定义的邀请码 (实际应用中应该存储在数据库或配置中)
INVITATION_CODES = ["CHAT2023", "WELCOME123"]

# 存储在线用户和颜色
users = {}  # {sid: {'username': str, 'color': str}}


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
                 color TEXT)''')

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
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
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

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    c.execute("SELECT username FROM users WHERE username = ? AND password = ?",
              (username, hashed_password))
    user = c.fetchone()
    conn.close()

    return user is not None


# 检查数据库大小并清空
def check_and_clear_db():
    db_size = os.path.getsize('chat.db') if os.path.exists('chat.db') else 0
    if db_size > 2 * 1024 * 1024 * 1024:  # 2GB in bytes
        conn = sqlite3.connect('chat.db')
        c = conn.cursor()
        c.execute("DELETE FROM messages")
        conn.commit()
        conn.close()
        print("Chat history cleared due to size exceeding 2GB")
        return True
    return False


# 登录和注册路由
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
    c.execute("SELECT username, message, timestamp, color FROM messages ORDER BY id ASC LIMIT 50")
    messages = c.fetchall()
    conn.close()
    return render_template('index.html', messages=messages, username=session['username'])


# WebSocket 事件处理
@socketio.on('connect')
def handle_connect():
    if 'username' not in session:
        return False
    print('New connection established')


@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in users:
        username = users[request.sid]['username']
        del users[request.sid]
        emit('user_left', {'username': username}, broadcast=True)


@socketio.on('join')
def handle_join():
    if 'username' not in session:
        return False

    username = session['username']
    color = generate_dark_color()  # 使用深色
    users[request.sid] = {'username': username, 'color': color}
    emit('user_joined', {'username': username, 'color': color}, broadcast=True)


@socketio.on('message')
def handle_message(data):
    if 'username' not in session or request.sid not in users:
        return False

    user = users[request.sid]
    username = user['username']
    color = user['color']
    timestamp = datetime.now().strftime('%H:%M:%S')

    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute("INSERT INTO messages (username, message, timestamp, color) VALUES (?, ?, ?, ?)",
              (username, data['message'], timestamp, color))
    conn.commit()
    conn.close()

    check_and_clear_db()

    emit('new_message', {
        'username': username,
        'message': data['message'],
        'timestamp': timestamp,
        'color': color
    }, broadcast=True)


if __name__ == '__main__':
    if not os.path.exists('chat.db'):
        init_db()
    else:
        init_db()  # 确保现有数据库更新结构
    socketio.run(app, host='0.0.0.0', port=5000, debug=False,
                 use_reloader=False, log_output=False)
