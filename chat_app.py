from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import sqlite3
import os
from datetime import datetime
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*", logger=False, engineio_logger=False)

# 存储在线用户和颜色
users = {}  # {sid: {'username': str, 'color': str}}


# 初始化或更新数据库
def init_db():
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    # 检查表是否存在，如果不存在则创建
    c.execute('''CREATE TABLE IF NOT EXISTS messages 
                (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                 username TEXT, 
                 message TEXT, 
                 timestamp TEXT)''')
    # 检查是否需要添加 color 列
    c.execute("PRAGMA table_info(messages)")
    columns = [col[1] for col in c.fetchall()]
    if 'color' not in columns:
        c.execute("ALTER TABLE messages ADD COLUMN color TEXT DEFAULT '#000000'")
    conn.commit()
    conn.close()


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


@app.route('/')
def index():
    check_and_clear_db()  # 检查并清空数据库
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute("SELECT username, message, timestamp, color FROM messages ORDER BY id ASC LIMIT 50")
    messages = c.fetchall()
    conn.close()
    return render_template('index.html', messages=messages)


@socketio.on('connect')
def handle_connect():
    print('New connection established')


@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in users:
        username = users[request.sid]['username']
        del users[request.sid]
        emit('user_left', {'username': username}, broadcast=True)


@socketio.on('join')
def handle_join(data):
    username = data['username']
    color = "#{:06x}".format(random.randint(0, 0xFFFFFF))  # 随机颜色
    users[request.sid] = {'username': username, 'color': color}
    emit('user_joined', {'username': username, 'color': color}, broadcast=True)


@socketio.on('message')
def handle_message(data):
    user = users.get(request.sid, {'username': 'Anonymous', 'color': '#000000'})
    username = user['username']
    color = user['color']
    timestamp = datetime.now().strftime('%H:%M:%S')  # 只显示时间

    # 存储到数据库
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute("INSERT INTO messages (username, message, timestamp, color) VALUES (?, ?, ?, ?)",
              (username, data['message'], timestamp, color))
    conn.commit()
    conn.close()

    check_and_clear_db()  # 发送消息后检查大小

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