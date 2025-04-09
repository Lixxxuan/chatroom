from flask import Flask, render_template, request  # 从 flask 导入 request
from flask_socketio import SocketIO, emit
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

# 存储在线用户
users = {}


# 初始化数据库
def init_db():
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS messages 
                (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                 username TEXT, 
                 message TEXT, 
                 timestamp TEXT)''')
    conn.commit()
    conn.close()


@app.route('/')
def index():
    # 获取历史消息
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute("SELECT username, message, timestamp FROM messages ORDER BY timestamp DESC LIMIT 50")
    messages = c.fetchall()
    conn.close()
    return render_template('index.html', messages=messages[::-1])  # 倒序显示，最新消息在底部


@socketio.on('connect')
def handle_connect():
    print('New connection established')


@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in users:
        username = users[request.sid]
        del users[request.sid]
        emit('user_left', {'username': username}, broadcast=True)


@socketio.on('join')
def handle_join(data):
    username = data['username']
    users[request.sid] = username
    emit('user_joined', {'username': username}, broadcast=True)


@socketio.on('message')
def handle_message(data):
    username = users.get(request.sid, 'Anonymous')
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 存储到数据库
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute("INSERT INTO messages (username, message, timestamp) VALUES (?, ?, ?)",
              (username, data['message'], timestamp))
    conn.commit()
    conn.close()

    emit('new_message', {
        'username': username,
        'message': data['message'],
        'timestamp': timestamp
    }, broadcast=True)


if __name__ == '__main__':
    if not os.path.exists('chat.db'):
        init_db()
    socketio.run(app, host='0.0.0.0', port=5000, debug=False,
                 use_reloader=False, log_output=False)