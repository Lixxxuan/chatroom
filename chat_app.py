from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

# 存储在线用户
users = {}

@app.route('/')
def index():
    return render_template('index.html')

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
    emit('new_message', {
        'username': username,
        'message': data['message']
    }, broadcast=True)

if __name__ == '__main__':
    # 在Linux环境下运行，优化内存使用
    socketio.run(app, host='0.0.0.0', port=6000, debug=False,
                use_reloader=False, log_output=False)