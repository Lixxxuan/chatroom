import os
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, session, redirect, url_for, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import eventlet
eventlet.monkey_patch()

# 应用配置
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'dev-secret-key-123'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['DATABASE'] = 'chat.db'
app.config['PREFERRED_URL_SCHEME'] = 'https'  # 确保生成HTTPS链接

# 配置服务器名称以确保url_for生成正确的URL
app.config['SERVER_NAME'] = 'chat.lxlxlx.xin'

# Socket.IO 配置
socketio = SocketIO(app, 
                   cors_allowed_origins="*",
                   async_mode='eventlet',
                   engineio_logger=True,
                   logger=True)

# 用户和房间管理
users = {}          # {sid: {'username': str, 'color': str}}
online_users = {}   # {username: {'sid': str, 'color': str}}
user_colors = {}    # 用户颜色缓存

# 数据库初始化
def init_db():
    with sqlite3.connect(app.config['DATABASE']) as conn:
        c = conn.cursor()
        
        # 用户表
        c.execute('''CREATE TABLE IF NOT EXISTS users 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     username TEXT UNIQUE,
                     password TEXT,
                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        # 消息表
        c.execute('''CREATE TABLE IF NOT EXISTS messages 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                     username TEXT, 
                     message TEXT, 
                     timestamp TEXT,
                     color TEXT,
                     is_private INTEGER DEFAULT 0,
                     target_user TEXT DEFAULT NULL,
                     message_type TEXT DEFAULT 'text')''')
        
        # 创建索引
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_private ON messages(is_private, target_user)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_type ON messages(message_type)")
        
        conn.commit()

# 文件扩展名检查
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# 生成随机颜色
def get_user_color(username):
    if username not in user_colors:
        colors = ['#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6']
        user_colors[username] = colors[len(user_colors) % len(colors)]
    return user_colors[username]

# 健康检查端点
@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy', 
        'websocket': True,
        'timestamp': datetime.now().isoformat(),
        'online_users': len(online_users)
    })

# 路由部分
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect(app.config['DATABASE']) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # 获取最近的50条公共消息或发给当前用户的私信
        c.execute('''SELECT username, message, timestamp, color, message_type 
                     FROM messages 
                     WHERE is_private = 0 OR (is_private = 1 AND target_user = ?)
                     ORDER BY id DESC LIMIT 50''', (session['username'],))
        messages = c.fetchall()[::-1]  # 反转列表使最新消息在底部
    
    return render_template('index.html', 
                         username=session['username'],
                         messages=messages)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with sqlite3.connect(app.config['DATABASE']) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = c.fetchone()
            
            if user and check_password_hash(user[2], password):
                session['username'] = username
                return redirect(url_for('index'))
            else:
                return render_template('login.html', error='用户名或密码错误')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        
        try:
            with sqlite3.connect(app.config['DATABASE']) as conn:
                c = conn.cursor()
                c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                         (username, password))
                conn.commit()
            
            session['username'] = username
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error='用户名已存在')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # 添加随机前缀防止文件名冲突
        unique_filename = f"{uuid.uuid4().hex[:8]}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        # 确保上传目录存在
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(filepath)
        
        # 返回HTTPS URL
        return jsonify({
            'url': f"https://chat.lxlxlx.xin/static/uploads/{unique_filename}"
        })
    
    return jsonify({'error': 'File type not allowed'}), 400

@app.route('/static/uploads/<filename>')
def uploaded_file(filename):
    # 设置安全头
    response = send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Socket.IO 事件处理
@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        sid = request.sid
        username = session['username']
        color = get_user_color(username)
        
        users[sid] = {
            'username': username,
            'color': color
        }
        online_users[username] = {
            'sid': sid,
            'color': color
        }
        
        # 通知所有用户更新在线列表
        emit('update_users', {
            'users': list(online_users.keys())
        }, broadcast=True)
        
        # 广播用户加入通知
        emit('new_message', {
            'username': '系统',
            'content': f"{username} 加入了聊天室",
            'timestamp': datetime.now().strftime("%H:%M:%S"),
            'color': '#6b7280',
            'message_type': 'system'
        }, broadcast=True)
        
        # 保存到数据库
        with sqlite3.connect(app.config['DATABASE']) as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO messages 
                        (username, message, timestamp, color, is_private, message_type)
                        VALUES (?, ?, ?, ?, ?, ?)''',
                     ('系统', f"{username} 加入了聊天室", 
                      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                      '#6b7280', 0, 'system'))
            conn.commit()

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    if sid in users:
        username = users[sid]['username']
        color = users[sid]['color']
        
        del users[sid]
        if username in online_users:
            del online_users[username]
        
        # 更新在线列表
        emit('update_users', {
            'users': list(online_users.keys())
        }, broadcast=True)
        
        # 广播用户离开通知
        emit('new_message', {
            'username': '系统',
            'content': f"{username} 离开了聊天室",
            'timestamp': datetime.now().strftime("%H:%M:%S"),
            'color': '#6b7280',
            'message_type': 'system'
        }, broadcast=True)
        
        # 保存到数据库
        with sqlite3.connect(app.config['DATABASE']) as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO messages 
                        (username, message, timestamp, color, is_private, message_type)
                        VALUES (?, ?, ?, ?, ?, ?)''',
                     ('系统', f"{username} 离开了聊天室", 
                      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                      '#6b7280', 0, 'system'))
            conn.commit()

@socketio.on('message')
def handle_message(data):
    if 'username' not in session:
        emit('error', {'message': '未登录'})
        return
    
    username = session['username']
    color = get_user_color(username)
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    # 处理普通文本消息
    if 'text' in data:
        message_content = data['text']
        message_type = 'text'
        
        # 广播消息
        emit('new_message', {
            'username': username,
            'content': message_content,
            'timestamp': timestamp,
            'color': color,
            'message_type': message_type
        }, broadcast=True)
        
        # 保存到数据库
        with sqlite3.connect(app.config['DATABASE']) as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO messages 
                        (username, message, timestamp, color, is_private, message_type)
                        VALUES (?, ?, ?, ?, ?, ?)''',
                     (username, message_content, 
                      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                      color, 0, message_type))
            conn.commit()
    
    # 处理图片消息
    elif 'image_url' in data:
        message_content = data['image_url']
        message_type = 'image'
        
        emit('new_message', {
            'username': username,
            'content': message_content,
            'timestamp': timestamp,
            'color': color,
            'message_type': message_type
        }, broadcast=True)
        
        with sqlite3.connect(app.config['DATABASE']) as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO messages 
                        (username, message, timestamp, color, is_private, message_type)
                        VALUES (?, ?, ?, ?, ?, ?)''',
                     (username, message_content, 
                      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                      color, 0, message_type))
            conn.commit()

@socketio.on('private_message')
def handle_private_message(data):
    if 'username' not in session:
        emit('error', {'message': '未登录'})
        return
    
    sender = session['username']
    receiver = data.get('to')
    message = data.get('message')
    
    if not receiver or not message:
        emit('error', {'message': '缺少接收者或消息内容'})
        return
    
    if receiver not in online_users:
        emit('error', {'message': '用户不在线'})
        return
    
    color = get_user_color(sender)
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    # 发送给接收者
    emit('private_message_received', {
        'from': sender,
        'message': message,
        'timestamp': timestamp,
        'color': color
    }, room=online_users[receiver]['sid'])
    
    # 发送回执给发送者
    emit('private_message_sent', {
        'to': receiver,
        'message': message
    })
    
    # 保存到数据库
    with sqlite3.connect(app.config['DATABASE']) as conn:
        c = conn.cursor()
        c.execute('''INSERT INTO messages 
                    (username, message, timestamp, color, is_private, target_user, message_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                 (sender, message, 
                  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                  color, 1, receiver, 'text'))
        conn.commit()

# 启动应用
if __name__ == '__main__':
    # 确保上传目录存在
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # 初始化数据库
    init_db()
    
    # 启动Socket.IO应用
    socketio.run(app, 
                 host='0.0.0.0', 
                 port=5000, 
                 debug=True,
                 use_reloader=False,
                 allow_unsafe_werkzeug=True)
