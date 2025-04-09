import os
import sqlite3
from datetime import datetime
import random
import uuid
from flask import Flask, render_template, request, session, redirect, url_for, flash, send_from_directory
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

# 数据库和用户管理
users = {}          # {sid: {'username': str, 'color': str}}
online_users = {}   # {username: {'sid': str, 'color': str}}
INVITATION_CODES = ["CHAT2023", "WELCOME123"]

def check_table_columns(table_name, required_columns):
    """检查表是否包含所有必需的列"""
    with sqlite3.connect('chat.db') as conn:
        c = conn.cursor()
        c.execute(f"PRAGMA table_info({table_name})")
        existing_columns = [col[1] for col in c.fetchall()]
        return all(col in existing_columns for col in required_columns)

def migrate_messages_table():
    """执行消息表迁移"""
    print("正在执行数据库迁移...")
    with sqlite3.connect('chat.db') as conn:
        c = conn.cursor()
        
        # 1. 重命名旧表
        c.execute("ALTER TABLE messages RENAME TO messages_old")
        
        # 2. 创建新表结构
        c.execute('''CREATE TABLE messages 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                     username TEXT, 
                     message TEXT, 
                     timestamp TEXT,
                     color TEXT,
                     is_private INTEGER DEFAULT 0,
                     target_user TEXT DEFAULT NULL,
                     message_type TEXT DEFAULT 'text')''')
        
        # 3. 迁移数据
        c.execute('''INSERT INTO messages 
                    (id, username, message, timestamp, color, is_private, target_user, message_type)
                    SELECT id, username, message, timestamp, color, is_private, target_user, 
                           CASE WHEN message LIKE '[图片]%' THEN 'image' ELSE 'text' END
                    FROM messages_old''')
        
        # 4. 清理旧表
        c.execute("DROP TABLE messages_old")
        
        # 5. 创建索引
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_private ON messages(is_private, target_user)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_type ON messages(message_type)")
        
        conn.commit()
    print("数据库迁移完成")

def init_db():
    """初始化数据库结构"""
    with sqlite3.connect('chat.db') as conn:
        c = conn.cursor()
        
        # 用户表
        c.execute('''CREATE TABLE IF NOT EXISTS users 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     username TEXT UNIQUE,
                     password TEXT,
                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        # 消息表（新结构）
        c.execute('''CREATE TABLE IF NOT EXISTS messages 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                     username TEXT, 
                     message TEXT, 
                     timestamp TEXT,
                     color TEXT,
                     is_private INTEGER DEFAULT 0,
                     target_user TEXT DEFAULT NULL,
                     message_type TEXT DEFAULT 'text')''')
        
        # 检查是否需要迁移
        if not check_table_columns('messages', ['message_type']):
            migrate_messages_table()
        else:
            # 确保索引存在
            c.execute("CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_messages_private ON messages(is_private, target_user)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_messages_type ON messages(message_type)")
        
        conn.commit()

def generate_dark_color():
    r = random.randint(0, 180)
    g = random.randint(0, 180)
    b = random.randint(0, 180)
    return f"#{r:02x}{g:02x}{b:02x}"

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# 路由
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect('chat.db') as conn:
        c = conn.cursor()
        c.execute("""
            SELECT username, message, timestamp, color, message_type 
            FROM messages 
            WHERE is_private = 0 OR (is_private = 1 AND target_user = ?)
            ORDER BY id DESC LIMIT 50
        """, (session['username'],))
        messages = c.fetchall()[::-1]
    
    return render_template('index.html', messages=messages, username=session['username'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        with sqlite3.connect('chat.db') as conn:
            c = conn.cursor()
            c.execute("SELECT password FROM users WHERE username = ?", (username,))
            result = c.fetchone()
            
        if result and check_password_hash(result[0], password):
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
        
        if invitation_code not in INVITATION_CODES:
            flash('邀请码无效')
        elif len(username) < 3:
            flash('用户名至少需要3个字符')
        elif len(password) < 6:
            flash('密码至少需要6个字符')
        else:
            try:
                with sqlite3.connect('chat.db') as conn:
                    c = conn.cursor()
                    hashed_password = generate_password_hash(password)
                    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                             (username, hashed_password))
                flash('注册成功，请登录')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('用户名已存在')
    return render_template('register.html', invitation_codes=INVITATION_CODES)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return {'error': '没有选择文件'}, 400
    
    file = request.files['file']
    if file.filename == '':
        return {'error': '没有选择文件'}, 400
    
    if not allowed_file(file.filename):
        return {'error': '不支持的文件类型'}, 400
    
    # 生成安全的文件名
    filename = secure_filename(file.filename)
    unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}_{filename}"
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    # 确保上传目录存在
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # 保存文件
    file.save(save_path)
    
    # 返回相对URL路径
    image_url = f"/static/uploads/{unique_filename}"
    return {'url': image_url}, 200

# Socket.IO 事件处理
@socketio.on('connect')
def handle_connect():
    if 'username' not in session:
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

@socketio.on('message')
def handle_message(data):
    if 'username' not in session or request.sid not in users:
        emit('message_error', {'error': '未登录或未加入聊天室'})
        return
    
    user = users[request.sid]
    timestamp = datetime.now().strftime('%H:%M:%S')
    
    # 处理图片消息
    if 'image_url' in data:
        message_type = 'image'
        content = data['image_url']
        display_content = f"[图片] {content}"
    else:
        message_type = 'text'
        content = data.get('message', '').strip()
        display_content = content
        if not content:
            emit('message_error', {'error': '消息不能为空'})
            return
    
    # 存储到数据库
    with sqlite3.connect('chat.db') as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO messages (username, message, timestamp, color, is_private, message_type) 
            VALUES (?, ?, ?, ?, 0, ?)
        """, (user['username'], display_content, timestamp, user['color'], message_type))
    
    # 广播消息
    emit('new_message', {
        'username': user['username'],
        'content': content if message_type == 'image' else display_content,
        'timestamp': timestamp,
        'color': user['color'],
        'type': message_type
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
            INSERT INTO messages (username, message, timestamp, color, is_private, target_user, message_type) 
            VALUES (?, ?, ?, ?, 1, ?, 'text')
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

def clean_old_files():
    """清理30天前的上传文件"""
    now = datetime.now().timestamp()
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.isfile(filepath):
            file_time = os.path.getmtime(filepath)
            if now - file_time > 30 * 86400:  # 30天
                os.unlink(filepath)
                print(f"已清理旧文件: {filename}")

if __name__ == '__main__':
    # 初始化数据库和上传目录
    init_db()
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # 启动前清理旧文件
    clean_old_files()
    
    # 启动应用
    socketio.run(app, 
                 host='0.0.0.0', 
                 port=5000, 
                 debug=True,
                 use_reloader=False,
                 allow_unsafe_werkzeug=True)
