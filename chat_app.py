import os
import eventlet
eventlet.monkey_patch()
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, session, redirect, url_for, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import uuid


# 应用配置
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'dev-secret-key-123'
app.config['UPLOAD_FOLDER'] = '/var/www/chatroom/static/uploads'  # 修改路径
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['DATABASE'] = '/var/www/chatroom/chat.db'  # 修改路径
app.config['PREFERRED_URL_SCHEME'] = 'https'

# 禁用SERVER_NAME以避免URL生成问题
# app.config['SERVER_NAME'] = 'chat.lxlxlx.xin'

# Socket.IO 配置
socketio = SocketIO(app, 
                   cors_allowed_origins="*",
                   async_mode='eventlet',
                   logger=True)

# 用户和房间管理
users = {}          # {sid: {'username': str, 'color': str}}
online_users = {}   # {username: {'sid': str, 'color': str}}
user_colors = {}    # 用户颜色缓存

def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

# 数据库初始化
def init_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     username TEXT UNIQUE,
                     password TEXT,
                     invitation_code TEXT,
                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        conn.commit()
        
        c.execute('''CREATE TABLE IF NOT EXISTS messages 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                     username TEXT, 
                     message TEXT, 
                     timestamp TEXT,
                     color TEXT,
                     is_private INTEGER DEFAULT 0,
                     target_user TEXT DEFAULT NULL,
                     message_type TEXT DEFAULT 'text')''')
        
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_private ON messages(is_private, target_user)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_messages_type ON messages(message_type)")
        
        c.execute('''CREATE TABLE IF NOT EXISTS private_conversations 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     user1 TEXT NOT NULL,
                     user2 TEXT NOT NULL,
                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                     UNIQUE(user1, user2))''')
        
        # 新增私聊消息表 (替代原messages表中的私聊消息)
        c.execute('''CREATE TABLE IF NOT EXISTS private_messages 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     conversation_id INTEGER NOT NULL,
                     sender TEXT NOT NULL,
                     message TEXT NOT NULL,
                     timestamp TEXT NOT NULL,
                     message_type TEXT DEFAULT 'text',
                     FOREIGN KEY(conversation_id) REFERENCES private_conversations(id))''')
        
        c.execute("CREATE INDEX IF NOT EXISTS idx_private_conversations_users ON private_conversations(user1, user2)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_private_messages_conversation ON private_messages(conversation_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_private_messages_timestamp ON private_messages(timestamp)")
        
        conn.commit()
        
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

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''SELECT username, message, timestamp, color, message_type 
                     FROM messages 
                     WHERE is_private = 0 OR (is_private = 1 AND target_user = ?)
                     ORDER BY id DESC LIMIT 50''', (session['username'],))
        messages = [dict(row) for row in c.fetchall()][::-1]
    
    # 预处理消息中的图片URL
    for msg in messages:
        if msg['message_type'] == 'image' and not msg['message'].startswith('http'):
            msg['message'] = f"/static/uploads/{os.path.basename(msg['message'])}"
    
    return render_template('index.html',
                         username=session['username'],
                         messages=messages)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            return render_template('login.html', error='用户名和密码不能为空')
        
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT * FROM users WHERE username = ?", (username,))
                user = c.fetchone()
                
                if user:
                    if check_password_hash(user['password'], password):
                        session.permanent = True
                        session['username'] = username
                        return redirect(url_for('index'))
                    else:
                        return render_template('login.html', 
                                            error='密码错误',
                                            request=request)
                else:
                    return render_template('login.html', 
                                        error='用户不存在',
                                        request=request)
        
        except Exception as e:
            app.logger.error(f"登录错误: {str(e)}")
            return render_template('login.html', 
                                error='系统错误，请稍后再试',
                                request=request)
    
    # GET请求时清除可能的旧session
    if 'username' in session:
        session.pop('username', None)
    
    return render_template('login.html', request=request)

# 在配置部分添加邀请码设置
VALID_INVITATION_CODES = ['CHAT2023', 'WELCOME123']  # 可配置为从数据库或环境变量读取

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        invitation_code = request.form.get('invitation_code', '').strip()
        
        # 验证所有字段
        if not all([username, password, invitation_code]):
            return render_template('register.html', 
                                error='所有字段都必须填写',
                                invitation_codes=VALID_INVITATION_CODES)
        
        # 验证邀请码
        if invitation_code not in VALID_INVITATION_CODES:
            return render_template('register.html',
                                error='无效的邀请码',
                                invitation_codes=VALID_INVITATION_CODES)
        
        # 验证用户名复杂度
        if len(username) < 4 or len(username) > 20:
            return render_template('register.html',
                                error='用户名长度需在4-20个字符之间',
                                invitation_codes=VALID_INVITATION_CODES)
        
        # 验证密码强度
        if len(password) < 8:
            return render_template('register.html',
                                error='密码长度至少8个字符',
                                invitation_codes=VALID_INVITATION_CODES)
        
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                
                # 检查用户名是否存在
                c.execute("SELECT id FROM users WHERE username = ?", (username,))
                if c.fetchone():
                    return render_template('register.html',
                                        error='用户名已存在',
                                        invitation_codes=VALID_INVITATION_CODES)
                
                # 创建用户
                c.execute("""
                    INSERT INTO users (username, password, invitation_code) 
                    VALUES (?, ?, ?)
                """, (username, generate_password_hash(password), invitation_code))
                conn.commit()
            
            # 注册成功后自动登录
            session.permanent = True
            session['username'] = username
            return redirect(url_for('index'))
            
        except Exception as e:
            app.logger.error(f"注册失败: {str(e)}")
            return render_template('register.html',
                                error='注册失败，请稍后再试',
                                invitation_codes=VALID_INVITATION_CODES)
    
    # GET请求显示注册表单
    return render_template('register.html',
                         invitation_codes=VALID_INVITATION_CODES)


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
        unique_filename = f"{uuid.uuid4().hex[:8]}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(filepath)
        
        return jsonify({
            'url': f"/static/uploads/{unique_filename}"
        })
    
    return jsonify({'error': 'File type not allowed'}), 400

@app.route('/static/uploads/<filename>')
def uploaded_file(filename):
    # 确保文件名安全
    safe_filename = secure_filename(filename)
    if not safe_filename or safe_filename != filename:
        return "Invalid filename", 400
    
    # 检查文件是否存在
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
    if not os.path.exists(filepath):
        return "File not found", 404
    
    # 设置正确的MIME类型
    mimetype = None
    if filename.lower().endswith('.png'):
        mimetype = 'image/png'
    elif filename.lower().endswith('.jpg') or filename.lower().endswith('.jpeg'):
        mimetype = 'image/jpeg'
    elif filename.lower().endswith('.gif'):
        mimetype = 'image/gif'
    
    # 发送文件并设置安全头
    response = send_from_directory(
        app.config['UPLOAD_FOLDER'],
        safe_filename,
        mimetype=mimetype
    )
    
    # 安全头设置
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Cache-Control'] = 'public, max-age=31536000'  # 1年缓存
    
    return response

# Socket.IO 事件处理
@socketio.on('connect')
def handle_connect():
    if 'username' not in session:
        return
    
    sid = request.sid
    username = session['username']
    color = get_user_color(username)
    
    users[sid] = {'username': username, 'color': color}
    online_users[username] = {'sid': sid, 'color': color}
    
    emit('update_users', {'users': list(online_users.keys())}, broadcast=True)
    
    message_data = {
        'username': '系统',
        'content': f"{username} 加入了聊天室",
        'timestamp': datetime.now().strftime("%H:%M:%S"),
        'color': '#6b7280',
        'message_type': 'system'
    }
    emit('new_message', message_data, broadcast=True)
    
    with get_db_connection() as conn:
        conn.execute('''INSERT INTO messages 
                      (username, message, timestamp, color, is_private, message_type)
                      VALUES (?, ?, ?, ?, ?, ?)''',
                   ('系统', f"{username} 加入了聊天室", 
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    '#6b7280', 0, 'system'))
        conn.commit()

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    if sid not in users:
        return
    
    username = users[sid]['username']
    color = users[sid]['color']
    
    del users[sid]
    if username in online_users:
        del online_users[username]
    
    emit('update_users', {'users': list(online_users.keys())}, broadcast=True)
    
    message_data = {
        'username': '系统',
        'content': f"{username} 离开了聊天室",
        'timestamp': datetime.now().strftime("%H:%M:%S"),
        'color': '#6b7280',
        'message_type': 'system'
    }
    emit('new_message', message_data, broadcast=True)
    
    with get_db_connection() as conn:
        conn.execute('''INSERT INTO messages 
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
    
    if 'text' in data and data['text'].strip():
        message_content = data['text'].strip()
        message_type = 'text'
        
        message_data = {
            'username': username,
            'content': message_content,
            'timestamp': timestamp,
            'color': color,
            'message_type': message_type
        }
        emit('new_message', message_data, broadcast=True)
        
        with get_db_connection() as conn:
            conn.execute('''INSERT INTO messages 
                          (username, message, timestamp, color, is_private, message_type)
                          VALUES (?, ?, ?, ?, ?, ?)''',
                       (username, message_content, 
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        color, 0, message_type))
            conn.commit()
    
    elif 'image_url' in data and data['image_url']:
        message_content = data['image_url']
        message_type = 'image'
        
        message_data = {
            'username': username,
            'content': message_content,
            'timestamp': timestamp,
            'color': color,
            'message_type': message_type
        }
        emit('new_message', message_data, broadcast=True)
        
        with get_db_connection() as conn:
            conn.execute('''INSERT INTO messages 
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
    receiver = data.get('to', '').strip()
    message = data.get('message', '').strip()
    
    if not receiver or not message:
        emit('error', {'message': '缺少接收者或消息内容'})
        return
    
    if receiver not in online_users:
        emit('error', {'message': '用户不在线'})
        return
    
    color = get_user_color(sender)
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    # 获取或创建会话
    with get_db_connection() as conn:
        # 确保会话存在 (user1总是字母顺序较小的用户名)
        user1, user2 = sorted([sender, receiver])
        conn.execute('''INSERT OR IGNORE INTO private_conversations 
                      (user1, user2) VALUES (?, ?)''', (user1, user2))
        
        # 获取会话ID
        c = conn.cursor()
        c.execute('''SELECT id FROM private_conversations 
                   WHERE user1 = ? AND user2 = ?''', (user1, user2))
        conversation_id = c.fetchone()['id']
        
        # 存储私聊消息
        conn.execute('''INSERT INTO private_messages 
                      (conversation_id, sender, message, timestamp, message_type)
                      VALUES (?, ?, ?, ?, ?)''',
                   (conversation_id, sender, message, 
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'text'))
        conn.commit()
    
    # 发送消息给接收者
    emit('private_message_received', {
        'from': sender,
        'message': message,
        'timestamp': timestamp,
        'color': color
    }, room=online_users[receiver]['sid'])
    
    # 发送确认给发送者
    emit('private_message_sent', {
        'to': receiver,
        'message': message,
        'timestamp': timestamp
    })
    
@app.route('/api/private_messages/<other_user>')
def get_private_messages(other_user):
    if 'username' not in session:
        return jsonify({'error': '未登录'}), 401
    
    current_user = session['username']
    user1, user2 = sorted([current_user, other_user])
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''SELECT pm.sender, pm.message, pm.timestamp, pm.message_type
                     FROM private_messages pm
                     JOIN private_conversations pc ON pm.conversation_id = pc.id
                     WHERE pc.user1 = ? AND pc.user2 = ?
                     ORDER BY pm.timestamp DESC LIMIT 50''', (user1, user2))
        messages = [dict(row) for row in c.fetchall()][::-1]
    
    return jsonify({'messages': messages})
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    init_db()
    
    with app.app_context():
        socketio.run(app, 
                    host='0.0.0.0', 
                    port=5000, 
                    debug=True,
                    use_reloader=False)
