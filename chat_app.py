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
app = Flask(__name__, static_folder='/var/www/chatroom/static')
app.secret_key = os.environ.get('SECRET_KEY') or 'dev-secret-key-123'

# 新路径配置
BASE_DIR = '/var/www/chatroom'
app.config.update({
    'UPLOAD_FOLDER': os.path.join(BASE_DIR, 'static/uploads'),
    'MAX_CONTENT_LENGTH': 5 * 1024 * 1024,  # 5MB
    'ALLOWED_EXTENSIONS': {'png', 'jpg', 'jpeg', 'gif'},
    'DATABASE': os.path.join(BASE_DIR, 'chat.db'),
    'PREFERRED_URL_SCHEME': 'https'
})

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
                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
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
        
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = c.fetchone()
            
            if user and check_password_hash(user['password'], password):
                session['username'] = username
                return redirect(url_for('index'))
            
        return render_template('login.html', error='用户名或密码错误')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            return render_template('register.html', error='用户名和密码不能为空')
        
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                         (username, generate_password_hash(password)))
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
    response.headers['Cache-Control'] = 'public, max-age=31536000'
    
    return response

# Socket.IO 事件处理 [保持不变...]

if __name__ == '__main__':
    # 确保目录存在
    os.makedirs(BASE_DIR, exist_ok=True)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # 初始化数据库
    init_db()
    
    # 启动应用
    socketio.run(app, 
                host='0.0.0.0', 
                port=5000, 
                debug=True,
                use_reloader=False)
