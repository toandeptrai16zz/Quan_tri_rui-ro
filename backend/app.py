# ================== IMPORTS ==================
import os
#Cài đặt thêm thư viện eventlet
import eventlet
eventlet.monkey_patch()
import secrets
import time
import random
import socket
import subprocess
import logging
import stat
import shutil
import base64
import re
import json
import smtplib
import threading
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from collections import defaultdict

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_socketio import SocketIO, emit
import mysql.connector
import paramiko
from werkzeug.security import generate_password_hash, check_password_hash

# ================== APP SETUP ==================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler('app.log'), logging.StreamHandler()]
)
#Sửa đường dẫn chỉ rõ thư mục frontend , vì cấu trúc thư mục khác Chỉ sửa FE
app = Flask(__name__, template_folder="../frontend/templates")
app.secret_key = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# ================== CONFIGURATIONS ==================
SECURITY_CONFIG = {
    'MAX_LOGIN_ATTEMPTS': 5, 'LOCKOUT_DURATION': 300, 'OTP_EXPIRY': 300,
    'SESSION_TIMEOUT': 1800, 'CSRF_EXPIRY': 3600, 'PASSWORD_MIN_LENGTH': 8,
    'USERNAME_MIN_LENGTH': 3, 'RATE_LIMIT_PER_MINUTE': 60,
}
EMAIL_CONFIG = {
    'SMTP_SERVER': 'smtp.gmail.com', 'SMTP_PORT': 587,
    'SMTP_USERNAME': 'haquangchuong28@gmail.com',
    'SMTP_PASSWORD': 'wddxglvwvpyznppn',
    'FROM_EMAIL': 'haquangchuong28@gmail.com'
}

# ================== IN-MEMORY STORAGE ==================
login_attempts = defaultdict(lambda: {'count': 0, 'locked_until': None})
otp_storage = {}
csrf_tokens = {}
rate_limiter = defaultdict(lambda: {'requests': [], 'blocked_until': None})

# ================== SECURITY UTILITIES ==================
def generate_csrf_token():
    token = secrets.token_urlsafe(32)
    csrf_tokens[token] = {'created_at': time.time(), 'user_ip': request.remote_addr if request else None}
    expired = [t for t, data in list(csrf_tokens.items()) if time.time() - data['created_at'] > SECURITY_CONFIG['CSRF_EXPIRY']]
    for t in expired: del csrf_tokens[t]
    return token

#sua dong 65
def validate_csrf_token(token):
    if not token or token not in csrf_tokens: return False
    if time.time() - csrf_tokens[token]['created_at'] > SECURITY_CONFIG['CSRF_EXPIRY']:
        del csrf_tokens[token]
        return False
    return True

def generate_captcha():
    chars, captcha = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', ''.join(random.choices(chars, k=6))
    token = base64.b64encode(f"{captcha}:{time.time()}".encode()).decode()
    return captcha, token

def validate_captcha(user_input, token):
    try:
        decoded = base64.b64decode(token.encode()).decode()
        captcha, timestamp = decoded.split(':', 1)
        if time.time() - float(timestamp) > 300: return False
        return user_input.upper() == captcha.upper()
    except: return False

def generate_otp(): return ''.join(random.choices('0123456789', k=6))

def send_otp_email(email, otp, username):
    try:
        msg = MIMEMultipart()
        msg['From'], msg['To'], msg['Subject'] = EMAIL_CONFIG['FROM_EMAIL'], email, "EPU Tech - Mã xác thực"
        body = f"Xin chào {username},\n\nMã xác thực của bạn là: {otp}\n\nMã này có hiệu lực trong 5 phút."
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        server = smtplib.SMTP(EMAIL_CONFIG['SMTP_SERVER'], EMAIL_CONFIG['SMTP_PORT'])
        server.starttls()
        server.login(EMAIL_CONFIG['SMTP_USERNAME'], EMAIL_CONFIG['SMTP_PASSWORD'])
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        app.logger.error(f"EMAIL SEND ERROR: {e}")
        return False
#xinchao
def validate_password_strength(password):
    if len(password) < SECURITY_CONFIG['PASSWORD_MIN_LENGTH']: return False, "Mật khẩu phải dài ít nhất 8 ký tự"
    if not re.search("[a-z]", password): return False, "Mật khẩu phải chứa chữ thường"
    if not re.search("[A-Z]", password): return False, "Mật khẩu phải chứa chữ HOA"
    if not re.search("[0-9]", password): return False, "Mật khẩu phải chứa số"
    return True, ""

# ================== DECORATORS ==================
def require_auth(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                flash('Vui lòng đăng nhập để tiếp tục.', 'warning')
                return redirect(url_for('login_page'))
            if 'last_activity' in session and time.time() - session['last_activity'] > SECURITY_CONFIG['SESSION_TIMEOUT']:
                session.clear()
                flash('Phiên đăng nhập đã hết hạn', 'warning')
                return redirect(url_for('login_page'))
            session['last_activity'] = time.time()
            if role and session.get('role') != role:
                flash('Bạn không có quyền truy cập trang này.', 'error')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Basic rate limiting logic can be added here
        return f(*args, **kwargs)
    return decorated_function

# ================== DATABASE & DOCKER HELPERS ==================
def get_db_connection():
    try:
        # Đọc thông tin kết nối từ biến môi trường
        db_host = os.environ.get('DB_HOST')
        db_user = os.environ.get('DB_USER')
        db_password = os.environ.get('DB_PASSWORD')
        db_name = os.environ.get('DB_NAME')
        
        return mysql.connector.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name,
            autocommit=True
        )
    except Exception as e:
        app.logger.error(f"DATABASE CONNECTION ERROR: {e}")
        return None

def init_db():
    db = get_db_connection()
    if not db: return
    cur = db.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50) NOT NULL UNIQUE, password VARCHAR(255) NOT NULL, email VARCHAR(255) NULL UNIQUE, role ENUM('admin','user') NOT NULL DEFAULT 'user', status ENUM('pending','active','blocked') NOT NULL DEFAULT 'pending', ssh_port INT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, last_login TIMESTAMP NULL);")
    cur.execute("CREATE TABLE IF NOT EXISTS logs (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50) NOT NULL, action VARCHAR(255) NOT NULL, timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, ip_address VARCHAR(45) NULL, user_agent TEXT NULL, success BOOLEAN DEFAULT TRUE, details JSON NULL);")
    cur.execute("SELECT id FROM users WHERE username='admin'")
    if not cur.fetchone():
        hashed_password = generate_password_hash('admin123@')
        cur.execute("INSERT INTO users (username, password, email, role, status) VALUES (%s, %s, %s, %s, %s)", ('admin', hashed_password, 'admin@eputech.com', 'admin', 'active'))
        app.logger.info("Created default admin user")
    db.commit()
    cur.close()
    db.close()

def log_action(username, action, success=True, details=None):
    try:
        db = get_db_connection()
        if not db: return
        cur = db.cursor()
        cur.execute("INSERT INTO logs (username, action, ip_address, user_agent, success, details) VALUES (%s, %s, %s, %s, %s, %s)",
                    (username, action, request.remote_addr, request.user_agent.string, success, json.dumps(details) if details else None))
        db.commit()
        cur.close()
        db.close()
    except Exception as e:
        app.logger.error(f"LOG ACTION ERROR: {e}")

def find_free_port(start=2200, end=2299):
    for _ in range(100):
        port = random.randint(start, end)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    return None

def docker_status(cname):
    try:
        r = subprocess.run(["docker", "inspect", "-f", "{{.State.Status}}", cname], capture_output=True, text=True, check=False, timeout=5)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""

def ensure_user_container(username):
    cname = f"{username}-dev"
    image = "my-dev-env:v2"
    db = get_db_connection()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT ssh_port FROM users WHERE username=%s", (username,))
    user_data = cur.fetchone()
    ssh_port = user_data.get("ssh_port") if user_data else None
    status = docker_status(cname)
    if not status or status != 'running':
        app.logger.info(f"Container '{cname}' not running (status: '{status}'). Ensuring it is started.")
        if not ssh_port:
            ssh_port = find_free_port()
            if not ssh_port: raise Exception("No free port available.")
            cur.execute("UPDATE users SET ssh_port=%s WHERE username=%s", (ssh_port, username))
            db.commit()
        if not status:
            host_user_dir = f"/home/chuongdev/QUAN_LY_USER/{username}"
            os.makedirs(host_user_dir, exist_ok=True)
            subprocess.run([
                "docker", "run", "-d", "--name", cname, "--restart", "always",
                "-p", f"{ssh_port}:22", "-e", f"USERNAME={username}", "-e", "PASSWORD=password123",
                "-v", f"{host_user_dir}:/home/{username}", image
            ], check=True, timeout=30)
            app.logger.info(f"Started new container '{cname}' on port {ssh_port}.")
        else:
            subprocess.run(["docker", "start", cname], check=True, timeout=10)
            app.logger.info(f"Restarted existing container '{cname}'.")
    cur.close()
    db.close()
    return ssh_port

def get_ssh_client(username):
    db = get_db_connection()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT ssh_port FROM users WHERE username=%s", (username,))
    user = cur.fetchone()
    cur.close()
    db.close()
    if not user or not user['ssh_port']: raise Exception("SSH port not configured.")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('127.0.0.1', port=user['ssh_port'], username=username, password='password123', timeout=10)
    return client

# ================== AUTHENTICATION ROUTES ==================
@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("admin_dashboard" if session.get("role") == "admin" else "user_redirect"))
    return redirect(url_for("login_page"))

@app.route("/api/generate-csrf", methods=["GET"])
def generate_csrf_api():
    return jsonify({'csrf_token': generate_csrf_token()})

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/api/login", methods=["POST"])
def login_api():
    ip_address = request.remote_addr
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    captcha = request.form.get("captcha", "").strip()
    captcha_token = request.form.get("captcha_token", "")
    csrf_token = request.form.get("csrf_token", "")

    if not all([username, password, captcha, captcha_token, csrf_token]):
        return jsonify({'success': False, 'message': 'Vui lòng điền đầy đủ thông tin'}), 400
    if not validate_csrf_token(csrf_token):
        return jsonify({'success': False, 'message': 'Token bảo mật không hợp lệ'}), 400
    if not validate_captcha(captcha, captcha_token):
        return jsonify({'success': False, 'message': 'Mã xác thực không đúng'}), 400

    db = get_db_connection()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cur.fetchone()

    if user and check_password_hash(user['password'], password):
        if user["status"] == "active":
            cur.execute("UPDATE users SET last_login=NOW() WHERE id=%s", (user['id'],))
            db.commit()
            if user.get('email'):
                otp = generate_otp()
                otp_storage[username] = {'otp': otp, 'expires_at': time.time() + SECURITY_CONFIG['OTP_EXPIRY'], 'ip': ip_address}
                send_otp_email(user['email'], otp, username)
                log_action(username, "Login: OTP sent")
                cur.close(), db.close()
                return jsonify({'success': True, 'requireOTP': True})
            else:
                session["username"], session["role"], session["last_activity"] = user["username"], user["role"], time.time()
                log_action(username, "Login: Success")
                cur.close(), db.close()
                return jsonify({'success': True, 'requireOTP': False, 'redirect': url_for('admin_dashboard' if user['role'] == 'admin' else 'user_redirect')})
        else:
            cur.close(), db.close()
            return jsonify({'success': False, 'message': 'Tài khoản đã bị khóa hoặc đang chờ xử lý.'}), 403
    else:
        cur.close(), db.close()
        log_action(username, "Login: Failed", False)
        return jsonify({'success': False, 'message': 'Sai tài khoản hoặc mật khẩu!'}), 401

@app.route("/api/verify-otp", methods=["POST"])
def verify_otp():
    otp = request.json.get('otp')
    username = next((user for user, data in otp_storage.items() if data.get('ip') == request.remote_addr), None)
    if not username or username not in otp_storage: return jsonify({'success': False, 'error': 'Không tìm thấy phiên OTP'}), 400
    otp_data = otp_storage[username]
    if time.time() > otp_data['expires_at']:
        del otp_storage[username]
        return jsonify({'success': False, 'error': 'Mã OTP đã hết hạn'}), 400
    if otp == otp_data['otp']:
        db = get_db_connection()
        cur = db.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cur.fetchone()
        cur.close()
        db.close()
        if user:
            session["username"], session["role"], session["last_activity"] = user["username"], user["role"], time.time()
            del otp_storage[username]
            log_action(username, "Login: OTP verified")
            return jsonify({'success': True, 'redirect': url_for('admin_dashboard' if user['role'] == 'admin' else 'user_redirect')})
    return jsonify({'success': False, 'error': 'Mã OTP không đúng'}), 400

@app.route("/logout")
def logout():
    log_action(session.get("username", "unknown"), "Logout: Success")
    session.clear()
    flash("Đã đăng xuất.", "info")
    return redirect(url_for("login_page"))

# ================== REGISTRATION WITH OTP ROUTES ==================
@app.route("/register", methods=["GET", "POST"])
def register():
    if "username" in session: return redirect(url_for("index"))
    if request.method == "POST":
        username, password, email = request.form["username"].strip(), request.form["password"].strip(), request.form.get("email", "").strip()
        
        is_strong, message = validate_password_strength(password)
        if not is_strong:
            flash(message, "error")
            return redirect(url_for("register"))
        if not email:
            flash("Vui lòng nhập email để xác thực.", "error")
            return redirect(url_for("register"))

        db = get_db_connection()
        cur = db.cursor()
        cur.execute("SELECT id FROM users WHERE username=%s OR email=%s", (username, email))
        if cur.fetchone():
            flash("Username hoặc Email đã tồn tại!", "error")
            cur.close(), db.close()
            return redirect(url_for("register"))

        otp = generate_otp()
        session['registration_data'] = {
            'username': username, 'password': generate_password_hash(password), 'email': email,
            'otp': otp, 'expires_at': time.time() + SECURITY_CONFIG['OTP_EXPIRY']
        }
        send_otp_email(email, otp, username)
        log_action(username, f"Register: OTP sent to {email}")
        return redirect(url_for('verify_email'))
    return render_template("register.html")

@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    if 'registration_data' not in session: return redirect(url_for('register'))
    reg_data = session['registration_data']
    if time.time() > reg_data['expires_at']:
        session.pop('registration_data', None)
        flash("Mã OTP đã hết hạn. Vui lòng đăng ký lại.", "error")
        return redirect(url_for('register'))
    if request.method == 'POST' and request.form.get('otp', '') == reg_data['otp']:
        db = get_db_connection()
        cur = db.cursor()
        cur.execute("INSERT INTO users(username, password, email, status, role) VALUES(%s, %s, %s, 'active', 'user')",
                    (reg_data['username'], reg_data['password'], reg_data['email']))
        db.commit()
        cur.close(), db.close()
        log_action(reg_data['username'], "Register success")
        session.pop('registration_data', None)
        flash("Xác thực và đăng ký thành công! Bây giờ bạn có thể đăng nhập.", "success")
        return redirect(url_for('login_page'))
    elif request.method == 'POST':
        flash("Mã OTP không chính xác!", "error")
    return render_template('verify_email.html', email=reg_data['email'])

# ================== USER ROUTES & IDE APIS ==================
@app.route("/user")
@require_auth('user')
def user_redirect():
    return redirect(url_for('user_workspace', username=session['username']))

@app.route("/user/<username>/workspace")
@require_auth('user')
def user_workspace(username):
    if session["username"] != username: return redirect(url_for("index"))
    try:
        ensure_user_container(username)
    except Exception as e:
        app.logger.error(f"Container check failed for {username}: {e}")
        flash("Lỗi khởi tạo môi trường làm việc!", "error")
    return render_template("user.html", username=username)

@app.route('/user/<username>/files', methods=['POST'])
@require_auth('user')
def list_files_api(username):
    if session['username'] != username: return jsonify(error="Unauthorized"), 403
    path = request.json.get("path", ".")
    if '..' in path or path.startswith('/'): return jsonify(error="Invalid path"), 400
    try:
        client = get_ssh_client(username)
        sftp = client.open_sftp()
        base_path = os.path.join("/home", username, path)
        files = []
        for attr in sftp.listdir_attr(base_path):
            if not attr.filename.startswith('.'):
                files.append({'name': attr.filename, 'is_dir': stat.S_ISDIR(attr.st_mode), 'size': attr.st_size, 'modified': attr.st_mtime})
        sftp.close(); client.close()
        files.sort(key=lambda x: (not x['is_dir'], x['name']))
        log_action(username, f"List files: {base_path}")
        return jsonify(files=files, path=path)
    except Exception as e: return jsonify(error=str(e)), 500

@app.route('/user/<username>/create-folder', methods=['POST'])
@require_auth('user')
def create_folder_api(username):
    if session['username'] != username: return jsonify(success=False, error="Unauthorized"), 403
    data = request.get_json()
    folder_name, path = data.get("folder_name"), data.get("path", ".")
    if not folder_name or '..' in folder_name or '/' in folder_name: return jsonify(success=False, error="Invalid folder name"), 400
    if '..' in path or path.startswith('/'): return jsonify(success=False, error="Invalid path"), 400
    try:
        client = get_ssh_client(username)
        sftp = client.open_sftp()
        full_path = os.path.join("/home", username, path, folder_name)
        sftp.mkdir(full_path)
        sftp.close(); client.close()
        log_action(username, f"Create folder: {full_path}")
        return jsonify(success=True)
    except Exception as e: return jsonify(success=False, error=str(e)), 500

@app.route('/user/<username>/editor/load', methods=['POST'])
@require_auth('user')
def load_file_api(username):
    if session['username'] != username: return jsonify(success=False, error="Unauthorized"), 403
    data = request.get_json()
    filename, path = data.get("filename"), data.get("path", ".")
    if not filename or '..' in filename or '..' in path: return jsonify(success=False, error="Invalid file path"), 400
    try:
        client = get_ssh_client(username)
        sftp = client.open_sftp()
        filepath = os.path.join("/home", username, path, filename)
        with sftp.open(filepath, 'r') as f: content = f.read().decode('utf-8', errors='ignore')
        sftp.close(); client.close()
        log_action(username, f"Open file: {filepath}")
        return jsonify(success=True, content=content)
    except Exception as e: return jsonify(success=False, error=str(e)), 500

@app.route('/user/<username>/editor/save', methods=['POST'])
@require_auth('user')
def save_file_api(username):
    if session['username'] != username: return jsonify(success=False, error="Unauthorized"), 403
    data = request.get_json()
    filename, content, path = data.get("filename"), data.get("content", ""), data.get("path", ".")
    if not filename or '..' in filename or '..' in path: return jsonify(success=False, error="Invalid file path"), 400
    try:
        client = get_ssh_client(username)
        sftp = client.open_sftp()
        filepath = os.path.join("/home", username, path, filename)
        with sftp.open(filepath, 'w') as f: f.write(content)
        sftp.close(); client.close()
        log_action(username, f"Save file: {filepath}")
        return jsonify(success=True)
    except Exception as e: return jsonify(success=False, error=str(e)), 500

@app.route('/user/<username>/rename-item', methods=['POST'])
@require_auth('user')
def rename_item_api(username):
    if session['username'] != username: return jsonify(success=False, error="Unauthorized"), 403
    data = request.get_json()
    old_path, new_name = data.get("old_path"), data.get("new_name")
    if not all([old_path, new_name]) or '..' in old_path or '..' in new_name or '/' in new_name: return jsonify(success=False, error="Invalid parameters"), 400
    try:
        client = get_ssh_client(username)
        sftp = client.open_sftp()
        base_dir = os.path.dirname(old_path)
        old_full_path = os.path.join("/home", username, old_path)
        new_full_path = os.path.join("/home", username, base_dir, new_name)
        sftp.rename(old_full_path, new_full_path)
        sftp.close(); client.close()
        log_action(username, f"Rename: from {old_path} to {os.path.join(base_dir, new_name)}")
        return jsonify(success=True)
    except Exception as e: return jsonify(success=False, error=str(e)), 500

@app.route('/user/<username>/delete-item', methods=['POST'])
@require_auth('user')
def delete_item_api(username):
    if session['username'] != username: return jsonify(success=False, error="Unauthorized"), 403
    path = request.json.get("path")
    if not path or '..' in path: return jsonify(success=False, error="Invalid path"), 400
    try:
        client = get_ssh_client(username)
        full_path = os.path.normpath(os.path.join("/home", username, path))
        if not full_path.startswith(f"/home/{username}/") or full_path == f"/home/{username}":
             return jsonify(success=False, error="Access denied"), 403
        stdin, stdout, stderr = client.exec_command(f'rm -rf "{full_path}"')
        if stdout.channel.recv_exit_status() == 0:
            log_action(username, f"Delete: {path}")
            return jsonify(success=True)
        else:
            raise Exception(stderr.read().decode().strip())
    except Exception as e: return jsonify(success=False, error=str(e)), 500

@app.route('/user/<username>/upload-files', methods=['POST'])
@require_auth('user')
def upload_files_api(username):
    if session['username'] != username: return jsonify(success=False, error="Unauthorized"), 403
    path, files = request.form.get('path', '.'), request.files.getlist('files')
    if not files: return jsonify(success=False, error="No files provided"), 400
    if '..' in path: return jsonify(success=False, error="Invalid path"), 400
    try:
        client = get_ssh_client(username)
        sftp = client.open_sftp()
        for file in files:
            if file.filename:
                sftp.putfo(file, os.path.join("/home", username, path, file.filename))
                log_action(username, f"Upload: {file.filename} to {path}")
        sftp.close(); client.close()
        return jsonify(success=True, message=f"Uploaded {len(files)} files.")
    except Exception as e: return jsonify(success=False, error=str(e)), 500

# ▼▼▼ DÁN ĐOẠN CODE API BIÊN DỊCH MỚI VÀO ĐÂY ▼▼▼
# =================================================================

@app.route('/user/<username>/compile', methods=['POST'])
@require_auth('user')
def compile_sketch_api(username):
    if session['username'] != username:
        return jsonify(error="Unauthorized"), 403

    data = request.get_json()
    sketch_path = data.get("sketch_path")
    board_fqbn = data.get("board_fqbn")

    if not sketch_path or not board_fqbn:
        return jsonify({"success": False, "output": "Lỗi: Thiếu đường dẫn file hoặc loại board."}), 400

    cname = f"{username}-dev"
    full_sketch_path = os.path.normpath(os.path.join("/home", username, sketch_path))

    try:
        # ✅ Sửa lỗi bằng cách sử dụng đường dẫn tuyệt đối
        command = [
            "docker", "exec", cname,
            "/usr/local/bin/arduino-cli", "compile",
            "--fqbn", board_fqbn,
            "--verbose",
            full_sketch_path
        ]

        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        
        full_output = ""
        if result.stdout:
            full_output += result.stdout
        if result.stderr:
            if full_output:
                full_output += "\n" + result.stderr
            else:
                full_output = result.stderr

        if result.returncode == 0:
            log_action(username, f"Compile success: {sketch_path} for {board_fqbn}")
            return jsonify({
                "success": True,
                "output": full_output + "\n\n✅ BIÊN DỊCH THÀNH CÔNG!",
                "returncode": result.returncode
            })
        else:
            log_action(username, f"Compile failed: {sketch_path}", success=False, 
                      details={"error_log": result.stderr, "returncode": result.returncode})
            
            error_analysis = analyze_compile_errors(full_output)
            
            return jsonify({
                "success": False,
                "output": full_output + "\n\n❌ BIÊN DỊCH THẤT BẠI!",
                "returncode": result.returncode,
                "error_analysis": error_analysis
            })

    except subprocess.TimeoutExpired:
        log_action(username, f"Compile timeout: {sketch_path}", success=False)
        return jsonify({
            "success": False, 
            "output": "Lỗi: Quá thời gian biên dịch (120 giây).",
            "error_type": "timeout"
        }), 500
    except Exception as e:
        app.logger.error(f"Compile API error for {username}: {e}")
        log_action(username, f"Compile system error: {sketch_path}", success=False, 
                  details={"system_error": str(e)})
        return jsonify({
            "success": False, 
            "output": f"Lỗi hệ thống: {str(e)}",
            "error_type": "system_error"
        }), 500

def analyze_compile_errors(output):
    """
    Phân tích output để tìm thông tin lỗi chi tiết
    """
    errors = []
    warnings = []
    
    lines = output.split('\n')
    
    for i, line in enumerate(lines):
        line = line.strip()
        
        # Tìm lỗi compile (error)
        if 'error:' in line.lower():
            error_info = extract_error_info(line, lines, i)
            if error_info:
                errors.append(error_info)
        
        # Tìm cảnh báo (warning)  
        elif 'warning:' in line.lower():
            warning_info = extract_warning_info(line, lines, i)
            if warning_info:
                warnings.append(warning_info)
    
    return {
        'errors': errors,
        'warnings': warnings,
        'error_count': len(errors),
        'warning_count': len(warnings)
    }

def extract_error_info(error_line, all_lines, line_index):
    """
    Trích xuất thông tin chi tiết về lỗi
    """
    import re
    
    # Pattern để tìm file:line:column: error
    pattern = r'(.+?):(\d+):(\d+):\s*error:\s*(.+)'
    match = re.search(pattern, error_line)
    
    if match:
        file_path = match.group(1)
        line_number = int(match.group(2))
        column_number = int(match.group(3))
        error_message = match.group(4)
        
        # Tìm thêm context từ các dòng tiếp theo
        context = []
        for j in range(line_index + 1, min(line_index + 3, len(all_lines))):
            if all_lines[j].strip() and not all_lines[j].strip().startswith('/'):
                context.append(all_lines[j].strip())
        
        return {
            'type': 'error',
            'file': os.path.basename(file_path),
            'line': line_number,
            'column': column_number,
            'message': error_message,
            'context': context
        }
    
    # Fallback cho các format lỗi khác
    if 'error:' in error_line.lower():
        return {
            'type': 'error',
            'message': error_line.strip(),
            'raw': True
        }
    
    return None

def extract_warning_info(warning_line, all_lines, line_index):
    """
    Trích xuất thông tin chi tiết về warning
    """
    import re
    
    # Pattern để tìm file:line:column: warning
    pattern = r'(.+?):(\d+):(\d+):\s*warning:\s*(.+)'
    match = re.search(pattern, warning_line)
    
    if match:
        file_path = match.group(1)
        line_number = int(match.group(2))
        column_number = int(match.group(3))
        warning_message = match.group(4)
        
        return {
            'type': 'warning',
            'file': os.path.basename(file_path),
            'line': line_number,
            'column': column_number,
            'message': warning_message
        }
    
    # Fallback cho các format warning khác
    if 'warning:' in warning_line.lower():
        return {
            'type': 'warning',
            'message': warning_line.strip(),
            'raw': True
        }
    
    return None
# =================================================================
# ▲▲▲ KẾT THÚC ĐOẠN CODE API BIÊN DỊCH MỚI ▲▲▲
# ================== ADMIN ROUTES ==================
#thêm route flask cho quản lý thiết bị và tag1
@app.route("/admin/devices")
@require_auth('admin')
def admin_devices():
    return render_template("admin/devices.html")
@app.route("/admin")
@require_auth('admin')
def admin_dashboard():
    db = get_db_connection()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT status, COUNT(*) as count FROM users GROUP BY status")
    stats = {row['status']: row['count'] for row in cur.fetchall()}
    cur.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 50")
    logs = cur.fetchall()
    cur.close(), db.close()
    return render_template("admin.html", 
                           total_users=sum(stats.values()),
                           active_users=stats.get('active', 0),
                           blocked_users=stats.get('blocked', 0),
                           pending_users=stats.get('pending', 0),
                           logs=logs)  

@app.route("/admin/manage")
@require_auth('admin')
def admin_manage():
    db = get_db_connection()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id, username, email, role, status, created_at FROM users ORDER BY created_at DESC")
    users = cur.fetchall()
    cur.close(), db.close()
    return render_template("manage.html", users=users)
    
@app.route("/admin/api/logs")
@require_auth('admin')
def admin_api_logs():
    db = get_db_connection()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT username, action, ip_address, timestamp FROM logs ORDER BY timestamp DESC LIMIT 50")
    logs = cur.fetchall()
    cur.close(), db.close()
    for log in logs: log['timestamp'] = log['timestamp'].isoformat()
    return jsonify({'success': True, 'logs': logs})

@app.route("/admin/add_user", methods=["POST"])
@require_auth('admin')
def add_user():
    username, password, email, role = request.form.get("username", "").strip(), request.form.get("password", "").strip(), request.form.get("email", "").strip() or None, request.form.get("role", "user")
    is_strong, message = validate_password_strength(password)
    if not is_strong:
        flash(message, "error")
        return redirect(url_for("admin_manage"))
    db = get_db_connection()
    cur = db.cursor()
    cur.execute("INSERT INTO users(username, password, email, role, status) VALUES(%s, %s, %s, %s, 'active')",
                (username, generate_password_hash(password), email, role))
    db.commit()
    cur.close(), db.close()
    flash(f"Đã thêm user '{username}' thành công!", "success")
    return redirect(url_for("admin_manage"))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@require_auth('admin')
def delete_user(user_id):
    db = get_db_connection()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT username FROM users WHERE id=%s AND role='user'", (user_id,))
    user = cur.fetchone()
    if user:
        target_username = user['username']
        # (Cleanup logic for Docker, etc.)
        cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
        db.commit()
        log_action(session["username"], f"Deleted user: {target_username}")
        flash(f"Đã xóa user {target_username}", "info")
    else:
        flash("User không tồn tại!", "error")
    cur.close(), db.close()
    return redirect(url_for("admin_manage"))

@app.route("/admin/change_user_status/<action>/<username>", methods=["POST"])
@require_auth('admin')
def change_user_status(action, username):
    db = get_db_connection()
    cur = db.cursor()
    actions = {
        "approve": ("active", f"Approved: {username}", f"Đã duyệt user {username}", "success"),
        "block": ("blocked", f"Blocked: {username}", f"Đã khóa user {username}", "warning"),
        "unblock": ("active", f"Unblocked: {username}", f"Đã mở khóa user {username}", "success"),
    }
    if action in actions:
        new_status, log_msg, flash_msg, flash_cat = actions[action]
        cur.execute("UPDATE users SET status=%s WHERE username=%s", (new_status, username))
        db.commit()
        log_action(session["username"], log_msg)
        flash(flash_msg, flash_cat)
    else:
        flash("Hành động không hợp lệ!", "error")
    cur.close(), db.close()
    return redirect(url_for("admin_manage"))

# ================== SOCKET.IO FOR TERMINAL ==================
@socketio.on('connect', namespace='/terminal')
def terminal_connect():
    if 'username' not in session:
        return False

    username = session['username']
    sid = request.sid 
    
    try:
        client = get_ssh_client(username)
        chan = client.invoke_shell(term='xterm-color')
        
        # Lưu client và channel vào session của SocketIO cho kết nối này
        session['ssh_client'] = client
        session['ssh_chan'] = chan
        log_action(username, "Terminal: User connected")

        def forward_output():
            """Gửi output từ container đến trình duyệt."""
            try:
                while chan.active:
                    if chan.recv_ready():
                        data = chan.recv(1024)
                        if not data:
                            break
                        socketio.emit('output', data.decode('utf-8', errors='ignore'), 
                                    namespace='/terminal', room=sid) 
                    else:
                        socketio.sleep(0.1)
            except Exception as e:
                app.logger.warning(f"Terminal forward_output thread for {username} ended: {e}")
                socketio.emit('output', f'\r\n\x1b[31mConnection lost: {e}\x1b[0m\r\n', 
                            namespace='/terminal', room=sid)
        
        socketio.start_background_task(target=forward_output)
        return True
        
    except Exception as e:
        app.logger.error(f"SOCKET CONNECT ERROR for {username}: {e}")
        # ✅ SỬA LỖI: Thêm room=sid để gửi lỗi về đúng client
        emit('output', f'\r\n\x1b[31mError connecting to terminal: {e}\x1b[0m\r\n', room=sid)
        return False

@socketio.on('input', namespace='/terminal')
def terminal_input(data):
    if 'ssh_chan' in session and session['ssh_chan'].active:
        try:
            # Kiểm tra data có hợp lệ không
            if isinstance(data, str):
                session['ssh_chan'].send(data)
            else:
                app.logger.warning(f"Invalid input data type: {type(data)}")
        except Exception as e:
            app.logger.error(f"SOCKET INPUT ERROR: {e}")
            # Thông báo lỗi đến client
            emit('output', f'\r\n\x1b[31mInput error: {e}\x1b[0m\r\n')

@socketio.on('disconnect', namespace='/terminal')
def terminal_disconnect():
    username = session.get("username", "unknown")
    
    # Đóng SSH channel an toàn
    if 'ssh_chan' in session:
        try:
            if session['ssh_chan'].active:
                session['ssh_chan'].close()
        except Exception as e:
            app.logger.warning(f"Error closing SSH channel for {username}: {e}")
        finally:
            session.pop('ssh_chan', None)
    
    # Đóng SSH client an toàn  
    if 'ssh_client' in session:
        try:
            session['ssh_client'].close()
        except Exception as e:
            app.logger.warning(f"Error closing SSH client for {username}: {e}")
        finally:
            session.pop('ssh_client', None)
            
    log_action(username, "Terminal: User disconnected")

# ================== MAIN EXECUTION ==================
if __name__ == "__main__":
    init_db()
    app.logger.info("Enhanced Flask App with Security Features Started")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, allow_unsafe_werkzeug=True)

