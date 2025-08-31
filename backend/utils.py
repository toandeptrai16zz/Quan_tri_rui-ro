# file: backend/utils.py
import os
import secrets
import time
import random
import socket
import subprocess
import json
from functools import wraps

from flask import request, session, flash, redirect, url_for, current_app
import mysql.connector
import paramiko

# ================== DATABASE & DOCKER HELPERS ==================
def get_db_connection():
    try:
        db_host = os.environ.get('DB_HOST')
        db_user = os.environ.get('DB_USER')
        db_password = os.environ.get('DB_PASSWORD')
        db_name = os.environ.get('DB_NAME')
        return mysql.connector.connect(
            host=db_host, user=db_user, password=db_password,
            database=db_name, autocommit=True
        )
    except Exception as e:
        app.logger.error(f"DATABASE CONNECTION ERROR: {e}")
        return None

def log_action(username, action, success=True, details=None):
    try:
        db = get_db_connection()
        if not db: return
        cur = db.cursor()
        # Đảm bảo request context tồn tại trước khi truy cập
        ip_address = request.remote_addr if request else 'N/A'
        user_agent = request.user_agent.string if request and request.user_agent else 'N/A'
        cur.execute("INSERT INTO logs (username, action, ip_address, user_agent, success, details) VALUES (%s, %s, %s, %s, %s, %s)",
                      (username, action, ip_address, user_agent, success, json.dumps(details) if details else None))
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
            # Lấy đường dẫn thư mục cha từ biến môi trường
            base_workspace_dir = os.environ.get('USER_WORKSPACE_DIR', '/app/workspaces')
            
            # Tạo đường dẫn đầy đủ cho thư mục của người dùng
            host_user_dir = os.path.join(base_workspace_dir, username)
            os.makedirs(host_user_dir, exist_ok=True)
            
            # Lệnh docker run sẽ sử dụng biến host_user_dir này
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