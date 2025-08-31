# file: backend/utils.py

import os
import re
import time
import json
import base64
import random
import socket
import secrets
import logging
import smtplib
import subprocess
from datetime import datetime
from functools import wraps
from collections import defaultdict

from flask import request, session, redirect, url_for, flash, current_app, jsonify
import mysql.connector
import paramiko
from werkzeug.security import generate_password_hash, check_password_hash
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ================== GLOBAL CONFIG ==================
SECURITY_CONFIG = {
    "MAX_LOGIN_ATTEMPTS": 5,
    "LOCKOUT_DURATION": 300,     # 5 phút
    "OTP_EXPIRY": 300,           # 5 phút
    "SESSION_TIMEOUT": 1800,     # 30 phút
    "CSRF_EXPIRY": 3600,         # 1 giờ
    "PASSWORD_MIN_LENGTH": 8,
    "USERNAME_MIN_LENGTH": 3,
    "RATE_LIMIT_PER_MINUTE": 60,
}

EMAIL_CONFIG = {
    "SMTP_SERVER": "smtp.gmail.com",
    "SMTP_PORT": 587,
    "SMTP_USERNAME": "haquangchuong28@gmail.com",
    "SMTP_PASSWORD": "wddxglvwvpyznppn",  # ⚠️ Nên chuyển vào ENV thay vì hardcode
    "FROM_EMAIL": "haquangchuong28@gmail.com",
}

# ================== IN-MEMORY STORAGE ==================
login_attempts = defaultdict(lambda: {"count": 0, "locked_until": None})
otp_storage = {}
csrf_tokens = {}
rate_limiter = defaultdict(lambda: {"requests": [], "blocked_until": None})

# ================== LOGGER ==================
logger = logging.getLogger(__name__)


# ================== DATABASE HELPERS ==================
def get_db_connection():
    """Tạo kết nối đến MySQL từ ENV (DB_HOST, DB_USER, DB_PASSWORD, DB_NAME)."""
    try:
        return mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME"),
            autocommit=True,
        )
    except Exception as e:
        logger.error(f"[DB] Connection error: {e}")
        return None


def log_action(username, action, success=True, details=None):
    """Lưu log người dùng vào bảng logs."""
    db = get_db_connection()
    if not db:
        return
    try:
        with db.cursor() as cur:
            ip_address = request.remote_addr if request else "N/A"
            user_agent = request.user_agent.string if request and request.user_agent else "N/A"
            cur.execute(
                """
                INSERT INTO logs (username, action, ip_address, user_agent, success, details)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    username,
                    action,
                    ip_address,
                    user_agent,
                    success,
                    json.dumps(details) if details else None,
                ),
            )
            db.commit()
    except Exception as e:
        logger.error(f"[DB] Log insert error: {e}")
    finally:
        if db and db.is_connected():
            db.close()


# ================== DOCKER & SSH HELPERS ==================
def find_free_port(start=2200, end=2299):
    """Tìm port còn trống để ánh xạ cho container SSH."""
    for _ in range(100):
        port = random.randint(start, end)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    return None


def docker_status(cname):
    """Kiểm tra trạng thái container (running / exited / etc.)."""
    try:
        r = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Status}}", cname],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def ensure_user_container(username):
    """Đảm bảo mỗi user có container dev riêng."""
    cname = f"{username}-dev"
    image = "my-dev-env:v2"
    db = get_db_connection()
    if not db:
        raise Exception("Không thể kết nối CSDL để kiểm tra container.")

    try:
        with db.cursor(dictionary=True) as cur:
            cur.execute("SELECT ssh_port FROM users WHERE username=%s", (username,))
            user_data = cur.fetchone()
            ssh_port = user_data.get("ssh_port") if user_data else None
            status = docker_status(cname)

            if not status or status != "running":
                logger.info(f"Container '{cname}' not running (status: {status}). Starting...")

                if not ssh_port:
                    ssh_port = find_free_port()
                    if not ssh_port:
                        raise Exception("Không còn port trống.")
                    cur.execute("UPDATE users SET ssh_port=%s WHERE username=%s", (ssh_port, username))
                    db.commit()

                if not status:  # container chưa tồn tại
                    host_user_dir = f"/home/chuongdev/QUAN_LY_USER/{username}"
                    os.makedirs(host_user_dir, exist_ok=True)
                    subprocess.run(
                        [
                            "docker", "run", "-d", "--name", cname, "--restart", "always",
                            "-p", f"{ssh_port}:22",
                            "-e", f"USERNAME={username}",
                            "-e", "PASSWORD=password123",
                            "-v", f"{host_user_dir}:/home/{username}",
                            image,
                        ],
                        check=True,
                        timeout=30,
                    )
                    logger.info(f"Started new container '{cname}' on port {ssh_port}.")
                else:  # container tồn tại nhưng stop
                    subprocess.run(["docker", "start", cname], check=True, timeout=10)
                    logger.info(f"Restarted container '{cname}'.")
    finally:
        if db and db.is_connected():
            db.close()


def get_ssh_client(username):
    """Tạo kết nối SSH đến container user."""
    db = get_db_connection()
    if not db:
        raise Exception("Không thể kết nối CSDL để lấy thông tin SSH.")
    try:
        with db.cursor(dictionary=True) as cur:
            cur.execute("SELECT ssh_port FROM users WHERE username=%s", (username,))
            user = cur.fetchone()
    finally:
        if db and db.is_connected():
            db.close()

    if not user or not user["ssh_port"]:
        raise Exception("Chưa cấu hình SSH port.")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_host = os.getenv("DOCKER_HOST_IP", "127.0.0.1")
    client.connect(
        ssh_host,
        port=user["ssh_port"],
        username=username,
        password="password123",
        timeout=10,
    )
    return client


# ================== DECORATORS ==================
def require_auth(role=None):
    """Decorator bắt buộc đăng nhập, có thể yêu cầu role cụ thể."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "username" not in session:
                flash("Vui lòng đăng nhập để tiếp tục.", "warning")
                return redirect(url_for("login_page"))

            if "last_activity" in session and time.time() - session["last_activity"] > SECURITY_CONFIG["SESSION_TIMEOUT"]:
                session.clear()
                flash("Phiên đăng nhập đã hết hạn.", "warning")
                return redirect(url_for("login_page"))

            session["last_activity"] = time.time()

            if role and session.get("role") != role:
                flash("Bạn không có quyền truy cập trang này.", "error")
                return redirect(url_for("index"))

            return f(*args, **kwargs)
        return wrapper
    return decorator


# ================== SECURITY UTILITIES ==================
def generate_csrf_token():
    """Tạo CSRF token có thời hạn."""
    token = secrets.token_urlsafe(32)
    csrf_tokens[token] = {"created_at": time.time(), "user_ip": request.remote_addr if request else None}
    # cleanup token cũ
    expired = [t for t, data in csrf_tokens.items() if time.time() - data["created_at"] > SECURITY_CONFIG["CSRF_EXPIRY"]]
    for t in expired:
        csrf_tokens.pop(t, None)
    return token


def validate_csrf_token(token):
    """Xác thực CSRF token."""
    data = csrf_tokens.get(token)
    if not data:
        return False
    if time.time() - data["created_at"] > SECURITY_CONFIG["CSRF_EXPIRY"]:
        csrf_tokens.pop(token, None)
        return False
    return True


def generate_captcha():
    """Sinh captcha ngẫu nhiên."""
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    captcha = "".join(random.choices(chars, k=6))
    token = base64.b64encode(f"{captcha}:{time.time()}".encode()).decode()
    return captcha, token


def validate_captcha(user_input, token):
    """Xác thực captcha bằng token."""
    try:
        decoded = base64.b64decode(token.encode()).decode()
        captcha, timestamp = decoded.split(":", 1)
        if time.time() - float(timestamp) > 300:
            return False
        return user_input.upper() == captcha.upper()
    except Exception:
        return False


def generate_otp():
    """Sinh mã OTP 6 số."""
    return "".join(random.choices("0123456789", k=6))


def send_otp_email(email, otp, username):
    """Gửi OTP qua email."""
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_CONFIG["FROM_EMAIL"]
        msg["To"] = email
        msg["Subject"] = "EPU Tech - Mã xác thực"

        body = f"Xin chào {username},\n\nMã xác thực của bạn là: {otp}\nMã này có hiệu lực trong 5 phút."
        msg.attach(MIMEText(body, "plain", "utf-8"))

        server = smtplib.SMTP(EMAIL_CONFIG["SMTP_SERVER"], EMAIL_CONFIG["SMTP_PORT"])
        server.starttls()
        server.login(EMAIL_CONFIG["SMTP_USERNAME"], EMAIL_CONFIG["SMTP_PASSWORD"])
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        logger.error(f"[EMAIL] Send error: {e}")
        return False


def validate_password_strength(password):
    """Kiểm tra độ mạnh mật khẩu."""
    if len(password) < SECURITY_CONFIG["PASSWORD_MIN_LENGTH"]:
        return False, "Mật khẩu phải dài ít nhất 8 ký tự"
    if not re.search("[a-z]", password):
        return False, "Mật khẩu phải chứa chữ thường"
    if not re.search("[A-Z]", password):
        return False, "Mật khẩu phải chứa chữ HOA"
    if not re.search("[0-9]", password):
        return False, "Mật khẩu phải chứa số"
    return True, ""
