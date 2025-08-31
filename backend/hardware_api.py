# backend/hardware_api.py

from flask import Blueprint, request, jsonify, session
from .utils import get_db_connection, require_auth # Giả sử bạn có file utils.py chứa các hàm này
from datetime import datetime, timedelta

# Tạo một Blueprint để nhóm các route phần cứng lại
hardware_bp = Blueprint('hardware_api', __name__, url_prefix='/api/hardware')

# =================================================================
# ===                  API CHO SINH VIÊN                        ===
# =================================================================
@hardware_bp.route("/tags/use", methods=["POST"])
@require_auth('user') # Dùng decorator đã có để bảo vệ
def use_tag():
    username = session['username'] # Lấy username từ session, an toàn hơn
    tag_name = request.json.get('tag_name')

    if not tag_name:
        return jsonify(error="Thiếu tag_name"), 400

    db = get_db_connection()
    cur = db.cursor(dictionary=True)

    # 1. Kiểm tra quyền được cấp
    cur.execute(
        "SELECT * FROM assignments WHERE user_id = %s AND tag_name = %s AND is_active = TRUE AND expires_at > NOW()",
        (username, tag_name)
    )
    assignment = cur.fetchone()
    if not assignment:
        cur.close()
        db.close()
        return jsonify(error=f"Bạn không có quyền hoặc quyền sử dụng TAG '{tag_name}' đã hết hạn."), 403

    # 2. Kiểm tra trạng thái thiết bị
    cur.execute("SELECT * FROM devices WHERE tag_name = %s", (tag_name,))
    device = cur.fetchone()
    if not device:
        cur.close()
        db.close()
        return jsonify(error=f"Không tìm thấy thiết bị nào có TAG '{tag_name}'."), 404
    if device.get('in_use_by'):
        cur.close()
        db.close()
        return jsonify(error=f"Thiết bị '{tag_name}' đang được sử dụng bởi '{device['in_use_by']}'."), 409

    # 3. Cấp quyền (khóa thiết bị)
    cur.execute("UPDATE devices SET in_use_by = %s WHERE tag_name = %s", (username, tag_name))
    db.commit()
    cur.close()
    db.close()
    
    # Ghi log hành động (nên có)
    # log_action(username, f"Bắt đầu sử dụng thiết bị {tag_name}")
    
    return jsonify(message=f"Thành công! Bạn đang sử dụng thiết bị '{tag_name}'."), 200

# Bạn sẽ tiếp tục viết các hàm khác như release_tag, flash, read-serial theo logic tương tự...

# =================================================================
# ===                    API CHO ADMIN                          ===
# =================================================================
@hardware_bp.route("/admin/assignments", methods=["POST"])
@require_auth('admin')
def create_assignment():
    data = request.json
    user_id = data.get('user_id')
    tag_name = data.get('tag_name')
    duration_hours = data.get('duration_hours', 24) # Mặc định 24 giờ

    if not all([user_id, tag_name]):
        return jsonify(error="Thiếu user_id hoặc tag_name"), 400

    expires_at = datetime.now() + timedelta(hours=int(duration_hours))
    
    db = get_db_connection()
    cur = db.cursor()
    
    try:
        cur.execute(
            "INSERT INTO assignments (user_id, tag_name, expires_at) VALUES (%s, %s, %s)",
            (user_id, tag_name, expires_at)
        )
        db.commit()
        # log_action(session['username'], f"Cấp quyền {tag_name} cho {user_id}")
        return jsonify(message="Cấp quyền thành công"), 201
    except Exception as e:
        db.rollback()
        return jsonify(error=f"Lỗi khi cấp quyền: {e}"), 500
    finally:
        cur.close()
        db.close()

