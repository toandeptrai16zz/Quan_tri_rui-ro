# backend/hardware_api.py (Phiên bản tối ưu)
import os
from flask import Blueprint, request, jsonify, session
from datetime import datetime, timedelta
import logging

# Import từ app module chính
from app import get_db_connection, require_auth, log_action

# Tạo Blueprint với url_prefix
hardware_bp = Blueprint('hardware_api', __name__, url_prefix='/api/hardware')

# Cấu hình logging
logger = logging.getLogger(__name__)

# =================================================================
# ===                  HELPER FUNCTIONS                         ===
# =================================================================
def validate_json_request(required_fields):
    """Validate JSON request and check required fields"""
    data = request.get_json()
    if not data:
        return None, jsonify(ok=False, error="Request body phải là JSON"), 400
    
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return None, jsonify(ok=False, error=f"Thiếu các trường bắt buộc: {', '.join(missing_fields)}"), 400
    
    return data, None, None

def safe_db_operation(operation_func, *args, **kwargs):
    """Safely execute database operations with proper error handling"""
    db = None
    cur = None
    try:
        db = get_db_connection()
        if not db:
            return jsonify(ok=False, error="Không thể kết nối đến database"), 500
        
        cur = db.cursor(dictionary=True)
        return operation_func(db, cur, *args, **kwargs)
        
    except Exception as e:
        if db:
            db.rollback()
        logger.error(f"Database operation failed: {str(e)}")
        return jsonify(ok=False, error=f"Lỗi hệ thống: {str(e)}"), 500
        
    finally:
        if cur:
            cur.close()
        if db and db.is_connected():
            db.close()

# =================================================================
# ===                  API CHO SINH VIÊN                        ===
# =================================================================
@hardware_bp.route("/tags/use", methods=["POST"])
@require_auth('user')
def use_tag():
    """API để sinh viên sử dụng thiết bị thông qua TAG"""
    
    # Validate request
    data, error_response, status_code = validate_json_request(['tag_name'])
    if error_response:
        return error_response, status_code
    
    # Lấy username từ session (sau khi đã authenticated)
    username = session.get('username')
    tag_name = data.get('tag_name')
    
    def _use_tag_operation(db, cur):
        # 1. Kiểm tra quyền được cấp
        cur.execute("""
            SELECT * FROM assignments 
            WHERE user_id = %s AND tag_name = %s AND is_active = TRUE AND expires_at > NOW()
        """, (username, tag_name))
        
        assignment = cur.fetchone()
        if not assignment:
            log_action(username, f"Thử sử dụng thiết bị {tag_name} nhưng không có quyền", success=False)
            return jsonify(ok=False, error=f"Bạn không có quyền hoặc quyền sử dụng TAG '{tag_name}' đã hết hạn."), 403

        # 2. Kiểm tra trạng thái thiết bị
        cur.execute("SELECT tag_name, in_use_by, device_name FROM devices WHERE tag_name = %s", (tag_name,))
        device = cur.fetchone()
        
        if not device:
            log_action(username, f"Thử sử dụng thiết bị {tag_name} nhưng không tìm thấy", success=False)
            return jsonify(ok=False, error=f"Không tìm thấy thiết bị nào có TAG '{tag_name}'."), 404
            
        if device.get('in_use_by'):
            log_action(username, f"Thử sử dụng thiết bị {tag_name} nhưng đang được sử dụng bởi {device['in_use_by']}", success=False)
            return jsonify(ok=False, error=f"Thiết bị '{device.get('device_name', tag_name)}' đang được sử dụng bởi '{device['in_use_by']}'."), 409

        # 3. Cấp quyền (khóa thiết bị)
        cur.execute("UPDATE devices SET in_use_by = %s, used_at = NOW() WHERE tag_name = %s", (username, tag_name))
        db.commit()
        
        log_action(username, f"Bắt đầu sử dụng thiết bị {tag_name}", success=True)
        
        return jsonify(
            ok=True, 
            message=f"Thành công! Bạn đang sử dụng thiết bị '{device.get('device_name', tag_name)}'.",
            device_info={
                'tag_name': tag_name,
                'device_name': device.get('device_name'),
                'started_at': datetime.now().isoformat()
            }
        ), 200
    
    return safe_db_operation(_use_tag_operation)

@hardware_bp.route("/tags/release", methods=["POST"])
@require_auth('user')
def release_tag():
    """API để sinh viên giải phóng thiết bị"""
    
    data, error_response, status_code = validate_json_request(['tag_name'])
    if error_response:
        return error_response, status_code
    
    username = session.get('username')
    tag_name = data.get('tag_name')
    
    def _release_tag_operation(db, cur):
        # Kiểm tra thiết bị có đang được sử dụng bởi user này không
        cur.execute("SELECT in_use_by, device_name FROM devices WHERE tag_name = %s", (tag_name,))
        device = cur.fetchone()
        
        if not device:
            return jsonify(ok=False, error=f"Không tìm thấy thiết bị có TAG '{tag_name}'."), 404
            
        if device.get('in_use_by') != username:
            return jsonify(ok=False, error="Bạn không đang sử dụng thiết bị này."), 403
        
        # Giải phóng thiết bị
        cur.execute("UPDATE devices SET in_use_by = NULL WHERE tag_name = %s", (tag_name,))
        db.commit()
        
        log_action(username, f"Giải phóng thiết bị {tag_name}", success=True)
        
        return jsonify(
            ok=True, 
            message=f"Đã giải phóng thiết bị '{device.get('device_name', tag_name)}'."
        ), 200
    
    return safe_db_operation(_release_tag_operation)

@hardware_bp.route("/tags/my-devices", methods=["GET"])
@require_auth('user')
def get_my_devices():
    """Lấy danh sách thiết bị user đang sử dụng và có quyền sử dụng"""
    
    username = session.get('username')
    
    def _get_my_devices_operation(db, cur):
        # Thiết bị đang sử dụng
        cur.execute("""
            SELECT d.tag_name, d.device_name, d.used_at
            FROM devices d 
            WHERE d.in_use_by = %s
        """, (username,))
        using_devices = cur.fetchall()
        
        # Thiết bị có quyền sử dụng (chưa hết hạn)
        cur.execute("""
            SELECT a.tag_name, d.device_name, a.expires_at, d.in_use_by
            FROM assignments a
            LEFT JOIN devices d ON a.tag_name = d.tag_name
            WHERE a.user_id = %s AND a.is_active = TRUE AND a.expires_at > NOW()
            ORDER BY a.expires_at ASC
        """, (username,))
        available_devices = cur.fetchall()
        
        return jsonify(
            ok=True,
            data={
                'using_devices': using_devices or [],
                'available_devices': available_devices or []
            }
        ), 200
    
    return safe_db_operation(_get_my_devices_operation)

# =================================================================
# ===                    API CHO ADMIN                          ===
# =================================================================
@hardware_bp.route("/admin/assignments", methods=["POST"])
@require_auth('admin')
def create_assignment():
    """Admin cấp quyền sử dụng thiết bị cho sinh viên"""
    
    data, error_response, status_code = validate_json_request(['user_id', 'tag_name'])
    if error_response:
        return error_response, status_code
    
    user_id = data.get('user_id')
    tag_name = data.get('tag_name')
    duration_hours = data.get('duration_hours', 24)  # Mặc định 24 giờ
    
    # Validate duration
    try:
        duration_hours = int(duration_hours)
        if duration_hours <= 0 or duration_hours > 168:  # Tối đa 1 tuần
            return jsonify(ok=False, error="Thời gian cấp quyền phải từ 1-168 giờ"), 400
    except (ValueError, TypeError):
        return jsonify(ok=False, error="duration_hours phải là số nguyên"), 400
    
    admin_username = session.get('username')
    
    def _create_assignment_operation(db, cur):
        # Kiểm tra user tồn tại
        cur.execute("SELECT username FROM users WHERE username = %s", (user_id,))
        if not cur.fetchone():
            return jsonify(ok=False, error=f"Không tìm thấy user '{user_id}'"), 404
        
        # Kiểm tra thiết bị tồn tại
        cur.execute("SELECT tag_name, device_name FROM devices WHERE tag_name = %s", (tag_name,))
        device = cur.fetchone()
        if not device:
            return jsonify(ok=False, error=f"Không tìm thấy thiết bị có TAG '{tag_name}'"), 404
        
        expires_at = datetime.now() + timedelta(hours=duration_hours)
        
        # Tạo assignment mới (hoặc cập nhật nếu đã tồn tại)
        cur.execute("""
            INSERT INTO assignments (user_id, tag_name, expires_at, created_by, is_active)
            VALUES (%s, %s, %s, %s, TRUE)
            ON DUPLICATE KEY UPDATE 
                expires_at = VALUES(expires_at),
                created_by = VALUES(created_by),
                is_active = TRUE,
                updated_at = NOW()
        """, (user_id, tag_name, expires_at, admin_username))
        
        db.commit()
        
        log_action(admin_username, f"Cấp quyền {tag_name} cho {user_id} (hết hạn: {expires_at})", success=True)
        
        return jsonify(
            ok=True,
            message=f"Đã cấp quyền thiết bị '{device.get('device_name', tag_name)}' cho user '{user_id}'",
            assignment_info={
                'user_id': user_id,
                'tag_name': tag_name,
                'device_name': device.get('device_name'),
                'expires_at': expires_at.isoformat(),
                'duration_hours': duration_hours
            }
        ), 201
    
    return safe_db_operation(_create_assignment_operation)

@hardware_bp.route("/admin/assignments", methods=["GET"])
@require_auth('admin')
def list_assignments():
    """Admin xem danh sách tất cả assignments"""
    
    # Query parameters
    active_only = request.args.get('active_only', 'true').lower() == 'true'
    user_filter = request.args.get('user_id')
    
    def _list_assignments_operation(db, cur):
        base_query = """
            SELECT a.*, d.device_name, u.full_name
            FROM assignments a
            LEFT JOIN devices d ON a.tag_name = d.tag_name
            LEFT JOIN users u ON a.user_id = u.username
        """
        
        conditions = []
        params = []
        
        if active_only:
            conditions.append("a.is_active = TRUE AND a.expires_at > NOW()")
        
        if user_filter:
            conditions.append("a.user_id = %s")
            params.append(user_filter)
        
        if conditions:
            base_query += " WHERE " + " AND ".join(conditions)
        
        base_query += " ORDER BY a.created_at DESC"
        
        cur.execute(base_query, params)
        assignments = cur.fetchall()
        
        return jsonify(
            ok=True,
            data=assignments or [],
            total=len(assignments) if assignments else 0
        ), 200
    
    return safe_db_operation(_list_assignments_operation)

@hardware_bp.route("/admin/assignments/<int:assignment_id>", methods=["DELETE"])
@require_auth('admin')
def revoke_assignment(assignment_id):
    """Admin thu hồi quyền sử dụng"""
    
    admin_username = session.get('username')
    
    def _revoke_assignment_operation(db, cur):
        # Kiểm tra assignment tồn tại
        cur.execute("SELECT user_id, tag_name FROM assignments WHERE id = %s", (assignment_id,))
        assignment = cur.fetchone()
        
        if not assignment:
            return jsonify(ok=False, error="Không tìm thấy assignment"), 404
        
        # Vô hiệu hóa assignment
        cur.execute("UPDATE assignments SET is_active = FALSE WHERE id = %s", (assignment_id,))
        
        # Nếu user đang sử dụng thiết bị, giải phóng luôn
        cur.execute(
            "UPDATE devices SET in_use_by = NULL WHERE tag_name = %s AND in_use_by = %s",
            (assignment['tag_name'], assignment['user_id'])
        )
        
        db.commit()
        
        log_action(admin_username, f"Thu hồi quyền {assignment['tag_name']} của {assignment['user_id']}", success=True)
        
        return jsonify(
            ok=True,
            message=f"Đã thu hồi quyền sử dụng {assignment['tag_name']} của {assignment['user_id']}"
        ), 200
    
    return safe_db_operation(_revoke_assignment_operation)

@hardware_bp.route("/admin/devices", methods=["GET"])
@require_auth('admin')
def list_devices():
    """Admin xem trạng thái tất cả thiết bị"""
    
    def _list_devices_operation(db, cur):
        cur.execute("""
            SELECT d.*, u.full_name as user_full_name
            FROM devices d
            LEFT JOIN users u ON d.in_use_by = u.username
            ORDER BY d.device_name
        """)
        devices = cur.fetchall()
        
        return jsonify(
            ok=True,
            data=devices or []
        ), 200
    
    return safe_db_operation(_list_devices_operation)

@hardware_bp.route("/admin/devices/<tag_name>/force-release", methods=["POST"])
@require_auth('admin')
def force_release_device(tag_name):
    """Admin cưỡng chế giải phóng thiết bị"""
    
    admin_username = session.get('username')
    
    def _force_release_operation(db, cur):
        # Kiểm tra thiết bị tồn tại và đang được sử dụng
        cur.execute("SELECT in_use_by, device_name FROM devices WHERE tag_name = %s", (tag_name,))
        device = cur.fetchone()
        
        if not device:
            return jsonify(ok=False, error=f"Không tìm thấy thiết bị có TAG '{tag_name}'"), 404
        
        if not device.get('in_use_by'):
            return jsonify(ok=False, error="Thiết bị không đang được sử dụng"), 400
        
        previous_user = device['in_use_by']
        
        # Giải phóng thiết bị
        cur.execute("UPDATE devices SET in_use_by = NULL WHERE tag_name = %s", (tag_name,))
        db.commit()
        
        log_action(admin_username, f"Cưỡng chế giải phóng thiết bị {tag_name} từ user {previous_user}", success=True)
        log_action(previous_user, f"Thiết bị {tag_name} bị admin giải phóng cưỡng chế", success=False)
        
        return jsonify(
            ok=True,
            message=f"Đã cưỡng chế giải phóng thiết bị '{device.get('device_name', tag_name)}' từ user '{previous_user}'"
        ), 200
    
    return safe_db_operation(_force_release_operation)

# =================================================================
# ===                  API HỆ THỐNG                             ===
# =================================================================
@hardware_bp.route("/admin/auto-discover", methods=["POST"])
def auto_discover_device():
    """
    API tự động phát hiện và thêm thiết bị mới vào hệ thống
    Được gọi từ hệ thống nội bộ, không cần xác thực session
    Có thể thêm secret key để bảo mật nếu cần
    """
    
    # Kiểm tra secret key nếu có (tùy chọn bảo mật)
    secret_key = request.headers.get('X-Internal-Secret')
    expected_secret = os.environ.get('INTERNAL_API_SECRET', 'default-secret-key') 


    
    if secret_key != expected_secret:
        return jsonify(ok=False, error="Không có quyền truy cập"), 403

    
    # Validate request
    data, error_response, status_code = validate_json_request(['port', 'type'])
    if error_response:
        return error_response, status_code
    
    port = data.get('port')           # ví dụ: "/dev/ttyUSB0"
    device_type = data.get('type')    # ví dụ: "ESP8266"
    device_name = data.get('device_name')  # Tên thiết bị tùy chọn
    
    def _auto_discover_operation(db, cur):
        # 1. Kiểm tra xem port này đã tồn tại chưa
        cur.execute("SELECT id, tag_name, device_name FROM devices WHERE port = %s", (port,))
        existing_device = cur.fetchone()
        
        if existing_device:
            log_action("system", f"Auto-discover: Thiết bị tại cổng {port} đã tồn tại với tag {existing_device['tag_name']}", success=True)
            return jsonify(
                ok=True, 
                message=f"Thiết bị tại cổng {port} đã tồn tại.",
                device_info={
                    'tag_name': existing_device['tag_name'],
                    'device_name': existing_device.get('device_name'),
                    'port': port,
                    'status': 'already_exists'
                }
            ), 200
        
        # 2. Tìm tag_name tiếp theo chưa được sử dụng
        cur.execute("SELECT tag_name FROM devices WHERE type = %s ORDER BY tag_name", (device_type,))
        existing_tags = {row['tag_name'] for row in cur.fetchall()}
        
        i = 1
        while True:
            new_tag_name = f"{device_type}_{i}"
            if new_tag_name not in existing_tags:
                break
            i += 1
        
        # 3. Tạo device_name mặc định nếu không có
        if not device_name:
            device_name = f"{device_type} Device #{i}"
        
        # 4. Thêm thiết bị mới vào CSDL
        cur.execute("""
            INSERT INTO devices (port, type, tag_name, device_name, created_at) 
            VALUES (%s, %s, %s, %s, NOW())
        """, (port, device_type, new_tag_name, device_name))
        
        db.commit()
        
        log_action("system", f"Auto-discovered new device: {new_tag_name} ({device_name}) at {port}", success=True)
        
        return jsonify(
            ok=True, 
            message=f"Đã tự động thêm thiết bị mới: {new_tag_name}",
            device_info={
                'tag_name': new_tag_name,
                'device_name': device_name,
                'type': device_type,
                'port': port,
                'status': 'newly_created'
            }
        ), 201
    
    return safe_db_operation(_auto_discover_operation)

@hardware_bp.route("/admin/devices/scan", methods=["POST"])
@require_auth('admin')
def manual_device_scan():
    """
    Admin có thể kích hoạt quét thiết bị thủ công
    API này sẽ gọi đến các service khác để scan ports
    """
    
    admin_username = session.get('username')
    
    # Chỉ trả về thông tin về việc scan, không thực hiện scan trực tiếp
    # Vì scan ports cần được thực hiện bởi service khác
    log_action(admin_username, "Yêu cầu quét thiết bị thủ công", success=True)
    
    return jsonify(
        ok=True,
        message="Đã gửi yêu cầu quét thiết bị. Các thiết bị mới sẽ được thêm tự động.",
        note="Service quét thiết bị sẽ gọi API /admin/auto-discover khi phát hiện thiết bị mới"
    ), 200

@hardware_bp.route("/admin/devices", methods=["POST"])
@require_auth('admin')
def add_device_manually():
    """Admin thêm thiết bị thủ công"""
    
    data, error_response, status_code = validate_json_request(['port', 'type', 'device_name'])
    if error_response:
        return error_response, status_code
    
    port = data.get('port')
    device_type = data.get('type')
    device_name = data.get('device_name')
    tag_name = data.get('tag_name')  # Cho phép admin tự đặt tag_name
    
    admin_username = session.get('username')
    
    def _add_device_manually_operation(db, cur):
        # Kiểm tra port đã tồn tại chưa
        cur.execute("SELECT tag_name FROM devices WHERE port = %s", (port,))
        if cur.fetchone():
            return jsonify(ok=False, error=f"Port {port} đã được sử dụng"), 400
        
        # Nếu không có tag_name, tự động tạo
        if not tag_name:
            cur.execute("SELECT tag_name FROM devices WHERE type = %s ORDER BY tag_name", (device_type,))
            existing_tags = {row['tag_name'] for row in cur.fetchall()}
            
            i = 1
            while True:
                auto_tag_name = f"{device_type}_{i}"
                if auto_tag_name not in existing_tags:
                    tag_name = auto_tag_name
                    break
                i += 1
        else:
            # Kiểm tra tag_name đã tồn tại chưa
            cur.execute("SELECT id FROM devices WHERE tag_name = %s", (tag_name,))
            if cur.fetchone():
                return jsonify(ok=False, error=f"TAG '{tag_name}' đã tồn tại"), 400
        
        # Thêm thiết bị
        cur.execute("""
            INSERT INTO devices (port, type, tag_name, device_name, created_by, created_at) 
            VALUES (%s, %s, %s, %s, %s, NOW())
        """, (port, device_type, tag_name, device_name, admin_username))
        
        db.commit()
        
        log_action(admin_username, f"Thêm thiết bị thủ công: {tag_name} ({device_name}) tại {port}", success=True)
        
        return jsonify(
            ok=True,
            message=f"Đã thêm thiết bị '{device_name}' với TAG '{tag_name}'",
            device_info={
                'tag_name': tag_name,
                'device_name': device_name,
                'type': device_type,
                'port': port,
                'created_by': admin_username
            }
        ), 201
    
    return safe_db_operation(_add_device_manually_operation)

@hardware_bp.route("/admin/devices/<tag_name>", methods=["PUT"])
@require_auth('admin')
def update_device(tag_name):
    """Admin cập nhật thông tin thiết bị"""
    
    data = request.get_json()
    if not data:
        return jsonify(ok=False, error="Request body phải là JSON"), 400
    
    admin_username = session.get('username')
    
    def _update_device_operation(db, cur):
        # Kiểm tra thiết bị tồn tại
        cur.execute("SELECT * FROM devices WHERE tag_name = %s", (tag_name,))
        device = cur.fetchone()
        if not device:
            return jsonify(ok=False, error=f"Không tìm thấy thiết bị có TAG '{tag_name}'"), 404
        
        # Chuẩn bị các trường có thể cập nhật
        updatable_fields = ['device_name', 'type', 'port']
        updates = []
        params = []
        
        for field in updatable_fields:
            if field in data:
                updates.append(f"{field} = %s")
                params.append(data[field])
        
        if not updates:
            return jsonify(ok=False, error="Không có trường nào để cập nhật"), 400
        
        # Nếu cập nhật port, kiểm tra port mới không bị trùng
        if 'port' in data and data['port'] != device['port']:
            cur.execute("SELECT tag_name FROM devices WHERE port = %s AND tag_name != %s", (data['port'], tag_name))
            if cur.fetchone():
                return jsonify(ok=False, error=f"Port {data['port']} đã được sử dụng"), 400
        
        # Thực hiện cập nhật
        params.append(tag_name)
        update_query = f"UPDATE devices SET {', '.join(updates)}, updated_at = NOW() WHERE tag_name = %s"
        
        cur.execute(update_query, params)
        db.commit()
        
        log_action(admin_username, f"Cập nhật thiết bị {tag_name}: {', '.join(updates)}", success=True)
        
        return jsonify(
            ok=True,
            message=f"Đã cập nhật thiết bị '{tag_name}'",
            updated_fields=list(data.keys())
        ), 200
    
    return safe_db_operation(_update_device_operation)

@hardware_bp.route("/admin/devices/<tag_name>", methods=["DELETE"])
@require_auth('admin')
def delete_device(tag_name):
    """Admin xóa thiết bị"""
    
    admin_username = session.get('username')
    
    def _delete_device_operation(db, cur):
        # Kiểm tra thiết bị tồn tại
        cur.execute("SELECT device_name, in_use_by FROM devices WHERE tag_name = %s", (tag_name,))
        device = cur.fetchone()
        if not device:
            return jsonify(ok=False, error=f"Không tìm thấy thiết bị có TAG '{tag_name}'"), 404
        
        # Kiểm tra thiết bị có đang được sử dụng không
        if device.get('in_use_by'):
            return jsonify(
                ok=False, 
                error=f"Không thể xóa thiết bị đang được sử dụng bởi '{device['in_use_by']}'. Hãy giải phóng trước."
            ), 400
        
        # Xóa các assignments liên quan trước
        cur.execute("DELETE FROM assignments WHERE tag_name = %s", (tag_name,))
        
        # Xóa thiết bị
        cur.execute("DELETE FROM devices WHERE tag_name = %s", (tag_name,))
        db.commit()
        
        log_action(admin_username, f"Xóa thiết bị {tag_name} ({device.get('device_name')})", success=True)
        
        return jsonify(
            ok=True,
            message=f"Đã xóa thiết bị '{device.get('device_name')}' (TAG: {tag_name})"
        ), 200
    
    return safe_db_operation(_delete_device_operation)

# =================================================================
# ===                  API CHUNG                                ===
# =================================================================
@hardware_bp.route("/devices/<tag_name>/status", methods=["GET"])
@require_auth('user')
def get_device_status(tag_name):
    """Lấy trạng thái thiết bị"""
    
    def _get_device_status_operation(db, cur):
        cur.execute("""
            SELECT d.tag_name, d.device_name, d.in_use_by, d.used_at,
                   u.full_name as user_full_name
            FROM devices d
            LEFT JOIN users u ON d.in_use_by = u.username
            WHERE d.tag_name = %s
        """, (tag_name,))
        
        device = cur.fetchone()
        if not device:
            return jsonify(ok=False, error=f"Không tìm thấy thiết bị có TAG '{tag_name}'"), 404
        
        return jsonify(ok=True, data=device), 200
    
    return safe_db_operation(_get_device_status_operation)

# =================================================================
# ===                  ERROR HANDLERS                           ===
# =================================================================
@hardware_bp.errorhandler(400)
def bad_request(error):
    return jsonify(ok=False, error="Yêu cầu không hợp lệ"), 400

@hardware_bp.errorhandler(401)
def unauthorized(error):
    return jsonify(ok=False, error="Chưa đăng nhập"), 401

@hardware_bp.errorhandler(403)
def forbidden(error):
    return jsonify(ok=False, error="Không có quyền truy cập"), 403

@hardware_bp.errorhandler(404)
def not_found(error):
    return jsonify(ok=False, error="Không tìm thấy tài nguyên"), 404

@hardware_bp.errorhandler(500)
def internal_error(error):
    return jsonify(ok=False, error="Lỗi máy chủ nội bộ"), 500