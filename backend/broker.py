import asyncio
import datetime
import subprocess
import logging
import serial
import base64
import tempfile
import os
import time
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='/var/log/hardware_broker.log',
    filemode='a'
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

app = FastAPI()

# Biến toàn cục để lưu trạng thái khóa
hardware_lock = {
    "locked_by": None,
    "locked_at": None,
    "lock_duration_minutes": 15
}
DEVICE_PORT = "/dev/ttyUSB0"

class RequestPayload(BaseModel):
    user: str

class FlashPayload(BaseModel):
    user: str
    firmware_data: str # Dữ liệu firmware đã được mã hóa base64

class SerialPayload(BaseModel):
    user: str
    duration: int # Thời gian đọc serial (giây)

def is_lock_expired():
    if hardware_lock["locked_at"] is None:
        return True
    expires_at = hardware_lock["locked_at"] + datetime.timedelta(minutes=hardware_lock["lock_duration_minutes"])
    return datetime.datetime.now() > expires_at

def verify_user_lock(user: str):
    if is_lock_expired():
        hardware_lock["locked_by"] = None
        hardware_lock["locked_at"] = None
        logging.warning("Khóa đã hết hạn, tự động giải phóng.")
        raise HTTPException(status_code=403, detail="Quyền truy cập đã hết hạn. Vui lòng yêu cầu lại.")
    if hardware_lock["locked_by"] != user:
        raise HTTPException(status_code=403, detail=f"Thiết bị đang được khóa bởi người dùng '{hardware_lock['locked_by']}'.")

@app.post("/request")
async def request_device(payload: RequestPayload):
    user = payload.user
    if hardware_lock["locked_by"] is not None and not is_lock_expired():
        logging.warning(f"TRUY CẬP BỊ TỪ CHỐI cho {user}. Đang khóa bởi {hardware_lock['locked_by']}")
        raise HTTPException(status_code=409, detail=f"Thiết bị đã được khóa bởi {hardware_lock['locked_by']}.")
    hardware_lock["locked_by"] = user
    hardware_lock["locked_at"] = datetime.datetime.now()
    logging.info(f"CẤP QUYỀN TRUY CẬP cho {user}. Khóa đã được thiết lập.")
    return {"message": f"Đã cấp quyền truy cập thiết bị cho {user}. Quyền sẽ hết hạn sau {hardware_lock['lock_duration_minutes']} phút."}

@app.post("/release")
async def release_device(payload: RequestPayload):
    user = payload.user
    if hardware_lock["locked_by"] != user:
        logging.warning(f"YÊU CẦU GIẢI PHÓNG KHÔNG HỢP LỆ từ {user}. Đang khóa bởi {hardware_lock['locked_by']}")
        raise HTTPException(status_code=403, detail="Bạn không phải là người đang giữ khóa.")
    hardware_lock["locked_by"] = None
    hardware_lock["locked_at"] = None
    logging.info(f"Thiết bị đã được giải phóng bởi {user}.")
    return {"message": "Đã giải phóng thiết bị thành công."}

@app.post("/flash")
async def flash_firmware(payload: FlashPayload):
    verify_user_lock(payload.user)
    
    # Giải mã dữ liệu firmware từ base64 và lưu vào file tạm
    try:
        firmware_bytes = base64.b64decode(payload.firmware_data)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp_file:
            tmp_file.write(firmware_bytes)
            tmp_file_path = tmp_file.name
    except Exception as e:
        logging.error(f"Lỗi giải mã firmware từ {payload.user}: {e}")
        raise HTTPException(status_code=400, detail=f"Dữ liệu firmware không hợp lệ: {e}")

    # Lệnh nạp firmware thực tế cho ESP8266
    cmd = [
        "esptool",
        "--port", DEVICE_PORT,
        "write-flash",
        "0x00000",
        tmp_file_path
    ]
    
    logging.info(f"Người dùng {payload.user} đang nạp firmware từ file tạm: {tmp_file_path}")
    
    try:
        # Sử dụng timeout để lệnh không bị treo vô hạn
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=120)
        os.remove(tmp_file_path) # Xóa file tạm sau khi nạp xong
        return {"status": "Thành công", "output": result.stdout + result.stderr}
    except subprocess.CalledProcessError as e:
        os.remove(tmp_file_path)
        logging.error(f"Nạp firmware thất bại cho {payload.user}. Lỗi: {e.stderr}")
        raise HTTPException(status_code=500, detail=f"Nạp firmware thất bại: {e.stderr}")
    except subprocess.TimeoutExpired:
        os.remove(tmp_file_path)
        logging.error(f"Nạp firmware cho {payload.user} quá thời gian.")
        raise HTTPException(status_code=500, detail="Nạp firmware quá thời gian (timeout).")

@app.post("/read-serial")
async def read_serial(payload: SerialPayload):
    verify_user_lock(payload.user)
    
    logging.info(f"Người dùng {payload.user} đang đọc serial trong {payload.duration} giây.")
    
    try:
        ser = serial.Serial(DEVICE_PORT, 115200, timeout=1)
        output = ""
        start_time = time.time()
        while time.time() - start_time < payload.duration:
            line = ser.readline().decode('utf-8', errors='ignore')
            if line:
                output += line
        ser.close()
        return {"status": "Thành công", "data": output or "Không có dữ liệu mới."}
    except serial.SerialException as e:
        logging.error(f"Lỗi khi đọc serial cho {payload.user}: {e}")
        raise HTTPException(status_code=500, detail=f"Lỗi cổng serial: {e}")
