import subprocess
import logging
import base64
import tempfile
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Cấu hình logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - BROKER - %(message)s')

app = FastAPI(title="Hardware Broker Service")

class FlashPayload(BaseModel):
    port: str
    device_type: str
    firmware_data: str # Base64 encoded

def run_command(command, timeout=120):
    """Hàm helper để chạy một lệnh hệ thống và trả về kết quả."""
    try:
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            check=True, 
            timeout=timeout
        )
        return True, result.stdout + result.stderr
    except subprocess.CalledProcessError as e:
        logging.error(f"Lệnh thất bại. Stderr: {e.stderr}")
        return False, e.stderr
    except subprocess.TimeoutExpired:
        logging.error("Lệnh hết thời gian thực thi.")
        return False, "Lỗi: Quá thời gian thực thi (Timeout)."
    except Exception as e:
        logging.error(f"Lỗi không xác định: {e}")
        return False, f"Lỗi không xác định: {str(e)}"

@app.post("/execute/flash")
def execute_flash(payload: FlashPayload):
    """
    Nhận lệnh từ backend, giải mã firmware, và gọi công cụ nạp code phù hợp.
    """
    logging.info(f"Nhận yêu cầu nạp code cho {payload.device_type} tại cổng {payload.port}")

    tmp_file_path = None
    try:
        # Giải mã firmware từ base64 và lưu vào file tạm
        firmware_bytes = base64.b64decode(payload.firmware_data)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin", dir="/tmp") as tmp_file:
            tmp_file.write(firmware_bytes)
            tmp_file_path = tmp_file.name

        command = []
        # Tự động chọn công cụ nạp code dựa trên device_type
        if "ESP" in payload.device_type.upper():
            command = [
                "esptool.py",
                "--port", payload.port,
                "write_flash",
                "0x1000", tmp_file_path
            ]
        elif "ARDUINO" in payload.device_type.upper():
            # Giả sử board là "uno". Cần logic phức tạp hơn nếu có nhiều loại Arduino.
            # arduino-cli upload -p [PORT] --fqbn arduino:avr:uno [SKETCH_PATH]
            # Lưu ý: arduino-cli cần file .ino, không phải .bin/.hex trực tiếp. 
            # Chức năng này cần được phát triển thêm.
            # Tạm thời chúng ta chỉ hỗ trợ ESP.
            raise HTTPException(status_code=501, detail="Nạp code cho Arduino chưa được hỗ trợ bởi broker.")
        else:
            raise HTTPException(status_code=400, detail=f"Loại thiết bị không xác định: {payload.device_type}")

        logging.info(f"Đang thực thi lệnh: {' '.join(command)}")
        success, output = run_command(command)

        if success:
            return {"success": True, "output": output}
        else:
            raise HTTPException(status_code=500, detail=output)

    finally:
        # Dọn dẹp file tạm
        if tmp_file_path and os.path.exists(tmp_file_path):
            os.remove(tmp_file_path)