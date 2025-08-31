# file: hardware_manager/listener.py
import sys
import os
import requests
import logging
import subprocess

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

BACKEND_URL = os.environ.get("BACKEND_URL", "http://backend:5000")
API_ENDPOINT = f"{BACKEND_URL}/api/hardware/admin/auto-discover"

# Từ điển để nhận dạng thiết bị qua Vendor ID và Product ID
# Bạn có thể bổ sung thêm các thiết bị khác vào đây
DEVICE_MAP = {
    "1a86:7523": "ESP_CH340",  # Common for NodeMCU, ESP8266
    "10c4:ea60": "ESP_CP2102", # Common for ESP32
    "2341:0043": "Arduino_Uno",
    "2341:0001": "Arduino_Uno",
    "2341:0042": "Arduino_Mega",
}

def get_device_id(port_name):
    """Lấy VID:PID của thiết bị từ udevadm."""
    try:
        # Lệnh này sẽ truy vấn thông tin của thiết bị tty
        command = f"udevadm info --name={port_name} --attribute-walk | grep -m 1 'ATTRS{{idVendor}}==\"' "
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)

        # Phân tích output để lấy VID và PID
        line = result.stdout.strip()
        vid = line.split('ATTRS{idVendor}=="')[1].split('"')[0]
        pid = line.split('ATTRS{idProduct}=="')[1].split('"')[0]
        return f"{vid}:{pid}"
    except Exception as e:
        logging.error(f"Không thể lấy được ID của thiết bị {port_name}: {e}")
        return None

def main():
    if len(sys.argv) < 2:
        logging.error("Thiếu tham số device port.")
        sys.exit(1)

    port_name = sys.argv[1] # ví dụ: ttyUSB0
    full_port_path = f"/dev/{port_name}"
    logging.info(f"Phát hiện sự kiện trên cổng: {full_port_path}")

    device_id = get_device_id(port_name)
    if not device_id:
        sys.exit(1)

    device_type = DEVICE_MAP.get(device_id, "Unknown_Device")
    logging.info(f"Định danh thiết bị: {device_type} (ID: {device_id})")

    payload = {
        "port": full_port_path,
        "type": device_type
    }

    try:
        logging.info(f"Gửi thông tin đến backend: {payload}")
        response = requests.post(API_ENDPOINT, json=payload, timeout=10)
        response.raise_for_status()
        logging.info(f"Backend phản hồi: {response.json()}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Lỗi khi gọi API backend: {e}")

if __name__ == "__main__":
    main()