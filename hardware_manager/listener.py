# file: hardware_manager/listener.py (PHIÊN BẢN ĐƠN GIẢN HÓA)
import sys
import os
import requests
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

BACKEND_URL = os.environ.get("BACKEND_URL", "http://backend:5000")
API_ENDPOINT = f"{BACKEND_URL}/api/hardware/admin/auto-discover"
INTERNAL_API_SECRET = os.environ.get('INTERNAL_API_SECRET', 'default-secret-key')

# Từ điển để nhận dạng thiết bị qua Vendor ID và Product ID
DEVICE_MAP = {
    "1a86:7523": "ESP_CH340",
    "10c4:ea60": "ESP_CP2102",
    "2341:0043": "Arduino_Uno",
    "2341:0001": "Arduino_Uno",
    "2341:0042": "Arduino_Mega",
    "10c4:ea60": "ESP8266",
    "0e0f:0002": "ESP8266",
    "1d6b:0001": "ESP8266",
}

def main():
    if len(sys.argv) < 4:
        logging.error(f"Thiếu tham số. Cần 3 tham số, nhận được {len(sys.argv) - 1}.")
        sys.exit(1)

    port_name = sys.argv[1]
    vendor_id = sys.argv[2]
    product_id = sys.argv[3]

    full_port_path = f"/dev/{port_name}"
    
    logging.info(f"Phát hiện sự kiện trên cổng: {full_port_path} với VID: {vendor_id}, PID: {product_id}")

    # Gửi dữ liệu thô lên backend
    payload = {
        "port": full_port_path,
        "vendor_id": vendor_id,
        "product_id": product_id
    }
    
    headers = {'X-Internal-Secret': INTERNAL_API_SECRET}

    try:
        logging.info(f"Gửi thông tin đến backend: {payload}")
        response = requests.post(API_ENDPOINT, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        logging.info(f"Backend phản hồi: {response.json()}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Lỗi khi gọi API backend: {e}")

if __name__ == "__main__":
    main()