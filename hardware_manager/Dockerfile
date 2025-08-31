# file: hardware_manager/Dockerfile
FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Cài đặt udevadm để script có thể truy vấn thông tin thiết bị
RUN apt-get update && apt-get install -y udev && rm -rf /var/lib/apt/lists/*

COPY listener.py .

# Giữ cho container chạy ngầm
CMD ["tail", "-f", "/dev/null"]