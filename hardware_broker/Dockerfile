FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# (Tùy chọn) Cài đặt thêm các công cụ khác nếu cần, ví dụ:
# RUN apt-get update && apt-get install -y arduino-cli

COPY broker.py .

# Broker sẽ lắng nghe trên cổng 8001
CMD ["uvicorn", "broker:app", "--host", "0.0.0.0", "--port", "8001"]