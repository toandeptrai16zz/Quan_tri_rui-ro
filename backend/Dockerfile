# Bước 1: Chọn một image Python nhẹ và ổn định làm nền tảng
FROM python:3.10-slim

# Bước 2: Đặt thư mục làm việc bên trong container là /app
WORKDIR /app

# Bước 3: Sao chép file requirements.txt vào trước
# Docker sẽ cache bước này, giúp build nhanh hơn nếu file này không thay đổi
COPY requirements.txt .

# Bước 4: Cài đặt tất cả các thư viện Python cần thiết
RUN pip install --no-cache-dir -r requirements.txt

# Bước 5: Sao chép toàn bộ mã nguồn của backend (app.py, hardware_api.py,...) vào thư mục /app
COPY . .

# Bước 6: Thông báo cho Docker rằng container sẽ lắng nghe trên cổng 5000
EXPOSE 5000

# Bước 7: Lệnh để khởi động ứng dụng khi container chạy
# Chúng ta sử dụng Gunicorn, một WSGI server mạnh mẽ cho môi trường production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "app:app"]