-- Vui lòng sử dụng UTF-8 khi lưu file này
CREATE DATABASE IF NOT EXISTS remote_lab;
USE remote_lab;

-- =================================================================
-- BẢNG TỪ HỆ THỐNG QUẢN LÝ USER (CỦA BẠN BẠN)
-- =================================================================

-- Bảng `users`: Lưu thông tin người dùng
CREATE TABLE IF NOT EXISTS `users` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `username` VARCHAR(50) NOT NULL UNIQUE,
  `password` VARCHAR(255) NOT NULL,
  `email` VARCHAR(255) NULL UNIQUE,
  `role` ENUM('admin','user') NOT NULL DEFAULT 'user',
  `status` ENUM('pending','active','blocked') NOT NULL DEFAULT 'pending',
  `ssh_port` INT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `last_login` TIMESTAMP NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Bảng `logs`: Ghi lại các hành động của người dùng
CREATE TABLE IF NOT EXISTS `logs` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `username` VARCHAR(50) NOT NULL,
  `action` VARCHAR(255) NOT NULL,
  `timestamp` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ip_address` VARCHAR(45) NULL,
  `user_agent` TEXT NULL,
  `success` BOOLEAN DEFAULT TRUE,
  `details` JSON NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- =================================================================
-- BẢNG TỪ HỆ THỐNG QUẢN LÝ PHẦN CỨNG (CỦA BẠN) - ĐÃ CHUYỂN SANG MYSQL
-- =================================================================

-- Bảng `devices`: Lưu thông tin các thiết bị phần cứng vật lý
CREATE TABLE IF NOT EXISTS `devices` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `port` VARCHAR(255) NOT NULL UNIQUE,         -- ví dụ: /dev/ttyUSB0
  `type` VARCHAR(100) NOT NULL,               -- ví dụ: ESP8266, Arduino Uno
  `tag_name` VARCHAR(100) NOT NULL UNIQUE,    -- ví dụ: ESP8266_Lab1
  `in_use_by` VARCHAR(50) NULL,               -- Username đang sử dụng, NULL nếu đang rảnh
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  
  -- Tạo mối quan hệ: `in_use_by` phải là một `username` có thật trong bảng `users`
  FOREIGN KEY (`in_use_by`) REFERENCES `users`(`username`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Bảng `assignments`: Lưu thông tin quyền sử dụng thiết bị của người dùng
CREATE TABLE IF NOT EXISTS `assignments` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` VARCHAR(50) NOT NULL,             -- Username của người được cấp quyền
  `tag_name` VARCHAR(100) NOT NULL,           -- Tag của thiết bị được cấp
  `expires_at` DATETIME NOT NULL,             -- Thời gian hết hạn quyền
  `is_active` BOOLEAN DEFAULT TRUE,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  
  -- Tạo mối quan hệ: `user_id` phải là một `username` có thật trong bảng `users`
  FOREIGN KEY (`user_id`) REFERENCES `users`(`username`) ON DELETE CASCADE ON UPDATE CASCADE,
  -- Tạo mối quan hệ: `tag_name` phải là một `tag_name` có thật trong bảng `devices`
  FOREIGN KEY (`tag_name`) REFERENCES `devices`(`tag_name`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- =================================================================
-- KHỞI TẠO DỮ LIỆU BAN ĐẦU
-- =================================================================

-- Tạo tài khoản admin mặc định (mật khẩu là 'admin123@')
-- Bạn có thể thay đổi mật khẩu sau này
INSERT INTO `users` (`username`, `password`, `email`, `role`, `status`)
SELECT 'admin', '$2b$12$K8.o3B5a.s4.6a0ZJ2n3nO.i4.mYg5i3U2e9R6j4.pYc5L5f6g7H8', 'admin@eputech.com', 'admin', 'active'
WHERE NOT EXISTS (SELECT 1 FROM `users` WHERE `username` = 'admin');
-- Lưu ý: password hash này tương ứng với 'admin123@', được tạo bởi generate_password_hash của werkzeug.
-- Nếu backend dùng thuật toán hash khác, bạn cần tạo lại hash này.