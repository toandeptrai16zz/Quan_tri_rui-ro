#!/bin/bash
set -e

# Tạo host keys nếu chưa có
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
  ssh-keygen -A
fi

USERNAME="${USERNAME:-devuser}"
PASSWORD="${PASSWORD:-password123}"

# Tạo user nếu chưa tồn tại
if ! id -u "$USERNAME" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$USERNAME"
  echo "${USERNAME}:${PASSWORD}" | chpasswd
  usermod -aG sudo "$USERNAME" || true
fi

# ===== QUAN TRỌNG: Thiết lập PATH cho user =====
# Thêm PATH vào .bashrc của user
echo 'export PATH="/usr/local/bin:$PATH"' >> /home/"$USERNAME"/.bashrc

# Thêm PATH vào .profile của user (cho non-interactive shells)
echo 'export PATH="/usr/local/bin:$PATH"' >> /home/"$USERNAME"/.profile

# Tạo symlink arduino-cli vào /usr/bin để đảm bảo
ln -sf /usr/local/bin/arduino-cli /usr/bin/arduino-cli

chown -R "$USERNAME":"$USERNAME" /home/"$USERNAME" || true

# Chạy sshd foreground
exec /usr/sbin/sshd -D
