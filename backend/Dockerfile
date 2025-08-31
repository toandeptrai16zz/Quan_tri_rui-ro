# Arduino Compile API - Zero Configuration Backend
# Web frontend chỉ cần POST code lên /compile là xong
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/usr/local/bin:${PATH}"

# ===================================================================
# SYSTEM SETUP
# ===================================================================
RUN apt-get update && apt-get install -y \
    openssh-server sudo ca-certificates curl wget vim \
    git python3 python3-pip python3-flask python3-flask-cors \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Arduino CLI với tất cả cores
RUN curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh | BINDIR=/usr/local/bin sh && \
    pip3 install pyserial esptool flask flask-cors

# Arduino CLI auto setup
RUN arduino-cli config init && \
    arduino-cli config set board_manager.additional_urls \
    "https://arduino.esp8266.com/stable/package_esp8266com_index.json,https://espressif.github.io/arduino-esp32/package_esp32_index.json" && \
    timeout 180 arduino-cli core update-index || echo "Using cached" && \
    arduino-cli core install arduino:avr && \
    (arduino-cli core install esp8266:esp8266 || echo "ESP8266 retry later") && \
    (arduino-cli core install esp32:esp32 || echo "ESP32 retry later")

# ===================================================================
# COMPILE API SERVER
# ===================================================================
RUN echo 'from flask import Flask, request, jsonify\n\
from flask_cors import CORS\n\
import subprocess\n\
import tempfile\n\
import os\n\
import json\n\
\n\
app = Flask(__name__)\n\
CORS(app)\n\
\n\
# Board mappings\n\
BOARDS = {\n\
    "uno": "arduino:avr:uno",\n\
    "nano": "arduino:avr:nano",\n\
    "esp8266": "esp8266:esp8266:nodemcuv2",\n\
    "esp32": "esp32:esp32:esp32",\n\
    "nodemcu": "esp8266:esp8266:nodemcuv2"\n\
}\n\
\n\
def auto_detect_board(code):\n\
    """Auto detect board from code"""\n\
    code_lower = code.lower()\n\
    if "esp8266" in code_lower or "nodemcu" in code_lower:\n\
        return "esp8266:esp8266:nodemcuv2"\n\
    elif "esp32" in code_lower or ("wifi.begin" in code_lower and "esp" in code_lower):\n\
        return "esp32:esp32:esp32"\n\
    else:\n\
        return "arduino:avr:uno"\n\
\n\
@app.route("/", methods=["GET"])\n\
def home():\n\
    return jsonify({\n\
        "status": "Arduino Compile API Ready",\n\
        "endpoints": {\n\
            "/compile": "POST - Compile Arduino code",\n\
            "/boards": "GET - List available boards",\n\
            "/status": "GET - System status"\n\
        },\n\
        "usage": {\n\
            "compile": {\n\
                "method": "POST",\n\
                "body": {\n\
                    "code": "Arduino code here",\n\
                    "board": "uno|esp8266|esp32|auto (optional)"\n\
                }\n\
            }\n\
        }\n\
    })\n\
\n\
@app.route("/compile", methods=["POST"])\n\
def compile_code():\n\
    try:\n\
        data = request.get_json()\n\
        \n\
        if not data or "code" not in data:\n\
            return jsonify({"error": "No code provided"}), 400\n\
            \n\
        code = data["code"]\n\
        board_type = data.get("board", "auto")\n\
        \n\
        # Auto detect board if not specified\n\
        if board_type == "auto":\n\
            board_fqbn = auto_detect_board(code)\n\
            detected_board = [k for k, v in BOARDS.items() if v == board_fqbn][0] if board_fqbn in BOARDS.values() else "uno"\n\
        else:\n\
            board_fqbn = BOARDS.get(board_type, BOARDS["uno"])\n\
            detected_board = board_type\n\
            \n\
        # Create temp file\n\
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ino", delete=False) as f:\n\
            f.write(code)\n\
            temp_file = f.name\n\
            \n\
        try:\n\
            # Compile\n\
            result = subprocess.run([\n\
                "arduino-cli", "compile", \n\
                "--fqbn", board_fqbn,\n\
                temp_file\n\
            ], capture_output=True, text=True, timeout=60)\n\
            \n\
            # Get file sizes if successful\n\
            file_info = {}\n\
            if result.returncode == 0:\n\
                base_name = temp_file.replace(".ino", "")\n\
                hex_file = f"{base_name}/{os.path.basename(base_name)}.ino.hex"\n\
                bin_file = f"{base_name}/{os.path.basename(base_name)}.ino.bin"\n\
                \n\
                if os.path.exists(hex_file):\n\
                    file_info["hex_size"] = os.path.getsize(hex_file)\n\
                if os.path.exists(bin_file):\n\
                    file_info["bin_size"] = os.path.getsize(bin_file)\n\
            \n\
            return jsonify({\n\
                "success": result.returncode == 0,\n\
                "board": detected_board,\n\
                "board_fqbn": board_fqbn,\n\
                "output": result.stdout,\n\
                "error": result.stderr if result.returncode != 0 else None,\n\
                "file_info": file_info,\n\
                "exit_code": result.returncode\n\
            })\n\
            \n\
        finally:\n\
            # Cleanup\n\
            try:\n\
                os.unlink(temp_file)\n\
                # Remove compile output directory\n\
                import shutil\n\
                output_dir = temp_file.replace(".ino", "")\n\
                if os.path.exists(output_dir):\n\
                    shutil.rmtree(output_dir)\n\
            except:\n\
                pass\n\
                \n\
    except subprocess.TimeoutExpired:\n\
        return jsonify({"error": "Compilation timeout"}), 408\n\
    except Exception as e:\n\
        return jsonify({"error": str(e)}), 500\n\
\n\
@app.route("/boards", methods=["GET"])\n\
def list_boards():\n\
    return jsonify({"boards": BOARDS})\n\
\n\
@app.route("/status", methods=["GET"])\n\
def status():\n\
    try:\n\
        # Check Arduino CLI\n\
        cli_result = subprocess.run(["arduino-cli", "version"], capture_output=True, text=True)\n\
        cores_result = subprocess.run(["arduino-cli", "core", "list"], capture_output=True, text=True)\n\
        \n\
        return jsonify({\n\
            "arduino_cli": {\n\
                "available": cli_result.returncode == 0,\n\
                "version": cli_result.stdout.strip() if cli_result.returncode == 0 else None\n\
            },\n\
            "cores": cores_result.stdout.strip() if cores_result.returncode == 0 else "Error getting cores",\n\
            "api": "Ready"\n\
        })\n\
    except Exception as e:\n\
        return jsonify({"error": str(e)}), 500\n\
\n\
if __name__ == "__main__":\n\
    print("🚀 Arduino Compile API Starting...")\n\
    print("📡 Endpoints:")\n\
    print("   POST /compile - Compile Arduino code")\n\
    print("   GET /boards   - List available boards") \n\
    print("   GET /status   - System status")\n\
    print("🌐 Running on http://0.0.0.0:5000")\n\
    app.run(host="0.0.0.0", port=5000, debug=False)\n\
' > /app.py

# ===================================================================
# STARTUP SCRIPT
# ===================================================================
RUN echo '#!/bin/bash\n\
echo "=== Arduino Compile API Server ==="\n\
\n\
# Start SSH\n\
service ssh start\n\
echo "✅ SSH server started"\n\
\n\
# Start API server\n\
echo "🚀 Starting Arduino Compile API..."\n\
python3 /app.py\n\
' > /entrypoint.sh && \
chmod +x /entrypoint.sh

# SSH config
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

# Create user
RUN useradd -m -s /bin/bash arduino && \
    echo 'arduino:arduino123' | chpasswd

# Test installation
RUN arduino-cli version && \
    arduino-cli core list && \
    python3 -c "import flask; print('Flask OK')"

EXPOSE 22 5000

ENTRYPOINT ["/entrypoint.sh"]
