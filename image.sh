#!/bin/bash
set -e

echo "===== Installing AI Image Enhancer (NCNN Version) ====="

sudo apt update -y
sudo apt install -y nginx unzip wget

# Create app directory
sudo mkdir -p /var/www/enhancer
cd /var/www/enhancer

# Download Real-ESRGAN NCNN (no PyTorch)
wget https://github.com/xinntao/Real-ESRGAN-ncnn-vulkan/releases/download/v0.2.0/realesrgan-ncnn-vulkan-20220424-ubuntu.zip
unzip realesrgan-ncnn-vulkan-20220424-ubuntu.zip
mv realesrgan-ncnn-vulkan-20220424-ubuntu realesrgan

# Create upload/enhance script
cat << 'EOF' > enhance.sh
#!/bin/bash
INPUT="$1"
OUTPUT="$2"

# 4x upscale
/var/www/enhancer/realesrgan/realesrgan-ncnn-vulkan -i "$INPUT" -o "$OUTPUT" -s 4
EOF

chmod +x enhance.sh

# Install backend (Flask lightweight)
sudo apt install -y python3 python3-pip
pip3 install flask

# Create Flask backend
cat << 'EOF' > app.py
from flask import Flask, request, send_file, render_template
import os
import subprocess

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/enhance", methods=["POST"])
def enhance():
    file = request.files["image"]

    input_path = "input.jpg"
    output_path = "output.png"

    file.save(input_path)

    subprocess.run(["bash", "enhance.sh", input_path, output_path])

    return send_file(output_path, as_attachment=True)
EOF

mkdir -p templates

# Simple frontend
cat << 'EOF' > templates/index.html
<!DOCTYPE html>
<html>
<head>
<title>AI Image Enhancer</title>
<style>
body{font-family:Arial;text-align:center;margin-top:50px;}
input{padding:10px;}
button{padding:10px 20px;background:#007bff;color:white;border:none;border-radius:5px;}
</style>
</head>
<body>
<h2>AI Image Enhancer (4× Upscale)</h2>
<form action="/enhance" method="POST" enctype="multipart/form-data">
<input type="file" name="image" required><br><br>
<button type="submit">Enhance Image</button>
</form>
</body>
</html>
EOF

# Create systemd service for Flask
cat << EOF | sudo tee /etc/systemd/system/enhancer.service
[Unit]
Description=AI Enhancer
After=network.target

[Service]
ExecStart=/usr/bin/python3 /var/www/enhancer/app.py
WorkingDirectory=/var/www/enhancer
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable enhancer
sudo systemctl start enhancer

# Configure NGINX
cat << EOF | sudo tee /etc/nginx/sites-available/enhancer
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:5000;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/enhancer /etc/nginx/sites-enabled/enhancer
sudo nginx -t
sudo systemctl restart nginx

echo "===== INSTALL COMPLETE ====="
echo "Visit: http://YOUR_SERVER_IP"
