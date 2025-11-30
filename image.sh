#!/bin/bash
set -e

echo "===== AI Image Enhancer Setup Started ====="

# Update system
sudo apt update -y
sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip python3-venv nginx git

# Create app folder
sudo mkdir -p /var/www/enhancer
sudo chown $USER:$USER /var/www/enhancer
cd /var/www/enhancer

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Real-ESRGAN & Flask
pip install flask pillow basicsr facexlib gfpgan realesrgan

# Download Real-ESRGAN repo
git clone https://github.com/xinntao/Real-ESRGAN.git
cd Real-ESRGAN
pip install -r requirements.txt

# Download model weights
wget https://github.com/xinntao/Real-ESRGAN/releases/download/v0.1.0/RealESRGAN_x4plus.pth -O weights.pth

# Go back to main folder
cd /var/www/enhancer

# Create Flask backend
cat << 'EOF' > app.py
from flask import Flask, request, send_file, render_template
from PIL import Image
import os
from realesrgan import RealESRGAN

app = Flask(__name__)

model = RealESRGAN('Real-ESRGAN/weights.pth', scale=4)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/enhance', methods=['POST'])
def enhance():
    file = request.files['image']
    input_path = "input.jpg"
    output_path = "output.jpg"

    file.save(input_path)

    img = Image.open(input_path)
    enhanced = model.predict(img)
    enhanced.save(output_path)

    return send_file(output_path, as_attachment=True, download_name="enhanced.jpg")
EOF

# Create templates folder
mkdir -p templates

# Create web UI
cat << 'EOF' > templates/index.html
<!DOCTYPE html>
<html>
<head>
<title>AI Image Enhancer</title>
<style>
body { font-family: Arial; text-align: center; background: #f8f8f8; }
.container { margin-top: 50px; background: white; padding: 30px; border-radius: 10px; width: 40%; margin-left: auto; margin-right: auto; }
button { padding: 12px 20px; background: #007bff; color: white; border: none; border-radius: 6px; cursor: pointer; }
</style>
</head>
<body>
<div class="container">
<h2>AI Image Enhancer</h2>
<form action="/enhance" method="POST" enctype="multipart/form-data">
<input type="file" name="image" required><br><br>
<button type="submit">Enhance Image</button>
</form>
</div>
</body>
</html>
EOF

# Create Gunicorn service
sudo bash -c 'cat <<EOF > /etc/systemd/system/enhancer.service
[Unit]
Description=AI Image Enhancer
After=network.target

[Service]
User=root
WorkingDirectory=/var/www/enhancer
ExecStart=/var/www/enhancer/venv/bin/gunicorn -b localhost:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF'

# Enable service
sudo systemctl daemon-reload
sudo systemctl enable enhancer
sudo systemctl start enhancer

# Configure NGINX
sudo bash -c 'cat <<EOF > /etc/nginx/sites-available/enhancer
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://localhost:5000;
    }
}
EOF'

sudo ln -sf /etc/nginx/sites-available/enhancer /etc/nginx/sites-enabled/enhancer
sudo nginx -t
sudo systemctl restart nginx

echo "===== INSTALLATION COMPLETE ====="
echo "Open your browser and visit: http://YOUR_SERVER_IP"
