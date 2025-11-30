#!/bin/bash
set -e

echo "===== AI Image Enhancer (NCNN Version) Setup Started ====="

sudo apt update -y
sudo apt install -y nginx unzip wget python3 python3-pip

sudo mkdir -p /var/www/enhancer
sudo chown $USER:$USER /var/www/enhancer
cd /var/www/enhancer

echo "===== Downloading RealESRGAN NCNN (Stable Working Build) ====="

wget https://github.com/xinntao/Real-ESRGAN-ncnn-vulkan/releases/download/v0.2.0/RealESRGAN-ncnn-vulkan-20220728-ubuntu.zip

unzip RealESRGAN-ncnn-vulkan-20220728-ubuntu.zip
mv RealESRGAN-ncnn-vulkan-20220728-ubuntu realesrgan
chmod +x realesrgan/realesrgan-ncnn-vulkan

echo "===== Creating Enhance Script ====="

cat << 'EOF' > enhance.sh
#!/bin/bash
INPUT="$1"
OUTPUT="$2"

/var/www/enhancer/realesrgan/realesrgan-ncnn-vulkan -i "$INPUT" -o "$OUTPUT" -s 4
EOF

chmod +x enhance.sh

pip3 install flask

echo "===== Creating Flask Backend ====="

cat << 'EOF' > app.py
from flask import Flask, request, send_file, render_template
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

echo "===== Creating Frontend ====="

cat << 'EOF' > templates/index.html
<!DOCTYPE html>
<html>
<head>
<title>AI Image Enhancer</title>
<style>
body {
    font-family: Arial;
    text-align: center;
    margin-top: 50px;
    background: #f4f4f4;
}
.container {
    background: white;
    width: 40%;
    margin-left: auto;
    margin-right: auto;
    padding: 30px;
    border-radius: 10px;
}
button {
    padding: 10px 20px;
    background: #007bff;
    color: white;
    border: none;
    border-radius: 5px;
}
</style>
</head>
<body>
<div class="container">
<h2>AI Image Enhancer (4× Upscale)</h2>
<form action="/enhance" method="POST" enctype="multipart/form-data">
<input type="file" name="image" required><br><br>
<button type="submit">Enhance Image</button>
</form>
</div>
</body>
</html>
EOF

echo "===== Creating systemd Service ====="

sudo bash -c 'cat << EOF > /etc/systemd/system/enhancer.service
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
EOF'

sudo systemctl daemon-reload
sudo systemctl enable enhancer
sudo systemctl start enhancer

echo "===== Configuring NGINX ====="

sudo bash -c 'cat << EOF > /etc/nginx/sites-available/enhancer
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:5000;
    }
}
EOF'

sudo ln -sf /etc/nginx/sites-available/enhancer /etc/nginx/sites-enabled/enhancer

sudo nginx -t
sudo systemctl restart nginx

echo "===== INSTALL COMPLETE ====="
echo "Visit your enhancer website: http://YOUR_SERVER_IP/"
