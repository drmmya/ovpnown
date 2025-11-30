#!/bin/bash
set -e

echo "===== Installing Dependencies ====="

sudo apt update -y
sudo apt install -y \
    git cmake build-essential python3 python3-pip python3-venv \
    unzip wget curl clang libvulkan1 vulkan-utils mesa-vulkan-drivers

echo "===== Installing Vulkan SDK ====="

wget https://sdk.lunarg.com/sdk/download/latest/linux/vulkan-sdk.tar.gz
tar -xvzf vulkan-sdk.tar.gz
VULKAN_SDK_DIR=$(find . -maxdepth 1 -type d -name "*/x86_64" | head -n 1)
export VULKAN_SDK="$PWD/$VULKAN_SDK_DIR"
export PATH="$VULKAN_SDK/bin:$PATH"
export LD_LIBRARY_PATH="$VULKAN_SDK/lib:$LD_LIBRARY_PATH"

echo "===== Cloning Real-ESRGAN-NCNN-Vulkan (Latest Source) ====="

sudo mkdir -p /var/www/enhancer
sudo chown $USER:$USER /var/www/enhancer
cd /var/www/enhancer

git clone https://github.com/xinntao/Real-ESRGAN-ncnn-vulkan.git source
cd source

echo "===== Updating Submodules ====="
git submodule update --init --recursive

echo "===== Building Real-ESRGAN-NCNN-Vulkan ====="

mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

echo "===== Copying Build Output ====="

cd /var/www/enhancer
mkdir -p realesrgan
cp /var/www/enhancer/source/build/realesrgan-ncnn-vulkan realesrgan/
cp -r /var/www/enhancer/source/models realesrgan/

chmod +x realesrgan/realesrgan-ncnn-vulkan

echo "===== Creating Enhance Script ====="

cat << 'EOF' > enhance.sh
#!/bin/bash
INPUT="$1"
OUTPUT="$2"

/var/www/enhancer/realesrgan/realesrgan-ncnn-vulkan -i "$INPUT" -o "$OUTPUT" -s 4
EOF

chmod +x enhance.sh

echo "===== Installing Flask ====="

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
echo "Open your website: http://YOUR_SERVER_IP/"
