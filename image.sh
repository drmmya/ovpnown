#!/bin/bash
set -e

echo "===== Installing Dependencies ====="

sudo apt update -y
sudo apt install -y \
    git cmake build-essential python3 python3-pip python3-venv \
    unzip wget curl clang libvulkan1 mesa-vulkan-drivers

echo "===== Downloading Vulkan SDK (Header-only) ====="

wget -q https://sdk.lunarg.com/sdk/download/latest/linux/vulkan-sdk.tar.gz
tar -xf vulkan-sdk.tar.gz

SDK_DIR=$(find . -maxdepth 3 -type d -name "x86_64" | head -n 1)
export VULKAN_SDK="$PWD/$SDK_DIR"
export PATH="$VULKAN_SDK/bin:$PATH"
export LD_LIBRARY_PATH="$VULKAN_SDK/lib:$LD_LIBRARY_PATH"

echo "===== PREPARING PROJECT DIRECTORY ====="

sudo rm -rf /var/www/enhancer/source       # <<< VERY IMPORTANT
sudo mkdir -p /var/www/enhancer
sudo chown $USER:$USER /var/www/enhancer
cd /var/www/enhancer

echo "===== CLONING MAIN REPO ====="
git clone https://github.com/xinntao/Real-ESRGAN-ncnn-vulkan.git source
cd source

echo "===== FIXING SUBMODULE URLS (SSH → HTTPS) ====="

sed -i 's|git@github.com:webmproject/libwebp.git|https://github.com/webmproject/libwebp.git|' .gitmodules
sed -i 's|git@github.com:Tencent/ncnn.git|https://github.com/Tencent/ncnn.git|' .gitmodules

git submodule sync --recursive

git config submodule.src/libwebp.url https://github.com/webmproject/libwebp.git
git config submodule.src/ncnn.url https://github.com/Tencent/ncnn.git

echo "===== UPDATING SUBMODULES ====="
git submodule update --init --recursive

echo "===== BUILDING PROJECT ====="

mkdir -p build
cd build
cmake -DUSE_SYSTEM_VULKAN=ON -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

echo "===== INSTALLING BUILD OUTPUT ====="

cd /var/www/enhancer
mkdir -p realesrgan
cp source/build/realesrgan-ncnn-vulkan realesrgan/
cp -r source/src/models realesrgan/
chmod +x realesrgan/realesrgan-ncnn-vulkan

echo "===== CREATING ENHANCE SCRIPT ====="

cat << 'EOF' > enhance.sh
#!/bin/bash
INPUT="$1"
OUTPUT="$2"

/var/www/enhancer/realesrgan/realesrgan-ncnn-vulkan -i "$INPUT" -o "$OUTPUT" -s 4
EOF

chmod +x enhance.sh

echo "===== INSTALLING FLASK ====="
pip3 install flask

echo "===== CREATING FLASK BACKEND ====="

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

echo "===== CREATING FRONTEND ====="

cat << 'EOF' > templates/index.html
<!DOCTYPE html>
<html>
<head>
<title>AI Image Enhancer</title>
<style>
body { font-family: Arial; text-align: center; margin-top: 50px; }
.container {
    background: white; padding: 30px; width: 40%;
    margin: auto; border-radius: 10px;
}
button {
    padding: 10px 20px; background: #007bff; color: white;
    border: none; border-radius: 5px;
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

echo "===== CREATING SYSTEMD SERVICE ====="

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

echo "===== CONFIGURING NGINX ====="

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
echo "Access your enhancer: http://YOUR_SERVER_IP/"
