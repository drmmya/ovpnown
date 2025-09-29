#!/usr/bin/env bash
# Ubuntu 22.04 Fresh OpenVPN Installer
set -e
if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo $0"; exit 1
fi

# ------------------------------
# 1️⃣ Clean previous installation
# ------------------------------
echo "[+] Removing previous OpenVPN and admin panel (if any)..."
systemctl stop openvpn@server || true
systemctl stop openvpn@server-tcp443 || true
systemctl stop openvpn-admin.service || true
systemctl disable openvpn@server || true
systemctl disable openvpn@server-tcp443 || true
systemctl disable openvpn-admin.service || true
rm -rf /etc/openvpn/easy-rsa /etc/openvpn/pki /etc/openvpn/*.conf /etc/openvpn/ta.key /etc/openvpn/creds.db
rm -rf /opt/openvpn-admin
rm -f /etc/systemd/system/openvpn-admin.service
iptables -t nat -F
netfilter-persistent save || true
ufw --force reset

# ------------------------------
# 2️⃣ Admin username & password
# ------------------------------
ADMIN_USER="openvpn"
ADMIN_PASS=$(tr -dc A-Z </dev/urandom | head -c2)$(shuf -i 100-999 -n1)
echo "[+] Admin username: $ADMIN_USER"
echo "[+] Admin password: $ADMIN_PASS"

# ------------------------------
# 3️⃣ Update OS and install packages
# ------------------------------
echo "[+] Updating OS and installing packages..."
apt update -y && apt upgrade -y
apt install -y openvpn easy-rsa python3 python3-venv python3-pip iptables-persistent nginx ufw curl

# ------------------------------
# 4️⃣ Easy-RSA & Certificates
# ------------------------------
echo "[+] Setting up Easy-RSA..."
make-cadir /etc/openvpn/easy-rsa
chown -R root:root /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa
./easyrsa init-pki
EASYRSA_BATCH=1 ./easyrsa build-ca nopass
EASYRSA_BATCH=1 ./easyrsa gen-dh
EASYRSA_BATCH=1 ./easyrsa build-server-full server nopass
openvpn --genkey --secret /etc/openvpn/ta.key

# Copy artifacts
cp pki/ca.crt pki/issued/server.crt pki/private/server.key pki/dh.pem /etc/openvpn/

# ------------------------------
# 5️⃣ OpenVPN Server Config
# ------------------------------
# UDP 1194
cat >/etc/openvpn/server.conf <<'EOF'
port 1194
proto udp
dev tun
client-cert-not-required
username-as-common-name
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh.pem
auth SHA256
tls-auth /etc/openvpn/ta.key 0
server 10.8.0.0 255.255.255.0
topology subnet
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
script-security 3
auth-user-pass-verify /etc/openvpn/verify_creds.py via-env
persist-key
persist-tun
status /var/log/openvpn-status.log
verb 3
EOF

# TCP 443
cat >/etc/openvpn/server-tcp443.conf <<'EOF'
port 443
proto tcp
dev tun
client-cert-not-required
username-as-common-name
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh.pem
auth SHA256
tls-auth /etc/openvpn/ta.key 0
server 10.8.1.0 255.255.255.0
topology subnet
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
script-security 3
auth-user-pass-verify /etc/openvpn/verify_creds.py via-env
persist-key
persist-tun
status /var/log/openvpn-status-tcp443.log
verb 3
EOF

# ------------------------------
# 6️⃣ Enable IP forwarding
# ------------------------------
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p

# ------------------------------
# 7️⃣ Firewall rules
# ------------------------------
IFACE=$(ip route get 8.8.8.8 | awk '{print $5}' | head -n1)
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o "$IFACE" -j MASQUERADE
netfilter-persistent save

ufw allow 1194/udp
ufw allow 443/tcp
ufw allow 943/tcp
ufw --force enable

# ------------------------------
# 8️⃣ Credentials DB & verify script
# ------------------------------
mkdir -p /etc/openvpn
touch /etc/openvpn/creds.db
chmod 600 /etc/openvpn/creds.db

cat >/etc/openvpn/verify_creds.py <<'PY'
#!/usr/bin/env python3
import os, hashlib, binascii
CRED_FILE = "/etc/openvpn/creds.db"

def pbkdf2_hash(password: str, salt: bytes, iterations=200000):
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    return binascii.hexlify(dk).decode()

def verify(username, password):
    if not os.path.exists(CRED_FILE):
        return False
    with open(CRED_FILE,'r') as f:
        for line in f:
            line=line.strip()
            if not line: continue
            parts=line.split(':')
            if len(parts)!=3: continue
            u,salt_hex,h=parts
            if u==username:
                salt=binascii.unhexlify(salt_hex)
                return pbkdf2_hash(password,salt)==h
    return False

if __name__=="__main__":
    username=os.environ.get('username') or ''
    password=os.environ.get('password') or ''
    exit(0) if verify(username,password) else exit(1)
PY
chmod 700 /etc/openvpn/verify_creds.py

# ------------------------------
# 9️⃣ Flask Admin Panel
# ------------------------------
mkdir -p /opt/openvpn-admin
python3 -m venv /opt/openvpn-admin/venv
/opt/openvpn-admin/venv/bin/pip install --upgrade pip
/opt/openvpn-admin/venv/bin/pip install flask werkzeug

# Flask app
cat >/opt/openvpn-admin/app.py <<'PYAPP'
from flask import Flask, request, Response, redirect, url_for, render_template_string, send_file
import os, binascii, hashlib
APP=Flask(__name__)
CRED_FILE="/etc/openvpn/creds.db"
TA_KEY="/etc/openvpn/ta.key"

MAIN_TMPL="<h2>OpenVPN Admin</h2><p><a href='{{url_for(\"list_users_route\")}}'>List users</a> | <a href='{{url_for(\"add_user_form\")}}'>Add user</a></p>"
LIST_TMPL="<h2>Users</h2>{% for u in users %}<li>{{u}} - <a href='{{ url_for(\"remove_user\", username=u) }}'>Remove</a> - <a href='{{ url_for(\"get_ovpn\", username=u) }}'>Download .ovpn</a></li>{% endfor %}<p><a href='{{ url_for(\"index\") }}'>Back</a></p>"
ADD_TMPL="<h2>Add user</h2><form method='post'>Username: <input name='username'><br>Password: <input name='password' type='password'><br><button type='submit'>Add</button></form><p><a href='{{ url_for(\"index\") }}'>Back</a></p>"

def pbkdf2_hash(password,salt,iterations=200000):
    dk=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,iterations)
    return binascii.hexlify(dk).decode()

def add_user_to_db(username,password):
    salt=os.urandom(16)
    h=pbkdf2_hash(password,salt)
    with open(CRED_FILE,"a") as f:
        f.write(f"{username}:{binascii.hexlify(salt).decode()}:{h}\n")

def remove_user_from_db(username):
    if not os.path.exists(CRED_FILE): return
    lines=[]
    with open(CRED_FILE,'r') as f:
        for line in f:
            if not line.strip(): continue
            if line.split(':',1)[0]!=username:
                lines.append(line)
    with open(CRED_FILE,'w') as f: f.writelines(lines)

def list_users(): return [line.split(':',1)[0] for line in open(CRED_FILE).readlines() if line.strip()]

def generate_ovpn(username):
    server_ip=os.popen("curl -s ifconfig.me || echo __SERVER_IP__").read().strip()
    path=f"/tmp/{username}.ovpn"
    with open(path,'w') as f:
        f.write(f"client\ndev tun\nproto udp\nremote {server_ip} 1194\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\nauth SHA256\ncipher AES-256-GCM\nremote-cert-tls server\nkey-direction 1\nverb 3\n<ca>\n")
        f.write(open("/etc/openvpn/ca.crt").read())
        f.write("</ca>\n<tls-auth>\n"+open(TA_KEY).read()+"\n</tls-auth>\n")
    return path

def check_auth(u,p): return u==os.environ.get("OPENVPN_ADMIN_USER") and p==os.environ.get("OPENVPN_ADMIN_PASS")
def authenticate(): return Response('Login required',401,{'WWW-Authenticate':'Basic realm="Login"'})
from functools import wraps
def requires_auth(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        auth=request.authorization
        if not auth or not check_auth(auth.username,auth.password): return authenticate()
        return f(*args,**kwargs)
    return decorated

@APP.route('/')
@requires_auth
def index(): return render_template_string(MAIN_TMPL)

@APP.route('/users')
@requires_auth
def list_users_route(): return render_template_string(LIST_TMPL, users=list_users())

@APP.route('/users/add', methods=['GET','POST'])
@requires_auth
def add_user_form():
    if request.method=='POST':
        u=request.form.get('username')
        p=request.form.get('password')
        if u and p: add_user_to_db(u,p)
        return redirect(url_for('list_users_route'))
    return render_template_string(ADD_TMPL)

@APP.route('/users/remove/<username>')
@requires_auth
def remove_user(username):
    remove_user_from_db(username)
    return redirect(url_for('list_users_route'))

@APP.route('/users/ovpn/<username>')
@requires_auth
def get_ovpn(username):
    if username not in list_users(): return "User not found",404
    return send_file(generate_ovpn(username), as_attachment=True, download_name=f"{username}.ovpn")

if __name__=="__main__":
    APP.run(host='0.0.0.0', port=943)
PYAPP

# ------------------------------
# 10️⃣ Admin environment
# ------------------------------
cat >/opt/openvpn-admin/.env <<ENV
OPENVPN_ADMIN_USER=${ADMIN_USER}
OPENVPN_ADMIN_PASS=${ADMIN_PASS}
ENV

chmod 700 /opt/openvpn-admin/.env
chown -R root:root /opt/openvpn-admin

# ------------------------------
# 11️⃣ Systemd service
# ------------------------------
cat >/etc/systemd/system/openvpn-admin.service <<'UNIT'
[Unit]
Description=OpenVPN Admin Flask App
After=network.target

[Service]
User=root
EnvironmentFile=/opt/openvpn-admin/.env
WorkingDirectory=/opt/openvpn-admin
ExecStart=/opt/openvpn-admin/venv/bin/python /opt/openvpn-admin/app.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

# ------------------------------
# 12️⃣ Enable services
# ------------------------------
systemctl daemon-reload
systemctl enable --now openvpn-admin.service
systemctl enable --now openvpn@server
systemctl enable --now openvpn@server-tcp443

echo "✅ Fresh installation complete!"
echo "Admin panel: http://<server-ip>:943"
echo "Admin username: $ADMIN_USER"
echo "Admin password: $ADMIN_PASS"
echo "OpenVPN server UDP 1194 & TCP 443 running"
