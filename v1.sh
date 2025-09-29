#!/usr/bin/env bash
# openvpn-auth-installer-ubuntu22.sh
# Run on Ubuntu 22.04 as root (or sudo)
set -e
if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo $0"; exit 1
fi

ADMIN_USER=${1:-admin}    # pass admin username as first arg (default: admin)
ADMIN_PASS=${2:-adminpass} # pass admin password as second arg (default: adminpass) -> CHANGE

echo "[+] Updating OS..."
apt update -y && apt upgrade -y

echo "[+] Installing required packages..."
apt install -y openvpn easy-rsa python3 python3-venv python3-pip iptables-persistent nginx

# setup easy-rsa
echo "[+] Setting up Easy-RSA..."
make-cadir /etc/openvpn/easy-rsa
chown -R root:root /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa
./easyrsa init-pki
EASYRSA_BATCH=1 ./easyrsa build-ca nopass
EASYRSA_BATCH=1 ./easyrsa gen-dh
EASYRSA_BATCH=1 ./easyrsa build-server-full server nopass
openvpn --genkey --secret /etc/openvpn/ta.key

# copy artifacts
cp pki/ca.crt pki/issued/server.crt pki/private/server.key pki/dh.pem /etc/openvpn/
cp /etc/openvpn/ta.key /etc/openvpn/

# Server config (password-based auth; client-cert-not-required)
cat >/etc/openvpn/server.conf <<'EOF'
port 1194
proto udp
dev tun
# allow clients without certs (we use username/password)
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

# user/password verification via script (python)
script-security 3
auth-user-pass-verify /etc/openvpn/verify_creds.py via-env

# do not verify client certs (we allow password-only)
;crl-verify crl.pem
persist-key
persist-tun
status /var/log/openvpn-status.log
verb 3
EOF

# sysctl enable ip forwarding
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p

# Setup iptables NAT
IFACE=$(ip route get 8.8.8.8 | awk '{print $5}' | head -n1)
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE
netfilter-persistent save

# create credentials file (format: username:salt:hexhash)
mkdir -p /etc/openvpn
touch /etc/openvpn/creds.db
chown root:root /etc/openvpn/creds.db
chmod 600 /etc/openvpn/creds.db

# write the verify script (python)
cat >/etc/openvpn/verify_creds.py <<'PY'
#!/usr/bin/env python3
# verify_creds.py
import os, sys, hashlib, binascii

CRED_FILE = "/etc/openvpn/creds.db"

def pbkdf2_hash(password: str, salt: bytes, iterations=200000):
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    return binascii.hexlify(dk).decode()

def verify(username, password):
    if not os.path.exists(CRED_FILE):
        return False
    with open(CRED_FILE, 'r') as f:
        for line in f:
            line=line.strip()
            if not line: continue
            parts=line.split(':')
            if len(parts) != 3: continue
            u, salt_hex, hash_hex = parts
            if u == username:
                salt = binascii.unhexlify(salt_hex)
                h = pbkdf2_hash(password, salt)
                return h == hash_hex
    return False

if __name__ == "__main__":
    # OpenVPN with via-env provides username/password as environment variables:
    # username and password
    username = os.environ.get('username') or ''
    password = os.environ.get('password') or ''
    if verify(username, password):
        sys.exit(0)
    else:
        sys.exit(1)
PY
chmod 700 /etc/openvpn/verify_creds.py
chown root:root /etc/openvpn/verify_creds.py

echo "[+] Setting up admin panel (Flask)..."
# Create venv for admin app
python3 -m venv /opt/openvpn-admin/venv
/opt/openvpn-admin/venv/bin/pip install --upgrade pip
/opt/openvpn-admin/venv/bin/pip install flask werkzeug

# write admin app
cat >/opt/openvpn-admin/app.py <<'PYAPP'
# simple Flask admin for OpenVPN user management
from flask import Flask, request, Response, redirect, url_for, render_template_string, send_file
import os, binascii, hashlib

APP = Flask(__name__)
CRED_FILE = "/etc/openvpn/creds.db"
EASYRSA_PKI = "/etc/openvpn/easy-rsa/pki"
TA_KEY = "/etc/openvpn/ta.key"
SERVER_IP_CMD = "curl -s ifconfig.me || echo __SERVER_IP__"

# Basic templates
MAIN_TMPL = """
<h2>OpenVPN Admin</h2>
<p><a href="{{url_for('list_users')}}">List users</a> | <a href="{{url_for('add_user_form')}}">Add user</a></p>
"""

LIST_TMPL = """
<h2>Users</h2>
<ul>
{% for u in users %}
  <li>{{u}} - <a href="{{ url_for('remove_user', username=u) }}">Remove</a> - <a href="{{ url_for('get_ovpn', username=u) }}">Download .ovpn</a></li>
{% endfor %}
</ul>
<p><a href="{{ url_for('index') }}">Back</a></p>
"""

ADD_TMPL = """
<h2>Add user</h2>
<form method="post">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <button type="submit">Add</button>
</form>
<p><a href="{{ url_for('index') }}">Back</a></p>
"""

def pbkdf2_hash(password: str, salt: bytes, iterations=200000):
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    return binascii.hexlify(dk).decode()

def add_user_to_db(username, password):
    salt = os.urandom(16)
    h = pbkdf2_hash(password, salt)
    entry = f"{username}:{binascii.hexlify(salt).decode()}:{h}\\n"
    with open(CRED_FILE, "a") as f:
        f.write(entry)

def remove_user_from_db(username):
    if not os.path.exists(CRED_FILE): return
    lines=[]
    with open(CRED_FILE,'r') as f:
        for line in f:
            if not line.strip(): continue
            if line.split(':',1)[0] != username:
                lines.append(line)
    with open(CRED_FILE,'w') as f:
        f.writelines(lines)

def list_users():
    if not os.path.exists(CRED_FILE): return []
    users=[]
    with open(CRED_FILE,'r') as f:
        for line in f:
            if not line.strip(): continue
            users.append(line.split(':',1)[0])
    return users

def generate_ovpn(username):
    # Creates a simple client.ovpn that uses auth-user-pass (user must enter creds in client)
    server_ip = os.popen(SERVER_IP_CMD).read().strip()
    if not server_ip:
        server_ip="__SERVER_IP__"
    path = f"/tmp/{username}.ovpn"
    with open(path,'w') as f:
        f.write(f"""client
dev tun
proto udp
remote {server_ip} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
auth SHA256
cipher AES-256-GCM
remote-cert-tls server
key-direction 1
verb 3

<ca>
""")
        # append CA
        with open("/etc/openvpn/ca.crt",'r') as ca:
            f.write(ca.read())
        f.write("</ca>\n")
        # append tls-auth
        f.write("<tls-auth>\n")
        with open(TA_KEY,'r') as ta:
            f.write(ta.read())
        f.write("\n</tls-auth>\n")
    return path

# basic auth wrapper (very simple)
def check_auth(username, password):
    return username == os.environ.get("OPENVPN_ADMIN_USER") and password == os.environ.get("OPENVPN_ADMIN_PASS")

def authenticate():
    return Response('Login required', 401, {'WWW-Authenticate': 'Basic realm="Login"'})

from functools import wraps
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

@APP.route('/')
@requires_auth
def index():
    return render_template_string(MAIN_TMPL)

@APP.route('/users')
@requires_auth
def list_users_route():
    return render_template_string(LIST_TMPL, users=list_users())

@APP.route('/users/add', methods=['GET','POST'])
@requires_auth
def add_user_form():
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')
        if u and p:
            add_user_to_db(u,p)
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
    if username not in list_users():
        return "User not found", 404
    path = generate_ovpn(username)
    return send_file(path, as_attachment=True, download_name=f"{username}.ovpn")

if __name__ == "__main__":
    APP.run(host='0.0.0.0', port=8080)
PYAPP

# create env for admin credentials (you must change default!)
mkdir -p /opt/openvpn-admin
cat >/opt/openvpn-admin/.env <<ENV
OPENVPN_ADMIN_USER=${ADMIN_USER}
OPENVPN_ADMIN_PASS=${ADMIN_PASS}
ENV

chown -R root:root /opt/openvpn-admin
chmod 700 /opt/openvpn-admin

# create systemd service for admin app
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

systemctl daemon-reload
systemctl enable --now openvpn-admin.service

# enable and start openvpn
systemctl enable --now openvpn@server

echo "Done."
echo "OpenVPN running. Admin panel: http://<server-ip>:8080 (use credentials from /opt/openvpn-admin/.env)"
echo "IMPORTANT: change admin password and secure the admin panel with HTTPS (nginx reverse-proxy + certbot)."
