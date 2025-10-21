#!/usr/bin/env bash
set -euo pipefail

# =========================
# OpenVPN One-Click Installer for Ubuntu 22.04
# - Fresh install or full re-install
# - UDP 1194 + TCP 443
# - Hostname-based clients
# - Simple web admin panel on :8080
# =========================

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Please run as root: sudo bash $0"
    exit 1
  fi
}

banner() {
  echo "=============================================="
  echo "     OpenVPN One-Click (Ubuntu 22.04)"
  echo "=============================================="
}

prompt_inputs() {
  read -rp "Enter VPN hostname (e.g. vpn.example.com): " OVPN_HOSTNAME
  while [[ -z "${OVPN_HOSTNAME}" ]]; do
    read -rp "Hostname cannot be empty. Enter VPN hostname: " OVPN_HOSTNAME
  done

  read -rp "Create admin username for web panel: " ADMIN_USER
  while [[ -z "${ADMIN_USER}" ]]; do
    read -rp "Admin username cannot be empty. Enter admin username: " ADMIN_USER
  done

  read -rsp "Create admin password for web panel: " ADMIN_PASS
  echo
  while [[ -z "${ADMIN_PASS}" ]]; do
    read -rsp "Admin password cannot be empty. Enter admin password: " ADMIN_PASS
    echo
  done
}

purge_existing_if_any() {
  if systemctl list-unit-files | grep -qE '^openvpn-server@'; then
    echo "[i] Existing OpenVPN installation detected. Re-installing fresh..."
    systemctl stop "openvpn-server@"* 2>/dev/null || true
  fi

  # Purge OpenVPN & EasyRSA if installed
  if dpkg -s openvpn >/dev/null 2>&1 || dpkg -s easy-rsa >/dev/null 2>&1; then
    apt-get remove --purge -y openvpn easy-rsa || true
    apt-get autoremove -y || true
  fi

  rm -rf /etc/openvpn /var/log/openvpn /etc/systemd/system/openvpn* || true
}

install_packages() {
  echo "[i] Installing dependencies..."
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    openvpn easy-rsa iptables-persistent \
    python3 python3-venv python3-pip
  mkdir -p /var/log/openvpn
}

setup_easy_rsa_and_pki() {
  echo "[i] Setting up Easy-RSA PKI..."
  mkdir -p /etc/openvpn/easy-rsa
  cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/
  cd /etc/openvpn/easy-rsa

  ./easyrsa init-pki
  # Build a non-password CA
  yes "" | ./easyrsa build-ca nopass

  # Server certificates
  ./easyrsa gen-dh
  ./easyrsa build-server-full server nopass

  # Default client (you can add more later)
  ./easyrsa build-client-full client1 nopass

  # tls-crypt key for extra protection
  openvpn --genkey --secret /etc/openvpn/easy-rsa/pki/ta.key
}

enable_ip_forwarding_and_nat() {
  echo "[i] Enabling IP forwarding & NAT..."
  sed -i 's/^#\?net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
  sysctl -p

  # Set up basic NAT (assumes default interface as the first non-loopback)
  IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
  iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE
  iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o "$IFACE" -j MASQUERADE

  netfilter-persistent save
}

write_server_confs() {
  echo "[i] Writing OpenVPN server configs..."

  # UDP server on 1194
  mkdir -p /etc/openvpn/server
  cat >/etc/openvpn/server/server.conf <<'EOF'
port 1194
proto udp
dev tun
user nobody
group nogroup
topology subnet
server 10.8.0.0 255.255.255.0
persist-key
persist-tun
keepalive 10 120
duplicate-cn
cipher AES-256-GCM
ncp-ciphers AES-256-GCM:AES-128-GCM
data-ciphers AES-256-GCM
data-ciphers-fallback AES-256-GCM
remote-cert-tls client
dh /etc/openvpn/easy-rsa/pki/dh.pem
ca /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/server.crt
key /etc/openvpn/easy-rsa/pki/private/server.key
tls-crypt /etc/openvpn/easy-rsa/pki/ta.key
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
status /var/log/openvpn/status-udp.log
verb 3
explicit-exit-notify 1
EOF

  # TCP server on 443
  cat >/etc/openvpn/server/server-tcp.conf <<'EOF'
port 443
proto tcp
dev tun
user nobody
group nogroup
topology subnet
server 10.9.0.0 255.255.255.0
persist-key
persist-tun
keepalive 10 120
duplicate-cn
cipher AES-256-GCM
ncp-ciphers AES-256-GCM:AES-128-GCM
data-ciphers AES-256-GCM
data-ciphers-fallback AES-256-GCM
remote-cert-tls client
dh /etc/openvpn/easy-rsa/pki/dh.pem
ca /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/server.crt
key /etc/openvpn/easy-rsa/pki/private/server.key
tls-crypt /etc/openvpn/easy-rsa/pki/ta.key
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
status /var/log/openvpn/status-tcp.log
verb 3
EOF
}

enable_services() {
  echo "[i] Enabling & starting OpenVPN services..."
  systemctl daemon-reload
  systemctl enable --now openvpn-server@server.service
  systemctl enable --now openvpn-server@server-tcp.service
  sleep 2
  systemctl status openvpn-server@server.service --no-pager || true
  systemctl status openvpn-server@server-tcp.service --no-pager || true
}

generate_client_configs() {
  echo "[i] Generating client OVPN profiles..."

  local HOST="$1"
  local OUTDIR="/root"
  local EASY="/etc/openvpn/easy-rsa/pki"

  # UDP profile
  cat >"${OUTDIR}/client-udp.ovpn" <<EOF
client
dev tun
proto udp
remote ${HOST} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
verb 3
key-direction 1
<ca>
$(cat ${EASY}/ca.crt)
</ca>
<cert>
$(awk '/BEGIN/,/END/' ${EASY}/issued/client1.crt)
</cert>
<key>
$(cat ${EASY}/private/client1.key)
</key>
<tls-crypt>
$(cat ${EASY}/ta.key)
</tls-crypt>
EOF

  # TCP profile
  cat >"${OUTDIR}/client-tcp.ovpn" <<EOF
client
dev tun
proto tcp
remote ${HOST} 443
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
verb 3
key-direction 1
<ca>
$(cat ${EASY}/ca.crt)
</ca>
<cert>
$(awk '/BEGIN/,/END/' ${EASY}/issued/client1.crt)
</cert>
<key>
$(cat ${EASY}/private/client1.key)
</key>
<tls-crypt>
$(cat ${EASY}/ta.key)
</tls-crypt>
EOF

  chmod 600 "${OUTDIR}/client-"*.ovpn
  echo "[i] Created:"
  echo "    ${OUTDIR}/client-udp.ovpn"
  echo "    ${OUTDIR}/client-tcp.ovpn"
}

install_web_admin() {
  echo "[i] Installing simple web admin panel (Flask) on :8080 ..."
  local APPDIR="/opt/ovpn-admin"
  mkdir -p "$APPDIR"
  python3 -m venv "${APPDIR}/venv"
  "${APPDIR}/venv/bin/pip" install --upgrade pip
  "${APPDIR}/venv/bin/pip" install flask waitress

  # Write Flask app
  cat >"${APPDIR}/app.py" <<'PYAPP'
import os
import subprocess
from flask import Flask, request, Response, render_template_string, redirect, url_for
from datetime import datetime

ADMIN_USER = os.environ.get("OVPN_ADMIN_USER", "")
ADMIN_PASS = os.environ.get("OVPN_ADMIN_PASS", "")

STATUS_UDP = "/var/log/openvpn/status-udp.log"
STATUS_TCP = "/var/log/openvpn/status-tcp.log"

TEMPLATE = """
<!doctype html>
<title>OpenVPN Admin</title>
<h2>OpenVPN Admin Panel</h2>
<p>Time: {{ now }}</p>
<h3>Status (UDP 1194)</h3>
<pre style="max-height:300px;overflow:auto">{{ udp }}</pre>
<h3>Status (TCP 443)</h3>
<pre style="max-height:300px;overflow:auto">{{ tcp }}</pre>
<form method="post" action="/restart">
  <button name="svc" value="udp">Restart UDP</button>
  <button name="svc" value="tcp">Restart TCP</button>
</form>
"""

app = Flask(__name__)

def check_auth(username, password):
    return username == ADMIN_USER and password == ADMIN_PASS

def authenticate():
    return Response(
        "Authentication required", 401,
        {"WWW-Authenticate": 'Basic realm="Login Required"'}
    )

def requires_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def read_file(path):
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception as e:
        return f"(No data: {e})"

@app.route("/")
@requires_auth
def index():
    udp = read_file(STATUS_UDP)
    tcp = read_file(STATUS_TCP)
    return render_template_string(TEMPLATE, now=str(datetime.utcnow())+" UTC", udp=udp, tcp=tcp)

@app.route("/restart", methods=["POST"])
@requires_auth
def restart():
    svc = request.form.get("svc", "")
    if svc == "udp":
        cmd = ["systemctl", "restart", "openvpn-server@server.service"]
    elif svc == "tcp":
        cmd = ["systemctl", "restart", "openvpn-server@server-tcp.service"]
    else:
        return redirect(url_for("index"))
    try:
        subprocess.run(cmd, check=True)
    except Exception as e:
        return f"Restart failed: {e}", 500
    return redirect(url_for("index"))
PYAPP

  # Systemd service (runs as root; keep closed on trusted networks or reverse proxy behind HTTPS)
  cat > /etc/systemd/system/ovpn-admin.service <<'SYSD'
[Unit]
Description=OpenVPN Simple Admin Panel
After=network.target

[Service]
Type=simple
Environment=OVPN_ADMIN_USER=
Environment=OVPN_ADMIN_PASS=
WorkingDirectory=/opt/ovpn-admin
ExecStart=/opt/ovpn-admin/venv/bin/waitress-serve --host=0.0.0.0 --port=8080 app:app
Restart=always

[Install]
WantedBy=multi-user.target
SYSD
}

configure_admin_credentials() {
  # inject env vars into service
  sed -i "s|Environment=OVPN_ADMIN_USER=.*|Environment=OVPN_ADMIN_USER=${ADMIN_USER}|" /etc/systemd/system/ovpn-admin.service
  sed -i "s|Environment=OVPN_ADMIN_PASS=.*|Environment=OVPN_ADMIN_PASS=${ADMIN_PASS}|" /etc/systemd/system/ovpn-admin.service
  systemctl daemon-reload
  systemctl enable --now ovpn-admin.service
}

summary() {
  echo
  echo "==================== SUMMARY ===================="
  echo " Hostname:           ${OVPN_HOSTNAME}"
  echo " UDP server:         1194/udp  (status: /var/log/openvpn/status-udp.log)"
  echo " TCP server:         443/tcp   (status: /var/log/openvpn/status-tcp.log)"
  echo " Admin panel:        http://$(hostname -I | awk '{print $1}'):8080"
  echo " Admin login:        ${ADMIN_USER} / (your password)"
  echo " Client files:       /root/client-udp.ovpn , /root/client-tcp.ovpn"
  echo "================================================="
  echo
}

main() {
  require_root
  banner
  prompt_inputs
  purge_existing_if_any
  install_packages
  setup_easy_rsa_and_pki
  write_server_confs
  enable_ip_forwarding_and_nat
  enable_services
  generate_client_configs "${OVPN_HOSTNAME}"
  install_web_admin
  configure_admin_credentials
  summary
}

main "$@"
