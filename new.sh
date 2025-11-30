#!/bin/bash
#
# OpenVPN Installer (Username/Password ONLY + Server Certificate)
# Auto .ovpn download at http://SERVER_IP/openvpn.ovpn
#

set -e

# DIRECTORIES
EASYRSA_DIR="/etc/openvpn/easy-rsa"
SERVER_CONF="/etc/openvpn/server/server.conf"
AUTH_DIR="/etc/openvpn/auth"
USER_FILE="$AUTH_DIR/users.txt"
CHECK_SCRIPT="$AUTH_DIR/checkpsw.sh"
WEB_ROOT="/var/www/html"

# ---------- ROOT CHECK ----------
require_root() {
    [[ "$EUID" -ne 0 ]] && { echo "Run as ROOT"; exit 1; }
}

# ---------- OS DETECT ----------
detect_os() {
    . /etc/os-release || exit 1
    [[ "$ID" == "ubuntu" || "$ID" == "debian" ]] || { echo "Debian/Ubuntu only"; exit 1; }
}

# ---------- IP DETECT ----------
get_server_ip() {
    SERVER_IP=$(curl -s ifconfig.me || true)
    [[ -z "$SERVER_IP" ]] && SERVER_IP=$(hostname -I | awk '{print $1}')
}

# ---------- AUTH SYSTEM ----------
setup_auth_system() {
    mkdir -p "$AUTH_DIR"

    # Credentials file
    [[ ! -f "$USER_FILE" ]] && touch "$USER_FILE"

    # Verification script
    cat > "$CHECK_SCRIPT" <<'EOF'
#!/bin/bash
PASSFILE="/etc/openvpn/auth/users.txt"
USER="$1"
PASS="$2"

VALID=$(grep -w "$USER:$PASS" "$PASSFILE" || true)

if [[ -n "$VALID" ]]; then
    exit 0
else
    exit 1
fi
EOF

    chmod +x "$CHECK_SCRIPT"
}

# ---------- ADD USER ----------
add_user() {
    read -rp "Enter username: " u
    read -rp "Enter password: " p
    echo "$u:$p" >> "$USER_FILE"
    echo "User added!"
}

# ---------- REMOVE USER ----------
remove_user() {
    read -rp "Remove username: " u
    sed -i "/^$u:/d" "$USER_FILE"
    echo "User removed."
}

# ---------- LIST USERS ----------
list_users() {
    echo "---- USER LIST ----"
    cut -d: -f1 "$USER_FILE"
}

# ---------- SHOW CONNECTED CLIENTS ----------
show_connected() {
    echo "---- CONNECTED CLIENTS ----"
    cat /var/log/openvpn-status.log || echo "Status file not found."
}

# ---------- SHOW LOGS ----------
show_logs() {
    journalctl -u openvpn-server@server --no-pager | tail -n 200
}

# ---------- NGINX DOWNLOAD ----------
setup_nginx_download() {
    OVPN_FILE="/root/client.ovpn"

    apt-get install -y nginx >/dev/null 2>&1
    systemctl enable --now nginx

    mkdir -p "$WEB_ROOT"
    cp "$OVPN_FILE" "$WEB_ROOT/openvpn.ovpn"
    chmod 644 "$WEB_ROOT/openvpn.ovpn"

    iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || \
        iptables -A INPUT -p tcp --dport 80 -j ACCEPT

    apt-get install -y iptables-persistent >/dev/null 2>&1 || true
    iptables-save > /etc/iptables/rules.v4 || true

    echo "Download config at: http://$SERVER_IP/openvpn.ovpn"
}

# ---------- EASYRSA / SERVER CERT ----------
setup_easyrsa() {
    apt-get update
    apt-get install -y openvpn easy-rsa iptables curl

    mkdir -p "$EASYRSA_DIR"
    cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR"

    cd "$EASYRSA_DIR"
    ./easyrsa init-pki
    ./easyrsa --batch build-ca nopass
    ./easyrsa --batch gen-req server nopass
    ./easyrsa --batch sign-req server server
    ./easyrsa gen-dh
    openvpn --genkey secret ta.key

    mkdir -p /etc/openvpn/server
    cp pki/ca.crt pki/issued/server.crt pki/private/server.key pki/dh.pem ta.key /etc/openvpn/server/
}

# ---------- SERVER CONFIG ----------
write_server_conf() {
cat > "$SERVER_CONF" <<EOF
port $PORT
proto $PROTOCOL
dev tun
user nobody
group nogroup

persist-key
persist-tun
keepalive 10 120
topology subnet

server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt

### AUTH ###
verify-client-cert none
auth-user-pass-verify /etc/openvpn/auth/checkpsw.sh via-file
username-as-common-name

### SERVER TLS ###
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-crypt ta.key

### ROUTE ALL TRAFFIC ###
push "redirect-gateway def1 bypass-dhcp"

### DNS ###
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"

### CIPHERS ###
data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC
data-ciphers-fallback AES-256-CBC

status /var/log/openvpn-status.log
verb 3
EOF
}

# ---------- FORWARDING ----------
enable_forwarding() {
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-openvpn.conf
    sysctl -p /etc/sysctl.d/99-openvpn.conf
}

# ---------- IPTABLES ----------
setup_iptables() {
    IFACE=$(ip route get 1.1.1.1 | awk '/dev/ {print $5}')
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE
    iptables -A FORWARD -i tun0 -o "$IFACE" -j ACCEPT
    iptables -A FORWARD -i "$IFACE" -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables-save > /etc/iptables/rules.v4
}

# ---------- START OPENVPN ----------
start_service() {
    systemctl enable --now openvpn-server@server
}

# ---------- GENERATE CLIENT CONFIG ----------
generate_client_ovpn() {
cat > /root/client.ovpn <<EOF
client
dev tun
proto $PROTOCOL
remote $SERVER_IP $PORT
auth-user-pass
cipher AES-256-CBC
auth SHA256
remote-cert-tls server
verb 3

<ca>
$(cat /etc/openvpn/server/ca.crt)
</ca>

<tls-crypt>
$(cat /etc/openvpn/server/ta.key)
</tls-crypt>
EOF
}

# ---------- WIPE ----------
wipe_all() {
    systemctl stop openvpn-server@server || true
    systemctl disable openvpn-server@server || true
    apt remove --purge -y openvpn easy-rsa nginx iptables-persistent || true
    rm -rf /etc/openvpn
    rm -rf "$WEB_ROOT/openvpn.ovpn"
    echo "Everything removed."
}

# ---------- INSTALL FLOW ----------
fresh_install() {
    echo "IP detected: $SERVER_IP"

    echo "1) UDP (recommended)"
    echo "2) TCP"
    read -rp "Protocol [1]: " p
    [[ "$p" == "2" ]] && PROTOCOL="tcp" || PROTOCOL="udp"

    read -rp "Port [1194]: " PORT
    PORT=${PORT:-1194}

    setup_auth_system
    setup_easyrsa
    write_server_conf
    enable_forwarding
    setup_iptables
    start_service
    generate_client_ovpn
    setup_nginx_download

    echo "INSTALL COMPLETE!"
}

# ---------- MAIN ----------
require_root
detect_os
get_server_ip

if [[ ! -f "$SERVER_CONF" ]]; then
    fresh_install
    exit 0
fi

clear
echo "OpenVPN is already installed."
echo "1) Add User"
echo "2) Remove User"
echo "3) List Users"
echo "4) Show Connected Clients"
echo "5) Show Logs"
echo "6) Remove EVERYTHING"
echo "7) Exit"
read -rp "Option: " O

case "$O" in
    1) add_user ;;
    2) remove_user ;;
    3) list_users ;;
    4) show_connected ;;
    5) show_logs ;;
    6) wipe_all ;;
    7) exit 0 ;;
    *) echo "Invalid option" ;;
esac
