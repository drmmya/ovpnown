#!/bin/bash
set -e

EASYRSA_DIR="/etc/openvpn/easy-rsa"
SERVER_CONF="/etc/openvpn/server/server.conf"
AUTH_DIR="/etc/openvpn/auth"
USER_FILE="$AUTH_DIR/users.txt"
CHECK_SCRIPT="$AUTH_DIR/checkpsw.sh"
WEB_ROOT="/var/www/html"

# ---------------- ROOT CHECK ----------------
if [[ "$EUID" -ne 0 ]]; then
    echo "Run as root."
    exit 1
fi

# ---------------- GET IP ----------------
get_server_ip() {
    SERVER_IP=$(curl -s ifconfig.me || true)
    [[ -z "$SERVER_IP" ]] && SERVER_IP=$(hostname -I | awk '{print $1}')
}

# ---------------- USER AUTH SYSTEM ----------------
setup_auth_system() {
    mkdir -p "$AUTH_DIR"
    touch "$USER_FILE"

cat > "$CHECK_SCRIPT" <<'EOF'
#!/bin/bash
PASSFILE="/etc/openvpn/auth/users.txt"
USER="$1"
PASS="$2"
grep -w "$USER:$PASS" "$PASSFILE" >/dev/null && exit 0
exit 1
EOF

    chmod +x "$CHECK_SCRIPT"
}

# ---------------- ADD USER ----------------
add_user() {
    read -rp "Username: " u
    read -rp "Password: " p
    echo "$u:$p" >> "$USER_FILE"
    echo "User added."
}

# ---------------- REMOVE USER ----------------
remove_user() {
    read -rp "Remove username: " u
    sed -i "/^$u:/d" "$USER_FILE"
    echo "Removed."
}

# ---------------- SHOW USERS ----------------
list_users() {
    cut -d: -f1 "$USER_FILE"
}

# ---------------- SHOW CONNECTIONS ----------------
show_connections() {
    cat /var/log/openvpn-status.log || echo "No status log."
}

# ---------------- SHOW LOGS ----------------
show_logs() {
    journalctl -u openvpn-server@server --no-pager | tail -n 200
}

# ---------------- EASYRSA SERVER CERT ----------------
setup_easyrsa() {
    apt-get update
    apt-get install -y openvpn easy-rsa nginx iptables curl

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

# ---------------- SERVER CONFIG ----------------
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

verify-client-cert none
auth-user-pass-verify /etc/openvpn/auth/checkpsw.sh via-file
username-as-common-name

ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-crypt ta.key

push "redirect-gateway def1 bypass-dhcp"

push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"

data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC
data-ciphers-fallback AES-256-CBC

status /var/log/openvpn-status.log
verb 3
EOF
}

# ---------------- ROUTING (FIXES YOUR NO INTERNET ERROR) ----------------
setup_routing() {
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-openvpn.conf
    sysctl -p /etc/sysctl.d/99-openvpn.conf

    IFACE=$(ip route get 1.1.1.1 | awk '/dev/ {print $5}')
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE
    iptables -A FORWARD -i tun0 -o "$IFACE" -j ACCEPT
    iptables -A FORWARD -i "$IFACE" -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT

    iptables-save > /etc/iptables/rules.v4
}

# ---------------- START SERVICE ----------------
start_service() {
    systemctl enable --now openvpn-server@server
}

# ---------------- CREATE CLIENT ----------------
generate_client() {
cat > /root/client.ovpn <<EOF
client
dev tun
proto $PROTOCOL
remote $SERVER_IP $PORT
auth-user-pass
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
verb 3

<ca>
$(cat /etc/openvpn/server/ca.crt)
</ca>

<tls-crypt>
$(cat /etc/openvpn/server/ta.key)
</tls-crypt>
EOF

    mkdir -p "$WEB_ROOT"
    cp /root/client.ovpn "$WEB_ROOT/openvpn.ovpn"
}

# ---------------- WIPE EVERYTHING ----------------
wipe_all() {
    systemctl stop openvpn-server@server || true
    systemctl disable openvpn-server@server || true
    apt-get remove --purge -y openvpn easy-rsa nginx iptables-persistent || true
    rm -rf /etc/openvpn
    rm -rf "$WEB_ROOT/openvpn.ovpn"
    echo "All removed."
}

# ---------------- INSTALL ----------------
fresh_install() {
    get_server_ip

    echo "Protocol: 1) UDP  2) TCP"
    read -rp "Choice [1]: " ch
    [[ "$ch" == "2" ]] && PROTOCOL="tcp" || PROTOCOL="udp"

    read -rp "Port [1194]: " PORT
    PORT=${PORT:-1194}

    setup_auth_system
    setup_easyrsa
    write_server_conf
    setup_routing
    start_service
    generate_client

    echo "DONE. DOWNLOAD:"
    echo "http://$SERVER_IP/openvpn.ovpn"
}

# ---------------- MAIN MENU ----------------
if [[ ! -f "$SERVER_CONF" ]]; then
    fresh_install
    exit 0
fi

echo "1) Add User"
echo "2) Remove User"
echo "3) List Users"
echo "4) Show Connected"
echo "5) Logs"
echo "6) Remove Everything"
echo "7) Exit"
read -rp "Option: " O

case "$O" in
    1) add_user ;;
    2) remove_user ;;
    3) list_users ;;
    4) show_connections ;;
    5) show_logs ;;
    6) wipe_all ;;
    7) exit 0 ;;
esac
