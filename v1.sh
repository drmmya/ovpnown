#!/bin/bash
#
# Simple OpenVPN installer (Debian/Ubuntu)
# With auto .ovpn download at http://SERVER_IP/openvpn.ovpn
# 2025 FULLY FIXED VERSION (NGINX, UFW, APACHE, PORTS)
#

set -e

EASYRSA_DIR="/etc/openvpn/easy-rsa"
SERVER_CONF="/etc/openvpn/server/server.conf"
WEB_ROOT="/var/www/html"

############################################
# ROOT CHECK
############################################
require_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "This installer must be run as root."
        exit 1
    fi
}

############################################
# OS DETECT
############################################
detect_os() {
    if [[ -e /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" == "ubuntu" || "$ID" == "debian" ]]; then
            OS="debian"
        else
            echo "This script only supports Debian/Ubuntu."
            exit 1
        fi
    else
        echo "This script only supports Debian/Ubuntu."
        exit 1
    fi
}

############################################
# GET SERVER IP
############################################
get_server_ip() {
    SERVER_IP=$(curl -s --max-time 5 ifconfig.me || echo "")
    [[ -z "$SERVER_IP" ]] && SERVER_IP=$(hostname -I | awk '{print $1}')
}

press_any_key() {
    read -n1 -r -p "Press any key to continue..." key
    echo
}

############################################
# NGINX AUTO FIX + DOWNLOAD READY
############################################
setup_nginx_and_download() {
    local client_name="$1"
    local ovpn_file="/root/${client_name}.ovpn"

    if [[ ! -f "$ovpn_file" ]]; then
        echo "ERROR: Client file $ovpn_file not found!"
        return
    fi

    echo "Installing nginx..."
    apt-get install -y nginx >/dev/null 2>&1 || true

    # FIX: Stop Apache if running (port 80 conflict)
    systemctl stop apache2 2>/dev/null || true
    systemctl disable apache2 2>/dev/null || true

    systemctl enable --now nginx >/dev/null 2>&1

    mkdir -p "$WEB_ROOT"
    cp "$ovpn_file" "$WEB_ROOT/openvpn.ovpn"
    chmod 644 "$WEB_ROOT/openvpn.ovpn"

    # OPEN FIREWALL PORTS
    ufw allow 80/tcp || true
    ufw allow 443/tcp || true

    get_server_ip

    echo
    echo "=============================================="
    echo " Download your OpenVPN config here:"
    echo "   http://${SERVER_IP}/openvpn.ovpn"
    echo "=============================================="
    echo
}

############################################
# EASYRSA / PKI
############################################
setup_easyrsa() {
    echo "Installing OpenVPN + Easy-RSA + iptables..."
    apt-get update
    apt-get install -y openvpn easy-rsa iptables curl iptables-persistent

    mkdir -p "$EASYRSA_DIR"
    cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR"/ 2>/dev/null || true

    cd "$EASYRSA_DIR"
    ./easyrsa init-pki
    ./easyrsa --batch build-ca nopass
    ./easyrsa gen-dh
    ./easyrsa --batch build-server-full server nopass
    ./easyrsa --batch build-client-full "$CLIENT_NAME" nopass
    ./easyrsa gen-crl

    openvpn --genkey secret "$EASYRSA_DIR/ta.key"

    mkdir -p /etc/openvpn/server

    cp pki/ca.crt /etc/openvpn/server/
    cp pki/issued/server.crt /etc/openvpn/server/
    cp pki/private/server.key /etc/openvpn/server/
    cp pki/dh.pem /etc/openvpn/server/dh.pem
    cp ta.key /etc/openvpn/server/ta.key
    cp pki/crl.pem /etc/openvpn/server/crl.pem

    chown nobody:nogroup /etc/openvpn/server/crl.pem
}

############################################
# SERVER CONFIG
############################################
write_server_conf() {
cat > "$SERVER_CONF" <<EOF
port ${PORT}
proto ${PROTOCOL}
dev tun
user nobody
group nogroup
persist-key
persist-tun
keepalive 10 120
topology subnet

server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt

ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-crypt ta.key

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"

crl-verify crl.pem
status /var/log/openvpn-status.log
verb 3
EOF
}

############################################
# ENABLE IP FORWARDING
############################################
enable_ip_forwarding() {
    echo "Enabling IP forwarding..."
    sed -i '/^net.ipv4.ip_forward/d' /etc/sysctl.conf
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p >/dev/null
}

############################################
# IPTABLES AUTO FIX
############################################
setup_iptables() {
    echo "Configuring iptables (simple NAT)..."

    IFACE=$(ip route get 1.1.1.1 | awk '{print $5}')

    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE
    iptables -A INPUT -p "$PROTOCOL" --dport "$PORT" -j ACCEPT
    iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

    iptables-save > /etc/iptables/rules.v4
}

############################################
# START OPENVPN SERVICE
############################################
start_openvpn_service() {
    systemctl enable --now openvpn-server@server.service
}

############################################
# CLIENT GENERATION
############################################
generate_client_ovpn() {
    local client_name="$1"
    local client_ovpn="/root/${client_name}.ovpn"

    get_server_ip

cat > "$client_ovpn" <<EOF
client
dev tun
proto ${PROTOCOL}
remote ${SERVER_IP} ${PORT}
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher AES-256-CBC
verb 3
key-direction 1

<ca>
$(cat $EASYRSA_DIR/pki/ca.crt)
</ca>

<cert>
$(awk '/BEGIN CERTIFICATE/{flag=1} flag{print} /END CERTIFICATE/{flag=0}' $EASYRSA_DIR/pki/issued/${client_name}.crt)
</cert>

<key>
$(cat $EASYRSA_DIR/pki/private/${client_name}.key)
</key>

<tls-crypt>
$(cat $EASYRSA_DIR/ta.key)
</tls-crypt>
EOF

    echo "Client config saved: $client_ovpn"
    setup_nginx_and_download "$client_name"
}

############################################
# MAIN INSTALL
############################################
fresh_install() {
    echo "Welcome to OpenVPN Auto Installer (2025 FIXED)."
    echo

    get_server_ip
    echo "Detected server IP: $SERVER_IP"
    echo

    echo "1) UDP (recommended)"
    echo "2) TCP"
    read -rp "Protocol [1]: " proto
    [[ "$proto" == "2" ]] && PROTOCOL="tcp" || PROTOCOL="udp"

    read -rp "Port [1194]: " port
    PORT=${port:-1194}

    read -rp "Client name [client]: " cname
    CLIENT_NAME=${cname:-client}
    CLIENT_NAME=$(echo "$CLIENT_NAME" | sed 's/[^0-9A-Za-z_-]/_/g')

    press_any_key

    setup_easyrsa
    write_server_conf
    enable_ip_forwarding
    setup_iptables
    start_openvpn_service
    generate_client_ovpn "$CLIENT_NAME"

    echo "Installation finished!"
}

############################################
# MAIN MENU IF ALREADY INSTALLED
############################################
add_client() {
    read -rp "New client name: " cname
    CLIENT_NAME=$(echo "$cname" | sed 's/[^0-9A-Za-z_-]/_/g')

    cd "$EASYRSA_DIR"
    ./easyrsa --batch build-client-full "$CLIENT_NAME" nopass
    generate_client_ovpn "$CLIENT_NAME"
}

revoke_client() {
    cd "$EASYRSA_DIR"
    awk '/^V/{print NR") "$NF}' pki/index.txt
    read -rp "Client number: " n

    CLIENT_CN=$(awk -v n="$n" '/^V/{c++; if(c==n) print $NF}' pki/index.txt)
    ./easyrsa --batch revoke "$CLIENT_CN"
    ./easyrsa gen-crl
    cp pki/crl.pem /etc/openvpn/server/crl.pem
    systemctl restart openvpn-server@server.service
    echo "Client revoked: $CLIENT_CN"
}

uninstall_openvpn() {
    read -rp "Remove OpenVPN? [y/N]: " ans
    [[ "$ans" != "y" ]] && exit 0

    systemctl stop openvpn-server@server.service || true
    apt-get remove --purge -y openvpn easy-rsa || true
    rm -rf /etc/openvpn
    echo "OpenVPN removed."
}

############################################
# START SCRIPT
############################################

require_root
detect_os

if [[ ! -f "$SERVER_CONF" ]]; then
    fresh_install
    exit 0
fi

echo "OpenVPN is already installed."
echo "1) Add client"
echo "2) Revoke client"
echo "3) Remove OpenVPN"
echo "4) Exit"
read -rp "Option: " opt

case "$opt" in
    1) add_client ;;
    2) revoke_client ;;
    3) uninstall_openvpn ;;
    4) exit 0 ;;
    *) echo "Invalid option" ;;
esac
