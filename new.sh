#!/bin/bash
#
# Simple OpenVPN + EasyRSA + Nginx installer (Debian/Ubuntu)
# 2025 FIXED VERSION – proper client certs, tls-auth, NAT, download via http://IP/openvpn.ovpn
#

EASYRSA_DIR="/etc/openvpn/easy-rsa"
SERVER_DIR="/etc/openvpn/server"
SERVER_CONF="$SERVER_DIR/server.conf"
WEB_ROOT="/var/www/html"

# --------- Helpers ---------

require_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "This installer must be run as root. Use: sudo bash v1.sh"
        exit 1
    fi
}

detect_os() {
    if [[ -e /etc/os-release ]]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian) OS="debian" ;;
            *) echo "This script only supports Debian/Ubuntu."; exit 1 ;;
        esac
    else
        echo "This script only supports Debian/Ubuntu."
        exit 1
    fi
}

get_ip() {
    # Try public IP first; fallback to first local IP
    if command -v curl >/dev/null 2>&1; then
        SERVER_IP=$(curl -s ifconfig.me || curl -s ipinfo.io/ip || true)
    fi
    if [[ -z "$SERVER_IP" ]]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi
}

pause_key() {
    read -n1 -r -p "Press any key to continue..." key
    echo
}

# --------- Firewall / NAT ---------

enable_ip_forward() {
    echo "Enabling IPv4 forwarding..."
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-openvpn-forward.conf
    sysctl -p /etc/sysctl.d/99-openvpn-forward.conf >/dev/null
}

setup_iptables_nat() {
    echo "Configuring iptables NAT rules..."
    local iface
    iface=$(ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)

    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$iface" -j MASQUERADE
    iptables -A INPUT -p "$PROTOCOL" --dport "$PORT" -j ACCEPT
    iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

    # Persist rules
    apt-get install -y iptables-persistent >/dev/null 2>&1 || true
    iptables-save > /etc/iptables/rules.v4
}

setup_ufw_ports() {
    if command -v ufw >/dev/null 2>&1; then
        if ! ufw status | grep -q "Status: active"; then
            echo "Enabling UFW firewall..."
            ufw --force enable
        fi
        ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp >/dev/null 2>&1
        ufw allow 80/tcp  >/dev/null 2>&1
        ufw allow 443/tcp >/dev/null 2>&1
        ufw allow "$PORT"/"$PROTOCOL" >/dev/null 2>&1
    fi
}

# --------- Nginx for .ovpn download ---------

setup_nginx() {
    echo "Installing nginx (for .ovpn download)..."
    apt-get install -y nginx >/dev/null 2>&1 || true
    systemctl enable --now nginx >/dev/null 2>&1 || true
    mkdir -p "$WEB_ROOT"
}

publish_ovpn() {
    local client="$1"
    local src="/root/${client}.ovpn"
    if [[ ! -f "$src" ]]; then
        echo "WARNING: $src not found, cannot publish."
        return
    fi
    cp "$src" "$WEB_ROOT/openvpn.ovpn"
    chmod 644 "$WEB_ROOT/openvpn.ovpn"
    get_ip
    echo
    echo "=============================================="
    echo " Download your OpenVPN config at:"
    echo "   http://${SERVER_IP}/openvpn.ovpn"
    echo "=============================================="
    echo
}

# --------- EasyRSA / PKI ---------

install_openvpn_easyrsa() {
    echo "Installing OpenVPN + Easy-RSA..."
    apt-get update
    apt-get install -y openvpn easy-rsa curl
}

init_easyrsa_pki() {
    mkdir -p "$EASYRSA_DIR"
    if [[ ! -f "$EASYRSA_DIR/easyrsa" ]]; then
        cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR"/
    fi

    cd "$EASYRSA_DIR"
    ./easyrsa init-pki

    # Simple non-interactive defaults (edit if you want)
    cat > vars <<EOF
set_var EASYRSA_REQ_COUNTRY    "BD"
set_var EASYRSA_REQ_PROVINCE   "Dhaka"
set_var EASYRSA_REQ_CITY       "Dhaka"
set_var EASYRSA_REQ_ORG        "OpenVPN"
set_var EASYRSA_REQ_EMAIL      "vpn@example.com"
set_var EASYRSA_REQ_OU         "Community"
EOF

    # Build CA, server & first client, DH, CRL
    ./easyrsa --batch build-ca nopass
    ./easyrsa --batch gen-req server nopass
    ./easyrsa --batch sign-req server server
    ./easyrsa --batch gen-dh
    ./easyrsa --batch gen-crl
    ./easyrsa --batch gen-req "$CLIENT_NAME" nopass
    ./easyrsa --batch sign-req client "$CLIENT_NAME"
}

copy_server_files() {
    mkdir -p "$SERVER_DIR"
    cd "$EASYRSA_DIR"

    cp pki/ca.crt                    "$SERVER_DIR/"
    cp pki/issued/server.crt         "$SERVER_DIR/"
    cp pki/private/server.key        "$SERVER_DIR/"
    cp pki/dh.pem                    "$SERVER_DIR/dh.pem"
    cp pki/crl.pem                   "$SERVER_DIR/crl.pem"

    # tls-auth key
    openvpn --genkey secret "$SERVER_DIR/ta.key"

    chown nobody:nogroup "$SERVER_DIR/crl.pem"
}

# --------- Server config ---------

write_server_conf() {
    cat > "$SERVER_CONF" <<EOF
port ${PORT}
proto ${PROTOCOL}
dev tun

ca ca.crt
cert server.crt
key server.key
dh dh.pem

auth SHA256
cipher AES-256-CBC

tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"

keepalive 10 120
persist-key
persist-tun

user nobody
group nogroup

crl-verify crl.pem
status /var/log/openvpn-status.log
verb 3
explicit-exit-notify 1
EOF
}

start_openvpn() {
    systemctl enable --now openvpn-server@server.service
}

# --------- Client config ---------

build_client_ovpn() {
    local client="$1"
    local out="/root/${client}.ovpn"

    local ca_cert="$SERVER_DIR/ca.crt"
    local tls_key="$SERVER_DIR/ta.key"
    local client_crt="$EASYRSA_DIR/pki/issued/${client}.crt"
    local client_key="$EASYRSA_DIR/pki/private/${client}.key"

    if [[ ! -f "$ca_cert" || ! -f "$client_crt" || ! -f "$client_key" || ! -f "$tls_key" ]]; then
        echo "ERROR: Missing cert/key files for client $client"
        exit 1
    fi

    get_ip

    cat > "$out" <<EOF
client
dev tun
proto ${PROTOCOL}
remote ${SERVER_IP} ${PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher AES-256-CBC
verb 3
key-direction 1

<ca>
$(cat "$ca_cert")
</ca>

<cert>
$(sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' "$client_crt")
</cert>

<key>
$(cat "$client_key")
</key>

<tls-auth>
$(cat "$tls_key")
</tls-auth>
EOF

    echo "Client config saved: $out"
    publish_ovpn "$client"
}

# --------- Main install flow ---------

fresh_install() {
    echo "Welcome to the OpenVPN installer (2025 fixed)."
    echo

    # Choose protocol
    echo "Select protocol:"
    echo "  1) UDP (recommended)"
    echo "  2) TCP"
    read -rp "Protocol [1]: " proto_choice
    case "$proto_choice" in
        2) PROTOCOL="tcp" ;;
        *) PROTOCOL="udp" ;;
    esac

    # Choose port
    read -rp "Port [1194]: " port_choice
    if [[ -z "$port_choice" ]]; then
        PORT=1194
    else
        PORT="$port_choice"
    fi

    # Client name
    read -rp "Enter name for first client [client]: " cname
    if [[ -z "$cname" ]]; then
        CLIENT_NAME="client"
    else
        CLIENT_NAME=$(echo "$cname" | sed 's/[^0-9A-Za-z_-]/_/g')
    fi

    echo
    echo "OpenVPN will be installed with:"
    echo "  Protocol : $PROTOCOL"
    echo "  Port     : $PORT"
    echo "  Client   : $CLIENT_NAME"
    echo
    pause_key

    # Do the things
    install_openvpn_easyrsa
    setup_nginx
    enable_ip_forward
    setup_iptables_nat
    setup_ufw_ports
    init_easyrsa_pki
    copy_server_files
    write_server_conf
    start_openvpn
    build_client_ovpn "$CLIENT_NAME"

    echo "Installation finished!"
    echo "You can run this script again to add more clients."
}

# --------- Post-install menu ---------

add_client() {
    cd "$EASYRSA_DIR"
    echo
    read -rp "New client name: " cname
    CLIENT_NAME=$(echo "$cname" | sed 's/[^0-9A-Za-z_-]/_/g')
    if [[ -z "$CLIENT_NAME" ]]; then
        echo "Invalid name."
        exit 1
    fi
    ./easyrsa --batch gen-req "$CLIENT_NAME" nopass
    ./easyrsa --batch sign-req client "$CLIENT_NAME"
    build_client_ovpn "$CLIENT_NAME"
}

revoke_client() {
    cd "$EASYRSA_DIR"
    echo
    echo "Existing valid clients:"
    awk '/^V/ {print NR ") " $NF}' pki/index.txt
    echo
    read -rp "Select number to revoke: " num

    local CN
    CN=$(awk -v n="$num" '/^V/ {c++; if (c==n) print $NF}' pki/index.txt)
    if [[ -z "$CN" ]]; then
        echo "Invalid selection."
        exit 1
    fi

    echo "Revoking $CN..."
    ./easyrsa --batch revoke "$CN"
    ./easyrsa --batch gen-crl
    cp pki/crl.pem "$SERVER_DIR/crl.pem"
    chown nobody:nogroup "$SERVER_DIR/crl.pem"
    systemctl restart openvpn-server@server.service
    echo "Client $CN revoked."
}

uninstall_openvpn() {
    echo
    read -rp "Are you sure you want to remove OpenVPN? [y/N]: " ans
    case "$ans" in
        y|Y)
            systemctl stop openvpn-server@server.service || true
            systemctl disable openvpn-server@server.service || true
            apt-get remove --purge -y openvpn easy-rsa iptables-persistent nginx || true
            rm -rf /etc/openvpn
            echo "OpenVPN + EasyRSA removed."
            ;;
        *)
            echo "Aborted."
            ;;
    esac
}

main_menu() {
    clear
    echo "OpenVPN is already installed."
    echo
    echo "Select an option:"
    echo "  1) Add a new client"
    echo "  2) Revoke an existing client"
    echo "  3) Uninstall OpenVPN"
    echo "  4) Exit"
    read -rp "Option: " opt
    case "$opt" in
        1) add_client ;;
        2) revoke_client ;;
        3) uninstall_openvpn ;;
        4) exit 0 ;;
        *) echo "Invalid option." ;;
    esac
}

# --------- Entry point ---------

require_root
detect_os

if [[ ! -f "$SERVER_CONF" ]]; then
    fresh_install
else
    main_menu
fi
