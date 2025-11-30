#!/bin/bash
#
# Simple OpenVPN installer (Debian/Ubuntu)
# With auto .ovpn download at http://SERVER_IP/openvpn.ovpn
#

set -e

EASYRSA_DIR="/etc/openvpn/easy-rsa"
SERVER_CONF="/etc/openvpn/server/server.conf"
WEB_ROOT="/var/www/html"

# ---------- Helpers ----------

require_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "This installer must be run as root."
        exit 1
    fi
}

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

get_server_ip() {
    # Try to detect public IP
    if command -v curl >/dev/null 2>&1; then
        SERVER_IP=$(curl -s ifconfig.me || true)
    fi
    if [[ -z "$SERVER_IP" ]]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi
}

press_any_key() {
    read -n1 -r -p "Press any key to continue..." key
    echo
}

# ---------- Nginx + download ----------

setup_nginx_and_download() {
    local client_name="$1"
    local ovpn_file="/root/${client_name}.ovpn"

    if [[ ! -f "$ovpn_file" ]]; then
        echo "ERROR: Client file $ovpn_file not found, cannot publish download link."
        return
    fi

    echo "Installing nginx (if not installed)..."
    apt-get install -y nginx >/dev/null 2>&1 || true
    systemctl enable --now nginx >/dev/null 2>&1 || true

    mkdir -p "$WEB_ROOT"
    cp "$ovpn_file" "$WEB_ROOT/openvpn.ovpn"
    chmod 644 "$WEB_ROOT/openvpn.ovpn"

    get_server_ip

    echo
    echo "=============================================="
    echo " Your OpenVPN config is now downloadable at:"
    echo "  http://${SERVER_IP}/openvpn.ovpn"
    echo "=============================================="
    echo
}

# ---------- Easy-RSA / PKI ----------

setup_easyrsa() {
    echo "Installing OpenVPN + Easy-RSA..."
    apt-get update
    apt-get install -y openvpn easy-rsa iptables curl

    mkdir -p "$EASYRSA_DIR"
    if [[ ! -f "$EASYRSA_DIR/easyrsa" ]]; then
        cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR"/
    fi

    cd "$EASYRSA_DIR"
    ./easyrsa init-pki
    ./easyrsa --batch build-ca nopass
    ./easyrsa gen-dh
    ./easyrsa --batch build-server-full server nopass
    ./easyrsa --batch build-client-full "$CLIENT_NAME" nopass
    ./easyrsa gen-crl

    # Generate tls-crypt key
    openvpn --genkey secret "$EASYRSA_DIR/ta.key"

    # Copy server files
    mkdir -p /etc/openvpn/server
    cp "$EASYRSA_DIR/pki/ca.crt" /etc/openvpn/server/
    cp "$EASYRSA_DIR/pki/issued/server.crt" /etc/openvpn/server/
    cp "$EASYRSA_DIR/pki/private/server.key" /etc/openvpn/server/
    cp "$EASYRSA_DIR/pki/dh.pem" /etc/openvpn/server/dh.pem
    cp "$EASYRSA_DIR/ta.key" /etc/openvpn/server/ta.key
    cp "$EASYRSA_DIR/pki/crl.pem" /etc/openvpn/server/crl.pem

    chown nobody:nogroup /etc/openvpn/server/crl.pem
}

# ---------- Server config ----------

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

enable_ip_forwarding() {
    echo "Enabling IP forwarding and fixing kernel routing filters..."

    # Remove old entries
    sed -i '/^net.ipv4.ip_forward/d' /etc/sysctl.conf
    sed -i '/^net.ipv4.conf.all.rp_filter/d' /etc/sysctl.conf
    sed -i '/^net.ipv4.conf.default.rp_filter/d' /etc/sysctl.conf

    # Add correct values
    {
        echo "net.ipv4.ip_forward=1"
        echo "net.ipv4.conf.all.rp_filter=0"
        echo "net.ipv4.conf.default.rp_filter=0"
    } >> /etc/sysctl.conf

    # Apply changes
    sysctl -p >/dev/null

    echo "IP forwarding enabled."
}


setup_iptables() {
    echo "Configuring iptables (NAT + forwarding)..."

    # Detect interface
    IFACE=$(ip route get 1.1.1.1 | awk '/dev/ {print $5}')

    # Clear previous rules
    iptables -t nat -F
    iptables -F

    # NAT MASQUERADE
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE
    iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE

    # Forward rules
    iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

    # Allow OpenVPN port
    iptables -A INPUT -p "$PROTOCOL" --dport "$PORT" -j ACCEPT

    echo "Saving iptables rules..."
    apt-get install -y iptables-persistent >/dev/null 2>&1 || true
    iptables-save > /etc/iptables/rules.v4
}


start_openvpn_service() {
    systemctl enable --now openvpn-server@server.service
}

# ---------- Client generation ----------

generate_client_ovpn() {
    local client_name="$1"
    local client_ovpn="/root/${client_name}.ovpn"

    CA_CERT="$EASYRSA_DIR/pki/ca.crt"
    CLIENT_CERT="$EASYRSA_DIR/pki/issued/${client_name}.crt"
    CLIENT_KEY="$EASYRSA_DIR/pki/private/${client_name}.key"
    TLS_KEY="$EASYRSA_DIR/ta.key"

    if [[ ! -f "$CA_CERT" || ! -f "$CLIENT_CERT" || ! -f "$CLIENT_KEY" || ! -f "$TLS_KEY" ]]; then
        echo "Missing certificates/keys for client $client_name"
        exit 1
    fi

    get_server_ip

    cat > "$client_ovpn" <<EOF
client
dev tun
proto ${PROTOCOL}
remote ${SERVER_IP} ${PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
verb 3
key-direction 1

<ca>
$(cat "$CA_CERT")
</ca>

<cert>
$(awk '/BEGIN CERTIFICATE/{flag=1} flag{print} /END CERTIFICATE/{flag=0}' "$CLIENT_CERT")
</cert>

<key>
$(cat "$CLIENT_KEY")
</key>

<tls-crypt>
$(cat "$TLS_KEY")
</tls-crypt>
EOF

    echo
    echo "Client configuration saved as: $client_ovpn"
    setup_nginx_and_download "$client_name"
}

# ---------- Install flow ----------

fresh_install() {
    echo "Welcome to the simple OpenVPN installer."
    echo

    # IP info (we use detected IP later in client .ovpn)
    get_server_ip
    echo "Detected server IP: ${SERVER_IP}"
    echo

    # Protocol
    echo "Select protocol:"
    echo "  1) UDP (recommended)"
    echo "  2) TCP"
    read -rp "Protocol [1]: " proto_choice
    case "$proto_choice" in
        2) PROTOCOL="tcp" ;;
        *) PROTOCOL="udp" ;;
    esac

    # Port
    read -rp "Port [1194]: " port_choice
    if [[ -z "$port_choice" ]]; then
        PORT=1194
    else
        PORT="$port_choice"
    fi

    # Client name
    read -rp "Enter a name for the first client [client]: " cname
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
    press_any_key

    setup_easyrsa
    write_server_conf
    enable_ip_forwarding
    setup_iptables
    start_openvpn_service
    generate_client_ovpn "$CLIENT_NAME"

    echo "Installation finished!"
    echo "You can add more clients by running this script again."
}

add_client() {
    echo
    read -rp "New client name: " cname
    CLIENT_NAME=$(echo "$cname" | sed 's/[^0-9A-Za-z_-]/_/g')
    if [[ -z "$CLIENT_NAME" ]]; then
        echo "Invalid name."
        exit 1
    fi

    cd "$EASYRSA_DIR"
    ./easyrsa --batch build-client-full "$CLIENT_NAME" nopass
    generate_client_ovpn "$CLIENT_NAME"
}

revoke_client() {
    cd "$EASYRSA_DIR"
    echo
    echo "Existing clients:"
    awk '/^V/{print NR ") " $NF}' pki/index.txt
    echo
    read -rp "Select client number to revoke: " num

    CLIENT_CN=$(awk -v n="$num" '/^V/{c++; if(c==n) print $NF}' pki/index.txt)
    if [[ -z "$CLIENT_CN" ]]; then
        echo "Invalid selection."
        exit 1
    fi

    echo "Revoking $CLIENT_CN..."
    ./easyrsa --batch revoke "$CLIENT_CN"
    ./easyrsa gen-crl
    cp "$EASYRSA_DIR/pki/crl.pem" /etc/openvpn/server/crl.pem
    chown nobody:nogroup /etc/openvpn/server/crl.pem
    systemctl restart openvpn-server@server.service
    echo "Client $CLIENT_CN revoked."
}

uninstall_openvpn() {
    echo
    read -rp "Are you sure you want to remove OpenVPN? [y/N]: " ans
    case "$ans" in
        y|Y)
            systemctl stop openvpn-server@server.service || true
            systemctl disable openvpn-server@server.service || true
            apt-get remove --purge -y openvpn easy-rsa iptables-persistent || true
            rm -rf /etc/openvpn
            echo "OpenVPN removed."
            ;;
        *)
            echo "Aborted."
            ;;
    esac
}

# ---------- Main ----------

require_root
detect_os

if [[ ! -f "$SERVER_CONF" ]]; then
    fresh_install
    exit 0
fi

# If we reach here, OpenVPN is already installed
clear
echo "OpenVPN is already installed."
echo
echo "Select an option:"
echo "   1) Add a new client"
echo "   2) Revoke an existing client"
echo "   3) Remove OpenVPN"
echo "   4) Exit"
read -rp "Option: " opt

case "$opt" in
    1) add_client ;;
    2) revoke_client ;;
    3) uninstall_openvpn ;;
    4) exit 0 ;;
    *) echo "Invalid option." ;;
esac
