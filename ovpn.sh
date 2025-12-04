#!/bin/bash
# Simple OpenVPN 2.4+ installer for Debian/Ubuntu
# IPv4 + IPv6 routing (NAT), Google DNS
# Generates /root/client.ovpn

set -e

VPN_NET_V4="10.8.0.0 255.255.255.0"
VPN_NET_V6="fd42:42:42:42::/112"
VPN_PORT="1194"
VPN_PROTO="udp"
VPN_USER="nobody"
VPN_GROUP="nogroup"
CLIENT_NAME="client"

require_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "This script must be run as root."
        exit 1
    fi
}

require_tun() {
    if [[ ! -e /dev/net/tun ]]; then
        echo "TUN device is not available. Enable it in your VPS panel."
        exit 1
    fi
}

detect_os() {
    if [[ -e /etc/debian_version ]]; then
        OS="debian"
    else
        echo "This script is written for Debian/Ubuntu only."
        exit 1
    fi
}

detect_nic() {
    # Try to detect default outgoing interface
    NIC=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')
    if [[ -z "$NIC" ]]; then
        NIC=$(ip route | awk '/default/ {print $5; exit}')
    fi
    if [[ -z "$NIC" ]]; then
        echo "Could not detect default network interface."
        exit 1
    fi
}

detect_public_ip() {
    # Try multiple methods, IPv4 preferred
    PUBLIC_IP=$(curl -4 -fsS https://api.ipify.org 2>/dev/null || true)
    if [[ -z "$PUBLIC_IP" ]]; then
        PUBLIC_IP=$(curl -4 -fsS https://ifconfig.me 2>/dev/null || true)
    fi
    if [[ -z "$PUBLIC_IP" ]]; then
        # Fallback to IP of default route interface
        PUBLIC_IP=$(ip -4 addr show "$NIC" | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)
    fi
    if [[ -z "$PUBLIC_IP" ]]; then
        echo "Could not detect public IP. Edit client.ovpn later and set 'remote YOUR_IP'."
        PUBLIC_IP="0.0.0.0"
    fi
}

enable_forwarding() {
    echo "Enabling IPv4 and IPv6 forwarding..."
    cat >/etc/sysctl.d/99-openvpn.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
    sysctl --system >/dev/null
}

install_packages() {
    echo "Updating and installing packages..."
    apt-get update
    apt-get install -y openvpn easy-rsa iptables-persistent curl
}

setup_easy_rsa() {
    echo "Setting up easy-rsa PKI..."
    mkdir -p /etc/openvpn/easy-rsa
    if [[ -d /usr/share/easy-rsa ]]; then
        cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/
    else
        echo "easy-rsa not found in /usr/share/easy-rsa."
        exit 1
    fi

    cd /etc/openvpn/easy-rsa

    # Configure easy-rsa (EC keys by default)
    cat >vars <<EOF
set_var EASYRSA_ALGO "ec"
set_var EASYRSA_CURVE "prime256v1"
set_var EASYRSA_REQ_CN "OpenVPN-CA"
EOF

    ./easyrsa init-pki
    EASYRSA_BATCH=1 ./easyrsa build-ca nopass
    EASYRSA_BATCH=1 ./easyrsa gen-dh
    EASYRSA_BATCH=1 ./easyrsa build-server-full server nopass
    EASYRSA_BATCH=1 ./easyrsa build-client-full $CLIENT_NAME nopass
    EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

    # Copy relevant files
    cp pki/ca.crt /etc/openvpn/
    cp pki/dh.pem /etc/openvpn/
    cp pki/issued/server.crt /etc/openvpn/
    cp pki/private/server.key /etc/openvpn/
    cp pki/crl.pem /etc/openvpn/
    chmod 644 /etc/openvpn/crl.pem

    # Generate tls-crypt key
    openvpn --genkey --secret /etc/openvpn/tls-crypt.key
}

write_server_conf() {
    echo "Writing /etc/openvpn/server.conf ..."

    # Use tun interface, IPv4 + IPv6, Google DNS (8.8.8.8/8.8.4.4)
    cat >/etc/openvpn/server.conf <<EOF
port $VPN_PORT
proto $VPN_PROTO
dev tun

user $VPN_USER
group $VPN_GROUP
persist-key
persist-tun

topology subnet
server $VPN_NET_V4
server-ipv6 $VPN_NET_V6
tun-ipv6
push "tun-ipv6"

# Routes for IPv4 + IPv6 internet
push "redirect-gateway def1 bypass-dhcp"
push "route-ipv6 2000::/3"
push "redirect-gateway ipv6"

# DNS - Google
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

# Crypto
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-crypt tls-crypt.key
crl-verify crl.pem

cipher AES-256-CBC
auth SHA256
tls-version-min 1.2
remote-cert-tls client

keepalive 10 120
explicit-exit-notify 1

# Logging
status /var/log/openvpn-status.log
log-append /var/log/openvpn.log
verb 3

# MTU tweaks for reliability
mssfix 1400
EOF
}

apply_iptables_rules() {
    echo "Applying iptables/ip6tables rules for NAT..."

    # IPv4 NAT
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$NIC" -j MASQUERADE
    iptables -A INPUT -i tun0 -j ACCEPT
    iptables -A FORWARD -i tun0 -o "$NIC" -j ACCEPT
    iptables -A FORWARD -i "$NIC" -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT

    # IPv6 NAT (if ip6tables nat table exists)
    if ip6tables -t nat -L >/dev/null 2>&1; then
        ip6tables -t nat -A POSTROUTING -s fd42:42:42:42::/112 -o "$NIC" -j MASQUERADE
        ip6tables -A INPUT -i tun0 -j ACCEPT
        ip6tables -A FORWARD -i tun0 -o "$NIC" -j ACCEPT
        ip6tables -A FORWARD -i "$NIC" -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
    else
        echo "Warning: ip6tables nat table not available. IPv6 NAT may not work on this system."
    fi

    # Save rules so they persist across reboot
    netfilter-persistent save
}

enable_openvpn_service() {
    echo "Enabling and starting OpenVPN server..."
    # Move server.conf into expected directory for systemd template
    if [[ -d /etc/openvpn/server ]]; then
        # Some distros expect /etc/openvpn/server/server.conf
        mv /etc/openvpn/server.conf /etc/openvpn/server/server.conf
        systemctl enable openvpn-server@server
        systemctl restart openvpn-server@server
    else
        # Classic Debian/Ubuntu layout: /etc/openvpn/server.conf and openvpn@server
        systemctl enable openvpn@server || true
        systemctl restart openvpn@server
    fi
}

generate_client_ovpn() {
    echo "Generating /root/${CLIENT_NAME}.ovpn ..."

    cd /etc/openvpn/easy-rsa

    cat >/root/${CLIENT_NAME}.ovpn <<EOF
client
dev tun
proto $VPN_PROTO
remote $PUBLIC_IP $VPN_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
key-direction 1
verb 3
redirect-gateway def1
EOF

    # Embed CA
    {
        echo "<ca>"
        cat /etc/openvpn/ca.crt
        echo "</ca>"

        # Embed client cert and key
        echo "<cert>"
        awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' "pki/issued/${CLIENT_NAME}.crt"
        echo "</cert>"

        echo "<key>"
        cat "pki/private/${CLIENT_NAME}.key"
        echo "</key>"

        # Embed tls-crypt key
        echo "<tls-crypt>"
        cat /etc/openvpn/tls-crypt.key
        echo "</tls-crypt>"
    } >>/root/${CLIENT_NAME}.ovpn

    echo
    echo "==============================================="
    echo " OpenVPN is installed and running."
    echo " IPv4 + IPv6 routing is configured via NAT."
    echo " Client config: /root/${CLIENT_NAME}.ovpn"
    echo " Download it and import in your OpenVPN app."
    echo "==============================================="
}

main() {
    require_root
    require_tun
    detect_os
    detect_nic
    detect_public_ip
    enable_forwarding
    install_packages
    setup_easy_rsa
    write_server_conf
    apply_iptables_rules
    enable_openvpn_service
    generate_client_ovpn
}

main
