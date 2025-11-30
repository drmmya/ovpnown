#!/bin/bash
# Simple OpenVPN + Web Admin installer
# OS: Ubuntu 20.04/22.04 / Debian 11

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root: sudo bash ovpn_panel_install.sh"
  exit
fi

echo "Updating system..."
apt update && apt upgrade -y

echo "Installing dependencies..."
apt install -y openvpn easy-rsa curl wget git docker.io docker-compose

# Enable Docker
systemctl enable --now docker

# ========= OpenVPN Server Setup =========

OVPN_DIR=/etc/openvpn
EASYRSA_DIR=/etc/openvpn/easy-rsa

mkdir -p $EASYRSA_DIR
cd $EASYRSA_DIR

echo "Downloading easy-rsa..."
wget -qO- https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.2/EasyRSA-3.1.2.tgz | tar xz --strip-components=1

# Create PKI
./easyrsa init-pki
YES="yes"
echo -e "$YES" | ./easyrsa build-ca nopass

./easyrsa gen-dh
./easyrsa gen-req server nopass
./easyrsa sign-req server server <<EOF
yes
EOF

openvpn --genkey secret $EASYRSA_DIR/ta.key

# Copy certs/keys
cp pki/ca.crt pki/issued/server.crt pki/private/server.key pki/dh.pem $OVPN_DIR
cp ta.key $OVPN_DIR

# Server config
cat > $OVPN_DIR/server.conf <<'EOF'
port 1194
proto udp
dev tun

ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0

cipher AES-256-CBC
auth SHA256
data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC
data-ciphers-fallback AES-256-CBC

topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt

keepalive 10 120
persist-key
persist-tun

user nobody
group nogroup

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"

explicit-exit-notify 1

status openvpn-status.log
log-append /var/log/openvpn.log
verb 3
EOF

# Enable IP forwarding
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-openvpn-forward.conf
sysctl --system

# Basic firewall rules (iptables)
IFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')

iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$IFACE" -j MASQUERADE
iptables-save > /etc/iptables.rules

cat > /etc/network/if-up.d/iptables <<EOF
#!/bin/sh
iptables-restore < /etc/iptables.rules
EOF
chmod +x /etc/network/if-up.d/iptables

# Enable OpenVPN
systemctl enable openvpn@server
systemctl start openvpn@server

# ========= Web Admin (openvpn-admin, Docker) =========

APP_DIR=/opt/openvpn-admin
mkdir -p $APP_DIR
cd $APP_DIR

cat > docker-compose.yml <<'EOF'
version: '3.7'
services:
  openvpn-admin:
    image: flant/openvpn-admin:latest
    container_name: openvpn-admin
    restart: always
    environment:
      - OPENVPN_ADMIN_USERNAME=admin
      - OPENVPN_ADMIN_PASSWORD=admin123
      - OPENVPN_STATUS_PATH=/etc/openvpn/openvpn-status.log
      - OPENVPN_LOG_PATH=/var/log/openvpn.log
    volumes:
      - /etc/openvpn:/etc/openvpn
    ports:
      - "8080:8080"
EOF

docker compose up -d

echo ""
echo "==============================================="
echo " OpenVPN + Web Admin installation complete!"
echo "-----------------------------------------------"
echo " OpenVPN server:"
echo "   Port: 1194/UDP"
echo "   Config: /etc/openvpn/server.conf"
echo ""
echo " Web Admin Panel (openvpn-admin):"
echo "   URL: http://YOUR_SERVER_IP:8080"
echo "   Username: admin"
echo "   Password: admin123 (change from UI)"
echo ""
echo " Don't forget to:"
echo "   - Open ports 1194/UDP and 8080/TCP in your firewall / provider panel."
echo "   - Reboot if something doesn't start correctly."
echo "==============================================="
