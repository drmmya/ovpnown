#!/bin/bash
# COMPLETE OPENVPN CLEANER + FRESH INSTALLER (IPv4 ONLY)

if [[ $EUID -ne 0 ]]; then
  echo "Run this script as root."
  exit 1
fi

echo "=============================="
echo " REMOVING ALL OLD OPENVPN "
echo "=============================="

# Stop services
systemctl stop openvpn &>/dev/null
systemctl stop openvpn@server &>/dev/null
systemctl stop openvpn-server@server &>/dev/null
systemctl disable openvpn &>/dev/null
systemctl disable openvpn@server &>/dev/null
systemctl disable openvpn-server@server &>/dev/null

# Remove OpenVPN packages
apt purge -y openvpn easy-rsa iptables-persistent netfilter-persistent 2>/dev/null

# Remove directories
rm -rf /etc/openvpn
rm -rf /etc/openvpn/*
rm -rf /etc/openvpn/server
rm -rf /etc/openvpn/easy-rsa
rm -rf /var/log/openvpn
rm -rf /etc/systemd/system/openvpn* 2>/dev/null

# Remove iptables rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

rm -rf /etc/iptables
rm -rf /etc/netfilter-persistent
rm -f /etc/sysctl.d/99-openvpn.conf

sysctl -p &>/dev/null

echo "Old OpenVPN installation fully removed."
echo "========================================="
echo " STARTING FRESH OPENVPN INSTALLATION"
echo "========================================="

apt update
apt install -y openvpn iptables openssl ca-certificates wget curl

# Create required directories
mkdir -p /etc/openvpn/server
mkdir -p /etc/openvpn/easy-rsa

echo "Installing EasyRSA 3..."
EASYRSA_VERSION="3.1.2"
wget -q -O /tmp/easyrsa.tgz \
  "https://github.com/OpenVPN/easy-rsa/releases/download/v${EASYRSA_VERSION}/EasyRSA-${EASYRSA_VERSION}.tgz"

tar -xzf /tmp/easyrsa.tgz --strip-components=1 -C /etc/openvpn/easy-rsa

cd /etc/openvpn/easy-rsa || exit

./easyrsa init-pki
yes "" | ./easyrsa build-ca nopass
yes "" | ./easyrsa build-server-full server nopass
./easyrsa gen-dh
./easyrsa gen-crl

openvpn --genkey --secret /etc/openvpn/server/tls-crypt.key

# Move files
cp pki/ca.crt pki/issued/server.crt pki/private/server.key pki/dh.pem pki/crl.pem \
  /etc/openvpn/server/
chmod 644 /etc/openvpn/server/crl.pem

# Create server.conf
cat > /etc/openvpn/server/server.conf <<EOF
port 1194
proto udp
dev tun
user nobody
group nogroup
persist-key
persist-tun

topology subnet
server 10.8.0.0 255.255.255.0

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-crypt tls-crypt.key
crl-verify crl.pem

cipher AES-256-CBC
auth SHA256
tls-version-min 1.2

keepalive 10 120
status /var/log/openvpn-status.log
log /var/log/openvpn.log
verb 3
EOF

echo "Enabling IPv4 forwarding..."
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-openvpn.conf
sysctl -p /etc/sysctl.d/99-openvpn.conf

echo "Setting up iptables NAT..."
IFACE=$(ip -4 route ls | grep default | awk '{print $5}')

iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $IFACE -j MASQUERADE
iptables -A INPUT -i tun0 -j ACCEPT
iptables -A FORWARD -i tun0 -j ACCEPT
iptables -A FORWARD -i $IFACE -o tun0 -j ACCEPT

apt install -y iptables-persistent
netfilter-persistent save

echo "Starting OpenVPN service..."
systemctl enable openvpn-server@server
systemctl restart openvpn-server@server

# Create first client
CLIENT="client1"
cd /etc/openvpn/easy-rsa
./easyrsa build-client-full $CLIENT nopass

# Generate client profile
cat > /root/$CLIENT.ovpn <<EOF
client
dev tun
proto udp
remote $(curl -s ifconfig.me) 1194
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-CBC
auth SHA256
remote-cert-tls server
verb 3

<ca>
$(cat /etc/openvpn/server/ca.crt)
</ca>

<cert>
$(awk '/BEGIN/,/END/' /etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt)
</cert>

<key>
$(cat /etc/openvpn/easy-rsa/pki/private/$CLIENT.key)
</key>

<tls-crypt>
$(cat /etc/openvpn/server/tls-crypt.key)
</tls-crypt>
EOF

echo ""
echo "===================================="
echo " FRESH INSTALL COMPLETE!"
echo " Client file: /root/$CLIENT.ovpn"
echo "===================================="
