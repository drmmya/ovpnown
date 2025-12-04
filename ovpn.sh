#!/bin/bash
# Simple OpenVPN IPv4-only installer for Ubuntu/Debian
# No IPv6 at all (prevents service crash)
# Generates /root/client.ovpn

set -e

VPN_NET_V4="10.8.0.0 255.255.255.0"
VPN_PORT="1194"
VPN_PROTO="udp"
CLIENT="client"

# --- Helpers ---
if [[ "$EUID" -ne 0 ]]; then
  echo "Run as root!"
  exit 1
fi

if [[ ! -e /dev/net/tun ]]; then
  echo "TUN not available! Enable it in your VPS panel."
  exit 1
fi

# Detect OS
if ! grep -qs "ubuntu\|debian" /etc/os-release; then
  echo "Only Ubuntu/Debian supported."
  exit 1
fi

# Detect network interface
NIC=$(ip route | grep default | awk '{print $5}' | head -n1)
if [[ -z "$NIC" ]]; then
  echo "Could not detect network interface."
  exit 1
fi

# Detect public IP
IPV4=$(curl -4 -s https://api.ipify.org || echo "")
if [[ -z "$IPV4" ]]; then
  IPV4=$(ip -4 addr show "$NIC" | awk '/inet /{print $2}' | cut -d/ -f1)
fi

echo "Using public IP: $IPV4"
echo "Using interface: $NIC"

# --- Enable IPv4 forwarding ---
echo "Enabling IPv4 forwarding..."
cat > /etc/sysctl.d/99-openvpn-ipv4.conf <<EOF
net.ipv4.ip_forward=1
EOF
sysctl --system >/dev/null

# --- Install dependencies ---
apt update
apt install -y openvpn easy-rsa iptables-persistent curl

# --- Setup EasyRSA PKI ---
mkdir -p /etc/openvpn/easy-rsa
cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/

cd /etc/openvpn/easy-rsa

cat > vars <<EOF
set_var EASYRSA_ALGO "ec"
set_var EASYRSA_CURVE "prime256v1"
set_var EASYRSA_REQ_CN "OpenVPN-CA"
EOF

./easyrsa init-pki
EASYRSA_BATCH=1 ./easyrsa build-ca nopass
EASYRSA_BATCH=1 ./easyrsa gen-dh
EASYRSA_BATCH=1 ./easyrsa build-server-full server nopass
EASYRSA_BATCH=1 ./easyrsa build-client-full $CLIENT nopass
EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

# Copy certs
cp pki/ca.crt /etc/openvpn/
cp pki/dh.pem /etc/openvpn/
cp pki/issued/server.crt /etc/openvpn/
cp pki/private/server.key /etc/openvpn/
cp pki/crl.pem /etc/openvpn/
chmod 644 /etc/openvpn/crl.pem

openvpn --genkey secret /etc/openvpn/tls-crypt.key

# --- Create server config (IPv4 ONLY) ---
mkdir -p /etc/openvpn/server
cat > /etc/openvpn/server/server.conf <<EOF
port $VPN_PORT
proto $VPN_PROTO
dev tun

user nobody
group nogroup
persist-key
persist-tun

topology subnet
server $VPN_NET_V4

push "redirect-gateway def1 bypass-dhcp"

# DNS
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
remote-cert-tls client
tls-version-min 1.2

keepalive 10 120
explicit-exit-notify 1

# Logging
status /var/log/openvpn-status.log
log-append /var/log/openvpn.log
verb 3

mssfix 1400
EOF

# --- Firewall/NAT IPv4 ---
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$NIC" -j MASQUERADE
iptables -A FORWARD -i tun0 -o "$NIC" -j ACCEPT
iptables -A FORWARD -i "$NIC" -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
netfilter-persistent save

# --- Enable OpenVPN service ---
systemctl enable openvpn-server@server
systemctl restart openvpn-server@server

# --- Generate client file ---
cd /etc/openvpn/easy-rsa
cat > /root/$CLIENT.ovpn <<EOF
client
dev tun
proto $VPN_PROTO
remote $IPV4 $VPN_PORT
nobind
persist-key
persist-tun
cipher AES-256-CBC
auth SHA256
remote-cert-tls server
key-direction 1
verb 3
redirect-gateway def1
EOF

{
echo "<ca>"
cat /etc/openvpn/ca.crt
echo "</ca>"

echo "<cert>"
awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' pki/issued/$CLIENT.crt
echo "</cert>"

echo "<key>"
cat pki/private/$CLIENT.key
echo "</key>"

echo "<tls-crypt>"
cat /etc/openvpn/tls-crypt.key
echo "</tls-crypt>"
} >> /root/$CLIENT.ovpn

echo "=============================================="
echo " OpenVPN IPv4-only installed successfully!"
echo " Client config: /root/$CLIENT.ovpn"
echo "=============================================="
