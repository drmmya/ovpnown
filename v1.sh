#!/bin/bash

#########################################
#  OPENVPN INSTALLER + AUTO-NGINX FIX   #
#        FULLY FIXED 2025 VERSION       #
#########################################

# REQUIRE ROOT
if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash openvpn-fix.sh"
  exit 1
fi

# AUTO REMOVE APACHE (conflicts with port 80)
systemctl stop apache2 2>/dev/null
systemctl disable apache2 2>/dev/null

# INSTALL NGINX IF MISSING
if ! command -v nginx >/dev/null 2>&1; then
  apt update
  apt install -y nginx
fi

systemctl enable nginx
systemctl restart nginx

# Enable UFW if off
if ! ufw status | grep -q "Status: active"; then
  ufw --force enable
fi

# Open ports for VPN + HTTP download
ufw allow 22
ufw allow 80
ufw allow 443
ufw allow 1194/tcp
ufw allow 1194/udp

# Install base OpenVPN + EasyRSA
apt install -y openvpn easy-rsa

make-cadir ~/openvpn-ca
cd ~/openvpn-ca

# EASYRSA CONFIG
cat > vars <<EOF
set_var EASYRSA_REQ_COUNTRY    "BD"
set_var EASYRSA_REQ_PROVINCE   "Dhaka"
set_var EASYRSA_REQ_CITY       "Dhaka"
set_var EASYRSA_REQ_ORG        "OpenVPN"
set_var EASYRSA_REQ_EMAIL      "vpn@example.com"
set_var EASYRSA_REQ_OU         "Community"
EOF

source ./vars
./easyrsa init-pki
./easyrsa build-ca nopass

./easyrsa gen-req server nopass
./easyrsa sign-req server server

./easyrsa gen-dh
openvpn --genkey secret ta.key

# COPY FILES TO /etc/openvpn
cp pki/ca.crt pki/private/server.key pki/issued/server.crt pki/dh.pem ta.key /etc/openvpn/

# SERVER CONFIG
cat > /etc/openvpn/server.conf <<EOF
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA256
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
persist-key
persist-tun
user nobody
group nogroup
verb 3
explicit-exit-notify 1
EOF

# ENABLE IP FORWARDING
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

# Start OpenVPN
systemctl enable openvpn@server
systemctl restart openvpn@server

# CREATE CLIENT CONFIG
IP=$(curl -s http://ipinfo.io/ip)

cat > /root/openvpn.ovpn <<EOF
client
dev tun
proto udp
remote $IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
verb 3

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>

<cert>
$(sed -n '/BEGIN/,/END/p' ~/openvpn-ca/pki/issued/server.crt)
</cert>

<key>
$(cat ~/openvpn-ca/pki/private/server.key)
</key>

<tls-auth>
$(cat /etc/openvpn/ta.key)
</tls-auth>
EOF

# COPY FILE TO WEB ROOT
cp /root/openvpn.ovpn /var/www/html/openvpn.ovpn
chmod 644 /var/www/html/openvpn.ovpn

echo "=============================================="
echo " Install Complete!"
echo " Download your OpenVPN config at:"
echo ""
echo "  http://$IP/openvpn.ovpn"
echo ""
echo "=============================================="
