#!/bin/bash

#########################################
#  OPENVPN INSTALLER 2025 (FIXED)
#  Proper client certs + nginx download
#########################################

if [[ $EUID -ne 0 ]]; then
  echo "Run as root."
  exit 1
fi

# Remove Apache (conflicts with port 80)
systemctl stop apache2 2>/dev/null
systemctl disable apache2 2>/dev/null

apt update
apt install -y openvpn easy-rsa nginx curl ufw

systemctl enable nginx
systemctl restart nginx

# Firewall
ufw allow 22
ufw allow 80
ufw allow 1194/udp
ufw --force enable

###############################################
# EASYRSA SETUP
###############################################

make-cadir /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa

cat > vars <<EOF
set_var EASYRSA_REQ_COUNTRY    "BD"
set_var EASYRSA_REQ_PROVINCE   "Dhaka"
set_var EASYRSA_REQ_CITY       "Dhaka"
set_var EASYRSA_REQ_ORG        "OpenVPN"
set_var EASYRSA_REQ_EMAIL      "vpn@example.com"
set_var EASYRSA_REQ_OU         "Community"
EOF

chmod +x easyrsa
source ./vars

./easyrsa init-pki
./easyrsa build-ca nopass

# Server cert
./easyrsa gen-req server nopass
./easyrsa sign-req server server

# Diffie-Hellman + TLS
./easyrsa gen-dh
openvpn --genkey secret ta.key

# Client cert (VERY IMPORTANT)
CLIENT="client1"
./easyrsa gen-req $CLIENT nopass
./easyrsa sign-req client $CLIENT

###############################################
# COPY FILES
###############################################

cp pki/ca.crt pki/issued/server.crt pki/private/server.key pki/dh.pem ta.key /etc/openvpn/
mkdir -p /etc/openvpn/client
cp pki/issued/$CLIENT.crt pki/private/$CLIENT.key /etc/openvpn/client/

###############################################
# SERVER CONFIG
###############################################

cat > /etc/openvpn/server.conf <<EOF
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
topology subnet

server 10.8.0.0 255.255.255.0

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"

keepalive 10 120
user nobody
group nogroup
persist-key
persist-tun
verb 3
explicit-exit-notify 1
EOF

###############################################
# ENABLE IP FORWARDING
###############################################

echo 1 > /proc/sys/net/ipv4/ip_forward
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

###############################################
# START OPENVPN
###############################################

systemctl enable openvpn@server
systemctl restart openvpn@server

###############################################
# GENERATE CLIENT .OVPN
###############################################

IP=$(curl -s ifconfig.me)

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
key-direction 1

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>

<cert>
$(sed -n '/BEGIN/,/END/p' /etc/openvpn/client/$CLIENT.crt)
</cert>

<key>
$(cat /etc/openvpn/client/$CLIENT.key)
</key>

<tls-auth>
$(cat /etc/openvpn/ta.key)
</tls-auth>
EOF

cp /root/openvpn.ovpn /var/www/html/openvpn.ovpn
chmod 644 /var/www/html/openvpn.ovpn

echo "=============================================="
echo " Install Complete!"
echo " Download your OpenVPN config:"
echo "  http://$IP/openvpn.ovpn"
echo "=============================================="
