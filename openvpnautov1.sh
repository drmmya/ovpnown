#!/bin/bash

###############################################
# FINAL CLEAN OPENVPN INSTALLER
# - Everything in /etc/openvpn
# - Service: openvpn@server.service
# - User: openvpn
# - Pass: Easin112233@
###############################################

set -e
export DEBIAN_FRONTEND=noninteractive

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

echo "=== STOP & REMOVE OLD OPENVPN ==="
systemctl stop openvpn@server.service 2>/dev/null || true
systemctl stop openvpn-server@server.service 2>/dev/null || true

apt-get purge -y openvpn 2>/dev/null || true
rm -rf /etc/openvpn
rm -f /var/log/openvpn.log /var/log/openvpn-status.log

echo "=== INSTALL OPENVPN + DEPS ==="
apt-get update -y
apt-get install -y openvpn nginx iptables-persistent curl openssl

echo "=== DETECT PUBLIC IP ==="
SERVER_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')
echo "Using IP: $SERVER_IP"

echo "=== PREPARE /etc/openvpn ==="
mkdir -p /etc/openvpn
cd /etc/openvpn

###############################################
# CA + SERVER CERT / KEY (OpenSSL 3 compatible)
###############################################

echo "=== GENERATE CA KEY & CERT ==="
openssl genrsa -out ca.key 2048
openssl req -new -x509 -key ca.key -out ca.crt -days 3650 -subj "/CN=ovpn-CA"

echo "=== GENERATE SERVER KEY & CERT ==="
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=ovpn-server"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 3650

chmod 600 server.key ca.key

echo "=== GENERATE DH PARAM (2048) ==="
openssl dhparam -out dh.pem 2048

###############################################
# AUTH USER/PASS
###############################################

echo "=== AUTH FILES ==="
mkdir -p /etc/openvpn/auth

cat > /etc/openvpn/auth/psw-file <<'EOF'
openvpn Easin112233@
EOF

cat > /etc/openvpn/auth/checkpsw.sh <<'EOF'
#!/bin/bash

PASSFILE="/etc/openvpn/auth/psw-file"
LOG="/var/log/openvpn-password.log"
CRED_FILE="$1"

USERNAME=$(head -n1 "$CRED_FILE")
PASSWORD=$(tail -n1 "$CRED_FILE")

CORRECT=$(grep "^$USERNAME " "$PASSFILE" | awk '{print $2}')

if [ "$PASSWORD" = "$CORRECT" ]; then
    echo "$(date): OK $USERNAME" >> "$LOG"
    exit 0
else
    echo "$(date): FAIL $USERNAME" >> "$LOG"
    exit 1
fi
EOF

chmod 700 /etc/openvpn/auth/checkpsw.sh
chmod 600 /etc/openvpn/auth/psw-file

###############################################
# SERVER CONFIG (/etc/openvpn/server.conf)
###############################################

echo "=== WRITE /etc/openvpn/server.conf ==="
cat > /etc/openvpn/server.conf <<'EOF'
port 1194
proto udp
dev tun

ca ca.crt
cert server.crt
key server.key
dh dh.pem

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

script-security 3
verify-client-cert none
auth-user-pass-verify /etc/openvpn/auth/checkpsw.sh via-file
username-as-common-name
duplicate-cn

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"

log /var/log/openvpn.log
status /var/log/openvpn-status.log
verb 3
EOF

###############################################
# IP FORWARD + NAT
###############################################

echo "=== ENABLE IP FORWARDING ==="
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-openvpn-forward.conf
sysctl -p /etc/sysctl.d/99-openvpn-forward.conf

echo "=== SET IPTABLES NAT RULES ==="
iptables -t nat -F
iptables -A INPUT -p udp --dport 1194 -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth1 -j MASQUERADE 2>/dev/null || true
iptables-save > /etc/iptables/rules.v4

###############################################
# START SERVICE (ONLY openvpn@server)
###############################################

echo "=== START OPENVPN SERVICE ==="
systemctl disable openvpn-server@server.service 2>/dev/null || true
systemctl stop openvpn-server@server.service 2>/dev/null || true

systemctl enable openvpn@server.service
systemctl restart openvpn@server.service

###############################################
# CLIENT .OVPN VIA NGINX
###############################################

echo "=== CREATE CLIENT OVPN ==="
mkdir -p /var/www/html/ovpn

cat > /var/www/html/ovpn/client.ovpn <<EOF
client
dev tun
proto udp
remote ${SERVER_IP} 1194

resolv-retry infinite
nobind
persist-key
persist-tun

auth-user-pass
setenv CLIENT_CERT 0
remote-cert-tls server

cipher AES-256-CBC
auth SHA256
verb 3

<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF

echo "=============================================="
echo " INSTALL FINISHED"
echo "----------------------------------------------"
echo " Server IP : ${SERVER_IP}"
echo " Username  : openvpn"
echo " Password  : Easin112233@"
echo ""
echo " Download client config:"
echo "   http://${SERVER_IP}/ovpn/client.ovpn"
echo ""
echo " Log file:"
echo "   /var/log/openvpn.log"
echo "=============================================="
