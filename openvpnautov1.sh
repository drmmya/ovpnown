#!/bin/bash

###############################################
# FINAL FULLY FIXED OPENVPN INSTALLER (V3)
# - Auto remove old OpenVPN
# - OpenVPN 2.6+ compatible
# - CA/cert/key fixed paths
# - Username: openvpn
# - Password: Easin112233@
# - Client:  http://SERVER_IP/ovpn/client.ovpn
###############################################

set -e
export DEBIAN_FRONTEND=noninteractive

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

echo "=== Removing old OpenVPN installation (if any) ==="
systemctl stop openvpn-server@server.service 2>/dev/null || true
systemctl stop openvpn@server.service 2>/dev/null || true
apt-get purge -y openvpn 2>/dev/null || true
rm -rf /etc/openvpn 2>/dev/null || true

echo "=== Installing OpenVPN + dependencies ==="
apt-get update -y
apt-get install -y openvpn nginx iptables-persistent curl openssl

echo "=== Detecting public IP ==="
SERVER_IP=$(curl -s ifconfig.me || hostname -I | awk '{print $1}')
echo "Using IP: $SERVER_IP"

echo "=== Creating OpenVPN directory ==="
mkdir -p /etc/openvpn/server
cd /etc/openvpn/server

###############################################
# Global CA certificate
###############################################
echo "=== Writing CA certificate ==="
cat > /etc/openvpn/server/ca.crt <<'EOF'
-----BEGIN CERTIFICATE-----
MIIFEzCCAvugAwIBAgIUJG02X6MpSkTCQob1GJ9CaNrJt3EwDQYJKoZIhvcNAQEL
BQAwGTEXMBUGA1UEAwwOT1ZQTi1HbG9iYWwtQ0EwHhcNMjUxMTI5MDUxMDU0WhcN
MzUxMTI3MDUxMDU0WjAZMRcwFQYDVQQDDA5PVlBOLUdsb2JhbC1DQTCCAiIwDQYJ
KoZIhvcNAQEBBQADggIPADCCAgoCggIBALiPsTQ4nkFBY9YFu4xXEVbwy4M/hEkf
ZmBGVeR1XWnm8/t7s87EFw8xWRcCIONNVqtEAftOo/aMgD3xXMnTguQ9S+6wBOSZ
sm8lCdjOSAgSxb9buIBDZ5Tj0VdCFGIazbS67FlJBvh/bdpvbgq6jnMdi77UUME7
TyJ26n+UpxusbIomIaUlrxmIzviG4A+wwRAnOqOcOfHjRPid6hclr+uj3aAwshnJ
dt2L2+BVETXVKPd80MjhgoZh8xPrhKoRfrQ8dGlM0PX67iUDHbBVed00/G55CWYY
1MsnO+M1yP/GvjkaG7kipBL16JvQrBTklWbvPKJQ7E6zFVsk9fKLqMnRipE7kjXE
BjoKywg5+ES/1NOfQm98wqLOoxghVc0Yuey0593YNRhWoi0b/mWqYlBMkWMZ0mCX
1KXqUeUphHQ1XAIa5MnUCJ6gwZJo3Da90rKzwZ1B+IRZ5ECzR5bb34PyoQGt5QRU
ShSRxsgqLrOLxm8clpf2UaSQbTejMlaqv2W0eN0s7GYu9txIb6XO9Ah9aOwc0h1X
Oel6w8V2k4bs0ZEuPfvluU9v8LsWLWAAHNwmTW12n/xqGrwOaVKDhwCoxBKQHGQk
YxTkUxfTzJs2ireOuh+o6ReQFTwywEr4l47W1dg1XbH3sEnuFeNmIjNVf1DLB3y/
usPHkH8a/NmfAgMBAAGjUzBRMB0GA1UdDgQWBBSoTfcqCa+jlHrajwgDDC3J9S0I
cjAfBgNVHSMEGDAWgBSoTfcqCa+jlHrajwgDDC3J9S0IcjAPBgNVHRMBAf8EBTAD
AQH/MA0GCSqGSIb3DQEBCwUAA4ICAQByM+m9SKoYS/9L4j7AqkEM8juWIH4OXocB
XOyXHX1L+ohAggJrTlKGaNojnoPqI0U1ZKY7Pt4EbEsnfNJbvfnp8X+ppVyII+zs
3/e7EM6Jwsp8S+v3NxzF+dJH9uerCj+zxytgLHmbXHXDX/XGlSZLNmGmH8cuPWtS
lLZ24MmkW1IGtkjHaQ4CAbwNSoEBZ9PG2vc+FRGCu9Gc34vgF2xtcRIoi382V/mc
fPqRLcq1CFwl7zt+1Il8gwn4rFQAnLTf3MdYW70h56L+Z30AXbJxOQxC4fM2CV6s
LLXJYdrANAzXw/WRHxvXJ3pLHJ3LaJXmYYlrBHKwDXJZEAhqo4LzuImFrzcLTZDI
MEU/Xh8+F9RlKigCJQpxBAe7A2rq8nRB/2egvmltDVDrZqJyHT4RSSf+8dwNwsw7
zBcljldCIhOz/imt9K/IXW1hGpCoZJexZqZ3mtFz5w2NftOINjPOPBb3CoZ0VVyT
iGEzqKzdO9w/I7O3WilRVjz1AZ7E6XxpYRA0hyczjHDzXcYcGBMSjEFvkUBkHabO
KTfqNq1GeWrS3/O+F4Ptz1EBFuNPehpnLIJIOhl9xvHdw8jb02V8nyZ+VQHltqcz
cnivT6xmRHn+TvXt163k943CLRwXdluai8ccIURoufMuUQQgekpfct0hhvWEUv/d
uImhp2w3xA==
-----END CERTIFICATE-----
EOF

###############################################
# Global Server certificate
###############################################
echo "=== Writing server certificate ==="
cat > /etc/openvpn/server/server.crt <<'EOF'
-----BEGIN CERTIFICATE-----
MIIEtjCCAp4CFAbfmyx9LE7QtoVckDo9KALEQX9jMA0GCSqGSIb3DQEBCwUAMBkx
FzAVBgNVBAMMDk9WUE4tR2xvYmFsLUNBMB4XDTI1MTEyOTA5NTExNVoXDTM1MTEy
NzA5NTExNVowFjEUMBIGA1UEAwwLT1ZQTi1TZXJ2ZXIwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCzrZeolH+aA2yXQJ12FE9r9qqWh0Q61c027iXpHjVH
exCbmG1/unjJTkk4G+02JAWUVOVnIzX20RTOpOsJSWmTVBHfvxkNu5e9AEZDRjxa
aO/CHUrLyWYSjsQXDe2H9F1r6nGEXHrE2GbTNdtJK/AG436qebozfxL4FDOwsTex
OBdI4X6pce0A0HLSnJ0f1Z9dvU6TnploIheVjLJvXOyV6hlLh4FRPmYFbOxxyfxD
z9lPJ48tdPRSi6E8cjKTuIrSGJ7qn/J00Behl7KMU/cpS7bUiUTd6Jz/Huy/4V60
uvSpNfiK+hlLm7Yd0F3/I8FpKpOiRS7+kOva3pTanGYO1sI9+seg1PHr8i23yCVe
JPkwHtiotTgYqPfc7UZU2+hVN5t+ryYqcs4xS80LibgC8jpLoMaBraEbDv1apzAO
mr4cZMk0/O7TbQLf+/QQeYahXHWs2EdK3mGAIWm68Wx6Fli3vF/6mVOtQnkjRZ7g
rByQT5uZT43ksOZt/mKBAyM8tOviYRA4W6LtBFeGiQAhFesTPFnEEhvW11Tma830
0aU8CoF2C7EodBh3xSTp1oCjhKqxq5lUTfoq9MxgkagNwOHcyAe/FvEfL4anxeeM
JXjbHz3veL0aLkQ7U1JkGafqUeGomjZaS4Otaev3fyGra0/MEcF6MePsLJ0TPJ3p
vQIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCLcMjIT2aeZBucBEM2QqkNXY02dNpy
e1P958awRIOz3vuMLwe2+9z9iGw3E9aL0nmigFl5ugMmJMZKvOeTn3k6pZW0DuLA
BaY52v1dd/mJNNErwufPOxFyzlVbCw+ordfs1yAHNMDguD4x+i+0BwAPs7OcEWwY
evIXQ0QQ5YSGJVpxBctLcFP11Gd85c8kfMOjl2Oj3HkzU8Dr3eimFUWUEPsaOBUO
VuP1c8FrYUBviwlZMGb/6uQrRZv0lbIrpV52tKiQlnHWK+fcF6BhUyvxpYeOBBR8
AsjsrrkwpvuZLeHVvU9Ti5zPm+RYFkbKw5Dbq/hssmnpNZGS5HPrpzaR3cK5MvBC
SOBaKl4alkjHe/+FBPPwCTYa6kVfUatljgAf4rjnMFTrv+b0f5FqaeeLViIbpXIn
tL86y8xGT2Pbvw3xArEhE9IFdPHFXrubFtj1OhpiyUxRxJYQRzTp9GLZImS0ex1i
1PFLZt6bUx3NilPxboCtDfs7UK/its/ebzH+y6pcF6iIgAlhmelmmBn4H1N7EMSx
E18GLISperclVPOoDA3hvbWaByXOqo+nuuueysaLL9m5+L4jsiaanR9YdgZcDJRt
ZEiRnbOYOsdZxx5pz2hF0FEaGIs31woYb9VIOZlL37ag2ZBi4vlqhgY73WMusg4l
yF3d7djUWxEOfA==
-----END CERTIFICATE-----
EOF

###############################################
# Global Server private key
###############################################
echo "=== Writing server private key ==="
cat > /etc/openvpn/server/server.key <<'EOF'
-----BEGIN PRIVATE KEY-----
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
Q9sHgFeQvngMtMmkakWHAwGhqzpY
-----END PRIVATE KEY-----
EOF
chmod 600 /etc/openvpn/server/server.key

echo "=== Generating dh.pem (2048-bit) ==="
openssl dhparam -out /etc/openvpn/server/dh.pem 2048

###############################################
# Username/password auth
###############################################
echo "=== Setting up authentication ==="
mkdir -p /etc/openvpn/server/auth

cat > /etc/openvpn/server/auth/psw-file <<'EOF'
openvpn Easin112233@
EOF

cat > /etc/openvpn/server/auth/checkpsw.sh <<'EOF'
#!/bin/bash

PASSFILE="/etc/openvpn/server/auth/psw-file"
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

chmod 700 /etc/openvpn/server/auth/checkpsw.sh
chmod 600 /etc/openvpn/server/auth/psw-file

###############################################
# OpenVPN server.conf (absolute paths)
###############################################
echo "=== Writing server.conf ==="
cat > /etc/openvpn/server/server.conf <<'EOF'
port 1194
proto udp
dev tun

ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server.crt
key /etc/openvpn/server/server.key
dh /etc/openvpn/server/dh.pem

cipher AES-256-CBC
auth SHA256
data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC
data-ciphers-fallback AES-256-CBC

topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /etc/openvpn/server/ipp.txt

keepalive 10 120
persist-key
persist-tun

script-security 3
verify-client-cert none
auth-user-pass-verify /etc/openvpn/server/auth/checkpsw.sh via-file
username-as-common-name
duplicate-cn

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"

log /var/log/openvpn.log
status /var/log/openvpn-status.log
verb 3
EOF

# Old-style service uses /etc/openvpn/server.conf
cp /etc/openvpn/server/server.conf /etc/openvpn/server.conf

echo "=== Enabling IP forwarding ==="
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-openvpn-forward.conf
sysctl -p /etc/sysctl.d/99-openvpn-forward.conf

###############################################
# NAT rules: eth0 + eth1
###############################################
echo "=== Configuring NAT (eth0 + eth1) ==="
iptables -t nat -F

iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth1 -j MASQUERADE 2>/dev/null || true

iptables -A INPUT -p udp --dport 1194 -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT

iptables-save > /etc/iptables/rules.v4

###############################################
# Start OpenVPN service (new + old style)
###############################################
echo "=== Starting OpenVPN service ==="
systemctl enable openvpn-server@server.service 2>/dev/null || true
systemctl restart openvpn-server@server.service 2>/dev/null || true

systemctl enable openvpn@server.service 2>/dev/null || true
systemctl restart openvpn@server.service 2>/dev/null || true

###############################################
# Generate client.ovpn and serve via nginx
###############################################
echo "=== Creating client.ovpn ==="
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
$(cat /etc/openvpn/server/ca.crt)
</ca>
EOF

echo "=============================================="
echo " INSTALL SUCCESSFUL!"
echo "----------------------------------------------"
echo " Server IP: ${SERVER_IP}"
echo " Username: openvpn"
echo " Password: Easin112233@"
echo ""
echo " Download client config:"
echo "   http://${SERVER_IP}/ovpn/client.ovpn"
echo ""
echo " Logs: /var/log/openvpn.log"
echo "=============================================="
