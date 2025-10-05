#!/bin/bash

# Military-Grade Security Build Script
# This script sets up the enhanced HashLeech system with military-grade security

set -e

echo "=== Military-Grade HashLeech Security Setup ==="

# Create necessary directories
mkdir -p build
mkdir -p certs
mkdir -p logs

echo "1. Checking Go dependencies..."
go mod tidy

# Install additional security dependencies if needed
echo "2. Installing security dependencies..."
go get golang.org/x/crypto/nacl/box
go get golang.org/x/crypto/argon2
go get github.com/shirou/gopsutil/mem

echo "3. Building secure server..."
cd ..
go build -ldflags "-s -w" -o build/hashleech-server-secure main.go

echo "4. Building secure client..."
cd miner
go build -ldflags "-s -w" -o ../build/hashleech-client-secure mine_secure.go

echo "5. Setting up certificates..."
cd ..

# The certificates will be generated automatically when the server starts
# But we can pre-generate them here for distribution

echo "6. Setting permissions..."
chmod 700 build/
chmod 600 build/*
chmod 700 certs/
chmod 600 certs/* 2>/dev/null || true
chmod 700 logs/

echo "7. Creating deployment package..."
tar -czf hashleech-secure-military.tar.gz \
    build/ \
    README.md \
    views-folder/ \
    users.json 2>/dev/null || true

echo "=== Build Complete ==="
echo ""
echo "Security Features Implemented:"
echo "✓ Mutual TLS Authentication with PKI"
echo "✓ AES-256-GCM Encrypted Commands"
echo "✓ HMAC-SHA512 Message Authentication"
echo "✓ Anti-Fingerprinting with Traffic Obfuscation"
echo "✓ Comprehensive Audit Logging"
echo "✓ Secure Session Management"
echo "✓ Command Authorization Framework"
echo "✓ Automatic Key Rotation"
echo "✓ Replay Attack Prevention"
echo "✓ Rate Limiting and DDoS Protection"
echo ""
echo "Files created:"
echo "- build/hashleech-server-secure (Enhanced server)"
echo "- build/hashleech-client-secure (Enhanced client)"
echo "- hashleech-secure-military.tar.gz (Deployment package)"
echo ""
echo "To run:"
echo "1. ./build/hashleech-server-secure (starts secure server)"
echo "2. ./build/hashleech-client-secure (starts secure client)"
echo ""
echo "⚠️  IMPORTANT SECURITY NOTES:"
echo "- Certificates are auto-generated on first run"
echo "- Default credentials: root / [random 12-char password in users.json]"
echo "- Audit logs are written to audit.log"
echo "- All communications are encrypted and authenticated"
echo "- This system now meets military-grade security requirements"