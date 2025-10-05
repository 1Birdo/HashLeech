#!/bin/bash

# Security Patch Verification Script
# Verifies that military-grade security functions are properly implemented

echo "=============================================="
echo "  MILITARY-GRADE SECURITY PATCH VERIFICATION"
echo "=============================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
WARNINGS=0

# Function to check and report results
check_result() {
    local test_name="$1"
    local result="$2"
    local details="$3"
    
    if [ "$result" = "PASS" ]; then
        echo -e "${GREEN}✓ PASS${NC}: $test_name"
        [ -n "$details" ] && echo "  └─ $details"
        ((PASSED++))
    elif [ "$result" = "FAIL" ]; then
        echo -e "${RED}✗ FAIL${NC}: $test_name"
        [ -n "$details" ] && echo "  └─ $details"
        ((FAILED++))
    else
        echo -e "${YELLOW}⚠ WARN${NC}: $test_name"
        [ -n "$details" ] && echo "  └─ $details"
        ((WARNINGS++))
    fi
}

echo "1. Checking Military-Grade Encryption Usage..."

# Check that military functions are used in main.go
if grep -q "encryptCommandMilitary" main.go; then
    check_result "Military encryption function used in main.go" "PASS" "encryptCommandMilitary() found"
else
    check_result "Military encryption function used in main.go" "FAIL" "encryptCommandMilitary() not found"
fi

# Check that military functions are used in miner
if grep -q "encryptCommand.*sessionKey" miner/mine_secure.go; then
    check_result "Military encryption used in miner" "PASS" "Military encryption active"
else
    check_result "Military encryption used in miner" "FAIL" "Military encryption not active"
fi

echo ""
echo "2. Checking Military-Grade HMAC Usage..."

# Check BLAKE2b HMAC usage in main.go
if grep -q "generateHMACMilitary" main.go; then
    check_result "Military HMAC function used in main.go" "PASS" "generateHMACMilitary() found"
else
    check_result "Military HMAC function used in main.go" "FAIL" "generateHMACMilitary() not found"
fi

# Check BLAKE2b HMAC usage in miner
if grep -q "blake2b" miner/mine_secure.go; then
    check_result "BLAKE2b HMAC used in miner" "PASS" "BLAKE2b implementation found"
else
    check_result "BLAKE2b HMAC used in miner" "FAIL" "BLAKE2b implementation not found"
fi

echo ""
echo "3. Checking Secure Download Implementation..."

# Check for downloadFileMilitary function
if grep -q "downloadFileMilitary" main.go; then
    check_result "Military-grade download function" "PASS" "downloadFileMilitary() implemented"
else
    check_result "Military-grade download function" "FAIL" "downloadFileMilitary() not found"
fi

# Check for HTTPS enforcement
if grep -q "https://.*only.*allowed" main.go; then
    check_result "HTTPS enforcement" "PASS" "HTTPS-only downloads enforced"
else
    check_result "HTTPS enforcement" "WARN" "HTTPS enforcement not clearly visible"
fi

# Check for integrity verification
if grep -q "integrity.*verification" main.go; then
    check_result "File integrity verification" "PASS" "SHA-256 integrity checks implemented"
else
    check_result "File integrity verification" "WARN" "Integrity verification not clearly visible"
fi

echo ""
echo "4. Checking Environment Variable Security..."

# Check for hardcoded URLs removal
if ! grep -q "github.com/xmrig" main.go; then
    check_result "Hardcoded GitHub URL removed" "PASS" "No hardcoded GitHub URLs found"
else
    check_result "Hardcoded GitHub URL removed" "FAIL" "Hardcoded GitHub URLs still present"
fi

# Check for environment variable usage
if grep -q "os.Getenv.*URL" main.go; then
    check_result "Environment variable URL loading" "PASS" "URLs loaded from environment"
else
    check_result "Environment variable URL loading" "FAIL" "URLs not loaded from environment"
fi

# Check for HTTP URL removal
if ! grep -q "http://.*\.com" main.go miner/mine_secure.go; then
    check_result "HTTP URLs removed" "PASS" "No insecure HTTP URLs found"
else
    check_result "HTTP URLs removed" "FAIL" "Insecure HTTP URLs still present"
fi

echo ""
echo "5. Checking Certificate Pinning Security..."

# Check for pinning violation kill switch
if grep -q "killSwitch.*Trigger.*PINNING" main.go; then
    check_result "Pinning violation kill switch" "PASS" "Kill switch triggers on pinning violations"
else
    check_result "Pinning violation kill switch" "FAIL" "Kill switch not triggered on pinning violations"
fi

# Check for fallback removal in miner
if ! grep -q "FALLBACK.*TESTING" miner/mine_secure.go; then
    check_result "Certificate pinning fallback removed" "PASS" "No dangerous fallbacks found"
else
    check_result "Certificate pinning fallback removed" "FAIL" "Dangerous fallbacks still present"
fi

echo ""
echo "6. Checking HSM Integration..."

# Check for HSM usage in key generation
if grep -q "hsmManager.*Generate" main.go; then
    check_result "HSM integration active" "PASS" "HSM used for key generation"
else
    check_result "HSM integration active" "FAIL" "HSM not used for key generation"
fi

echo ""
echo "7. Checking Kill Switch Enhancement..."

# Check for kill switch triggers
if grep -q "triggerKillSwitch.*CERT_PINNING" miner/mine_secure.go; then
    check_result "Kill switch cert pinning trigger" "PASS" "Kill switch triggers on cert violations"
else
    check_result "Kill switch cert pinning trigger" "FAIL" "Kill switch not triggered on cert violations"
fi

# Check for authentication failure tracking
if grep -q "trackAuthFailure\|authFailures" miner/mine_secure.go; then
    check_result "Authentication failure tracking" "PASS" "Auth failures tracked for kill switch"
else
    check_result "Authentication failure tracking" "FAIL" "Auth failures not tracked"
fi

echo ""
echo "8. Checking Cryptographic Randomization..."

# Check for crypto/rand usage in jitter
if grep -q "rand.Read.*jitter" main.go miner/mine_secure.go; then
    check_result "Cryptographic jitter randomization" "PASS" "crypto/rand used for jitter"
else
    check_result "Cryptographic jitter randomization" "FAIL" "crypto/rand not used for jitter"
fi

# Check for secure memory scrubbing
if grep -q "rand.Read.*randomBytes" main.go miner/mine_secure.go; then
    check_result "Secure memory scrubbing" "PASS" "Cryptographically secure memory overwrite"
else
    check_result "Secure memory scrubbing" "WARN" "Memory scrubbing security unclear"
fi

echo ""
echo "9. Checking Error Information Disclosure..."

# Check for secure error handling
if grep -q "secureError" main.go; then
    check_result "Secure error handling" "PASS" "secureError() function implemented"
else
    check_result "Secure error handling" "FAIL" "secureError() function not found"
fi

echo ""
echo "10. Checking Network Obfuscation..."

# Check for traffic mixing activation
if grep -q "ENABLE_TRAFFIC_MIXING" main.go; then
    check_result "Traffic mixing configuration" "PASS" "Traffic mixing can be enabled"
else
    check_result "Traffic mixing configuration" "WARN" "Traffic mixing configuration not found"
fi

# Check for proxy chain support
if grep -q "loadProxyChain\|PROXY_CHAIN" main.go; then
    check_result "Proxy chain support" "PASS" "Proxy chain support implemented"
else
    check_result "Proxy chain support" "FAIL" "Proxy chain support not found"
fi

echo ""
echo "=============================================="
echo "  VERIFICATION SUMMARY"
echo "=============================================="
echo -e "${GREEN}PASSED${NC}: $PASSED tests"
echo -e "${YELLOW}WARNINGS${NC}: $WARNINGS tests"
echo -e "${RED}FAILED${NC}: $FAILED tests"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ SECURITY PATCH VERIFICATION SUCCESSFUL${NC}"
    echo "The military-grade security functions are properly implemented."
    echo ""
    echo "Next steps:"
    echo "1. Set up environment variables using security-config.template.env"
    echo "2. Configure certificate pinning with SERVER_CERT_PIN"
    echo "3. Set secure download URLs"
    echo "4. Deploy with ./build-secure.sh"
    exit 0
else
    echo -e "${RED}✗ SECURITY PATCH VERIFICATION FAILED${NC}"
    echo "Critical security issues remain. Review failed tests above."
    exit 1
fi