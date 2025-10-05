# MILITARY INFRASTRUCTURE INTEGRATION GUIDE
**Classification**: UNCLASSIFIED//FOR OFFICIAL USE ONLY  
**Date**: October 5, 2025  
**Version**: 1.0

## EXECUTIVE SUMMARY

This document provides comprehensive guidance for integrating HashLeech with existing military security infrastructure, including DoD PKI, SIPR/NIPR networks, Common Access Card (CAC) systems, and enterprise security tools.

## 1. DOD PKI INTEGRATION

### 1.1 CURRENT STATE ANALYSIS
**Implemented**: Basic PKI with self-signed certificates  
**Required**: Full DoD PKI integration with CAC support

### 1.2 DOD PKI REQUIREMENTS

#### Certificate Authority Hierarchy
```
DoD Root CA 2
    ├── DoD Interoperability Root CA 2
    │   ├── DoD EMAIL CA-33
    │   ├── DoD ID CA-33
    │   └── DoD SW CA-33
    └── DoD Component CAs
        ├── DoD Army CA
        ├── DoD Navy CA
        └── DoD Air Force CA
```

#### Implementation Strategy
```go
// pkg/dodpki/dodpki.go
package dodpki

import (
    "crypto/x509"
    "fmt"
    "strings"
)

type DoDPKIValidator struct {
    rootCAs      *x509.CertPool
    validOIDs    []string
    crlUrls      []string
}

func NewDoDPKIValidator() (*DoDPKIValidator, error) {
    validator := &DoDPKIValidator{
        rootCAs: x509.NewCertPool(),
        validOIDs: []string{
            "2.16.840.1.101.2.1.11.5",  // DoD ID certificate
            "2.16.840.1.101.2.1.11.18", // DoD EMAIL certificate
        },
    }
    
    // Load DoD root certificates
    if err := validator.loadDoDRootCAs(); err != nil {
        return nil, fmt.Errorf("failed to load DoD root CAs: %w", err)
    }
    
    return validator, nil
}

func (v *DoDPKIValidator) ValidateCertificate(cert *x509.Certificate) error {
    // Verify certificate chain
    opts := x509.VerifyOptions{
        Roots: v.rootCAs,
        KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
    }
    
    chains, err := cert.Verify(opts)
    if err != nil {
        return fmt.Errorf("certificate chain validation failed: %w", err)
    }
    
    // Verify this is a DoD certificate
    if !v.isDoDCertificate(cert) {
        return fmt.Errorf("certificate is not from DoD PKI")
    }
    
    // Extract and validate EDIPI
    edipi, err := v.extractEDIPI(cert)
    if err != nil {
        return fmt.Errorf("failed to extract EDIPI: %w", err)
    }
    
    if !v.validateEDIPI(edipi) {
        return fmt.Errorf("invalid EDIPI: %s", edipi)
    }
    
    // Check certificate revocation
    if err := v.checkRevocation(cert); err != nil {
        return fmt.Errorf("certificate revocation check failed: %w", err)
    }
    
    return nil
}

func (v *DoDPKIValidator) isDoDCertificate(cert *x509.Certificate) bool {
    // Check if certificate contains DoD OIDs
    for _, ext := range cert.Extensions {
        for _, validOID := range v.validOIDs {
            if ext.Id.String() == validOID {
                return true
            }
        }
    }
    
    // Check issuer DN
    issuer := cert.Issuer.String()
    return strings.Contains(issuer, "DoD") || 
           strings.Contains(issuer, "Department of Defense")
}

func (v *DoDPKIValidator) extractEDIPI(cert *x509.Certificate) (string, error) {
    // Extract EDIPI from Subject Alternative Name
    for _, name := range cert.Subject.Names {
        if name.Type.String() == "2.16.840.1.113730.3.1.39" { // EDIPI OID
            if edipi, ok := name.Value.(string); ok {
                return edipi, nil
            }
        }
    }
    
    // Fallback: extract from subject CN
    cn := cert.Subject.CommonName
    parts := strings.Split(cn, ".")
    if len(parts) >= 2 {
        return parts[len(parts)-1], nil // Last part should be EDIPI
    }
    
    return "", fmt.Errorf("EDIPI not found in certificate")
}

func (v *DoDPKIValidator) validateEDIPI(edipi string) bool {
    // EDIPI should be 10 digits
    if len(edipi) != 10 {
        return false
    }
    
    // All characters should be numeric
    for _, char := range edipi {
        if char < '0' || char > '9' {
            return false
        }
    }
    
    return true
}
```

### 1.3 CAC Integration
```go
// pkg/cac/cac.go
package cac

import (
    "crypto/x509"
    "fmt"
    "github.com/your-org/hashleech/pkg/dodpki"
)

type CACAuthenticator struct {
    pkiValidator *dodpki.DoDPKIValidator
    middleware   *CACMiddleware
}

func NewCACAuthenticator() (*CACAuthenticator, error) {
    validator, err := dodpki.NewDoDPKIValidator()
    if err != nil {
        return nil, err
    }
    
    return &CACAuthenticator{
        pkiValidator: validator,
        middleware:   NewCACMiddleware(),
    }, nil
}

func (c *CACAuthenticator) AuthenticateCAC(cert *x509.Certificate) (*CACIdentity, error) {
    // Validate DoD PKI certificate
    if err := c.pkiValidator.ValidateCertificate(cert); err != nil {
        return nil, fmt.Errorf("CAC validation failed: %w", err)
    }
    
    // Extract CAC identity information
    identity := &CACIdentity{
        EDIPI:      extractEDIPIFromCert(cert),
        LastName:   extractLastName(cert),
        FirstName:  extractFirstName(cert),
        MiddleName: extractMiddleName(cert),
        Rank:       extractRank(cert),
        Branch:     extractBranch(cert),
        ClearanceLevel: extractClearanceLevel(cert),
    }
    
    return identity, nil
}

type CACIdentity struct {
    EDIPI          string
    LastName       string
    FirstName      string
    MiddleName     string
    Rank           string
    Branch         string
    ClearanceLevel string
}
```

## 2. SIPR/NIPR NETWORK INTEGRATION

### 2.1 NETWORK CLASSIFICATION SUPPORT

#### Network Detection and Configuration
```go
// pkg/network/classification.go
package network

import (
    "net"
    "os"
    "strings"
)

type NetworkClassification string

const (
    UNCLASSIFIED NetworkClassification = "UNCLASSIFIED"
    CONFIDENTIAL NetworkClassification = "CONFIDENTIAL"
    SECRET       NetworkClassification = "SECRET"
    TOP_SECRET   NetworkClassification = "TOP_SECRET"
)

type NetworkConfig struct {
    Classification NetworkClassification
    Domain         string
    DNS            []string
    Proxy          string
    CACRequired    bool
    EncryptionSuite string
}

func DetectNetworkClassification() NetworkClassification {
    // Check environment variable first
    if env := os.Getenv("NETWORK_CLASSIFICATION"); env != "" {
        return NetworkClassification(env)
    }
    
    // Detect based on domain suffix
    hostname, err := os.Hostname()
    if err != nil {
        return UNCLASSIFIED
    }
    
    switch {
    case strings.HasSuffix(hostname, ".smil.mil"):
        return SECRET
    case strings.HasSuffix(hostname, ".nipr.mil"):
        return UNCLASSIFIED
    case strings.HasSuffix(hostname, ".gov"):
        return CONFIDENTIAL
    default:
        return UNCLASSIFIED
    }
}

func GetNetworkConfig(classification NetworkClassification) NetworkConfig {
    configs := map[NetworkClassification]NetworkConfig{
        UNCLASSIFIED: {
            Classification: UNCLASSIFIED,
            Domain:        ".nipr.mil",
            DNS:           []string{"8.8.8.8", "8.8.4.4"},
            Proxy:         "",
            CACRequired:   false,
            EncryptionSuite: "TLS_AES_256_GCM_SHA384",
        },
        SECRET: {
            Classification: SECRET,
            Domain:        ".smil.mil", 
            DNS:           []string{"10.0.0.1", "10.0.0.2"},
            Proxy:         "proxy.smil.mil:8080",
            CACRequired:   true,
            EncryptionSuite: "TLS_CHACHA20_POLY1305_SHA256",
        },
    }
    
    return configs[classification]
}
```

### 2.2 HAIPE INTEGRATION
```go
// pkg/haipe/haipe.go
package haipe

import (
    "crypto/tls"
    "fmt"
    "net"
)

type HAIPEConfig struct {
    Enabled        bool
    EncryptionSuite string
    KeyManagement  string
    DeviceID       string
}

type HAIPEConnector struct {
    config   HAIPEConfig
    device   *HAIPEDevice
}

func NewHAIPEConnector() (*HAIPEConnector, error) {
    config := HAIPEConfig{
        Enabled:        os.Getenv("HAIPE_ENABLED") == "true",
        EncryptionSuite: "Suite B",
        KeyManagement:  "NSA Type 1",
        DeviceID:       os.Getenv("HAIPE_DEVICE_ID"),
    }
    
    if !config.Enabled {
        return &HAIPEConnector{config: config}, nil
    }
    
    device, err := connectToHAIPE(config.DeviceID)
    if err != nil {
        return nil, fmt.Errorf("HAIPE connection failed: %w", err)
    }
    
    return &HAIPEConnector{
        config: config,
        device: device,
    }, nil
}

func (h *HAIPEConnector) CreateSecureConnection(addr string) (net.Conn, error) {
    if !h.config.Enabled {
        // Fallback to standard TLS
        return tls.Dial("tcp", addr, &tls.Config{
            MinVersion: tls.VersionTLS13,
        })
    }
    
    // Use HAIPE for encryption
    return h.device.SecureDial(addr)
}
```

## 3. ENTERPRISE SECURITY INTEGRATION

### 3.1 SIEM INTEGRATION

#### Splunk Integration
```go
// pkg/siem/splunk.go
package siem

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

type SplunkForwarder struct {
    endpoint string
    token    string
    client   *http.Client
}

func NewSplunkForwarder(endpoint, token string) *SplunkForwarder {
    return &SplunkForwarder{
        endpoint: endpoint,
        token:    token,
        client: &http.Client{
            Timeout: 10 * time.Second,
        },
    }
}

func (s *SplunkForwarder) SendEvent(event AuditEvent) error {
    splunkEvent := map[string]interface{}{
        "time":       event.Timestamp.Unix(),
        "host":       os.Hostname(),
        "source":     "hashleech",
        "sourcetype": "hashleech:audit",
        "event":      event,
    }
    
    jsonData, err := json.Marshal(splunkEvent)
    if err != nil {
        return err
    }
    
    req, err := http.NewRequest("POST", s.endpoint, bytes.NewBuffer(jsonData))
    if err != nil {
        return err
    }
    
    req.Header.Set("Authorization", "Splunk "+s.token)
    req.Header.Set("Content-Type", "application/json")
    
    resp, err := s.client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("splunk returned status %d", resp.StatusCode)
    }
    
    return nil
}
```

#### QRadar Integration
```go
// pkg/siem/qradar.go
package siem

import (
    "fmt"
    "net"
    "time"
)

type QRadarForwarder struct {
    syslogAddr string
    facility   int
    severity   int
}

func NewQRadarForwarder(addr string) *QRadarForwarder {
    return &QRadarForwarder{
        syslogAddr: addr,
        facility:   16, // Local use 0
        severity:   6,  // Info
    }
}

func (q *QRadarForwarder) SendEvent(event AuditEvent) error {
    // Format as CEF (Common Event Format)
    cef := fmt.Sprintf("CEF:0|YourOrg|HashLeech|1.0|%s|%s|%d|src=%s duser=%s act=%s outcome=%s",
        event.EventType,
        event.Action,
        q.mapSeverity(event.Severity),
        event.IPAddress,
        event.UserID,
        event.Action,
        event.Result,
    )
    
    // Send via syslog
    conn, err := net.Dial("udp", q.syslogAddr)
    if err != nil {
        return err
    }
    defer conn.Close()
    
    timestamp := event.Timestamp.Format(time.RFC3339)
    message := fmt.Sprintf("<%d>%s hostname hashleech: %s", 
        q.facility*8+q.severity, timestamp, cef)
    
    _, err = conn.Write([]byte(message))
    return err
}

func (q *QRadarForwarder) mapSeverity(severity string) int {
    switch severity {
    case "CRITICAL":
        return 10
    case "ERROR":
        return 7
    case "WARNING":
        return 5
    case "INFO":
        return 3
    default:
        return 1
    }
}
```

### 3.2 Active Directory Integration
```go
// pkg/ldap/ad.go
package ldap

import (
    "crypto/tls"
    "fmt"
    "github.com/go-ldap/ldap/v3"
)

type ADAuthenticator struct {
    conn     *ldap.Conn
    baseDN   string
    bindDN   string
    bindPass string
}

func NewADAuthenticator(server, baseDN, bindDN, bindPass string) (*ADAuthenticator, error) {
    conn, err := ldap.DialTLS("tcp", server, &tls.Config{
        ServerName: server,
    })
    if err != nil {
        return nil, err
    }
    
    err = conn.Bind(bindDN, bindPass)
    if err != nil {
        return nil, err
    }
    
    return &ADAuthenticator{
        conn:     conn,
        baseDN:   baseDN,
        bindDN:   bindDN,
        bindPass: bindPass,
    }, nil
}

func (ad *ADAuthenticator) ValidateUser(username, password string) (*ADUser, error) {
    // Search for user
    searchRequest := ldap.NewSearchRequest(
        ad.baseDN,
        ldap.ScopeWholeSubtree,
        ldap.NeverDerefAliases,
        0, 0, false,
        fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", username),
        []string{"dn", "cn", "mail", "memberOf", "department"},
        nil,
    )
    
    sr, err := ad.conn.Search(searchRequest)
    if err != nil {
        return nil, err
    }
    
    if len(sr.Entries) != 1 {
        return nil, fmt.Errorf("user not found or multiple entries")
    }
    
    userDN := sr.Entries[0].DN
    
    // Authenticate user
    err = ad.conn.Bind(userDN, password)
    if err != nil {
        return nil, fmt.Errorf("authentication failed")
    }
    
    // Rebind as service account
    err = ad.conn.Bind(ad.bindDN, ad.bindPass)
    if err != nil {
        return nil, err
    }
    
    // Return user information
    entry := sr.Entries[0]
    return &ADUser{
        DN:         entry.DN,
        Username:   username,
        CommonName: entry.GetAttributeValue("cn"),
        Email:      entry.GetAttributeValue("mail"),
        Department: entry.GetAttributeValue("department"),
        Groups:     entry.GetAttributeValues("memberOf"),
    }, nil
}

type ADUser struct {
    DN         string
    Username   string
    CommonName string
    Email      string
    Department string
    Groups     []string
}
```

## 4. COMPLIANCE INTEGRATION

### 4.1 STIG Compliance Automation
```bash
#!/bin/bash
# scripts/stig-compliance.sh

echo "Running STIG compliance checks..."

# RHEL 8 STIG V1R12 checks (example)
check_stig_v000001() {
    echo "V-230221: System must display Standard Mandatory DoD Notice"
    if [ -f /etc/issue ]; then
        grep -q "DoD" /etc/issue && echo "PASS" || echo "FAIL"
    else
        echo "FAIL - /etc/issue not found"
    fi
}

check_stig_v000002() {
    echo "V-230222: System must display Standard Mandatory DoD Notice (network)"
    if [ -f /etc/issue.net ]; then
        grep -q "DoD" /etc/issue.net && echo "PASS" || echo "FAIL"
    else
        echo "FAIL - /etc/issue.net not found"
    fi
}

# Run all STIG checks
check_stig_v000001
check_stig_v000002
# ... additional checks

echo "STIG compliance check complete"
```

### 4.2 SCAP Integration
```xml
<!-- scap/hashleech-security-guide.xml -->
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" 
           id="hashleech-security-guide" 
           xml:lang="en">
    <status>draft</status>
    <title>HashLeech Security Configuration Guide</title>
    <description>Security configuration guide for HashLeech Military C2</description>
    
    <Group id="encryption">
        <title>Cryptographic Controls</title>
        
        <Rule id="rule-fips-mode" severity="high">
            <title>FIPS Mode Must Be Enabled</title>
            <description>System must operate in FIPS 140-2 validated mode</description>
            <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
                <check-content-ref href="oval-hashleech.xml" name="oval:hashleech:def:1"/>
            </check>
        </Rule>
        
        <Rule id="rule-tls-version" severity="high">
            <title>TLS Version Requirements</title>
            <description>Only TLS 1.3 must be used for communications</description>
            <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
                <check-content-ref href="oval-hashleech.xml" name="oval:hashleech:def:2"/>
            </check>
        </Rule>
    </Group>
</Benchmark>
```

## 5. DEPLOYMENT CONFIGURATIONS

### 5.1 SIPR Network Deployment
```yaml
# config/sipr-deployment.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: hashleech-sipr-config
data:
  network-classification: "SECRET"
  domain-suffix: ".smil.mil"
  cac-required: "true"
  haipe-enabled: "true"
  proxy-url: "proxy.smil.mil:8080"
  dns-servers: "10.0.0.1,10.0.0.2"
  siem-endpoint: "splunk.smil.mil:8088"
  
---
apiVersion: v1
kind: Secret
metadata:
  name: hashleech-sipr-certs
type: Opaque
data:
  ca.crt: LS0tLS1CRUdJTi... # Base64 encoded DoD CA cert
  server.crt: LS0tLS1CRUdJTi... # Base64 encoded server cert
  server.key: LS0tLS1CRUdJTi... # Base64 encoded server key
```

### 5.2 NIPR Network Deployment
```yaml
# config/nipr-deployment.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: hashleech-nipr-config
data:
  network-classification: "UNCLASSIFIED"
  domain-suffix: ".nipr.mil"
  cac-required: "false"
  haipe-enabled: "false"
  proxy-url: ""
  dns-servers: "8.8.8.8,8.8.4.4"
  siem-endpoint: "qradar.nipr.mil:514"
```

## 6. INTEGRATION TESTING

### 6.1 CAC Authentication Test
```bash
#!/bin/bash
# tests/cac-integration-test.sh

echo "Testing CAC authentication..."

# Test with valid DoD CAC certificate
openssl s_client -connect localhost:7003 -cert test-cac.crt -key test-cac.key \
  -verify_return_error -brief 2>&1 | grep -q "Verification: OK" && echo "PASS" || echo "FAIL"

# Test with invalid certificate
openssl s_client -connect localhost:7003 -cert invalid.crt -key invalid.key \
  -verify_return_error -brief 2>&1 | grep -q "Verification: OK" && echo "FAIL" || echo "PASS"
```

### 6.2 SIEM Integration Test
```go
// tests/siem_test.go
func TestSIEMIntegration(t *testing.T) {
    // Test Splunk integration
    splunk := NewSplunkForwarder("https://splunk.mil:8088", "test-token")
    
    event := AuditEvent{
        Timestamp: time.Now(),
        EventType: "TEST",
        Action:    "INTEGRATION_TEST",
        Result:    "SUCCESS",
    }
    
    err := splunk.SendEvent(event)
    assert.NoError(t, err)
    
    // Test QRadar integration
    qradar := NewQRadarForwarder("qradar.mil:514")
    err = qradar.SendEvent(event)
    assert.NoError(t, err)
}
```

## 7. DEPLOYMENT CHECKLIST

### 7.1 Pre-Deployment
- [ ] DoD PKI certificates installed and validated
- [ ] CAC reader hardware configured
- [ ] SIPR/NIPR network configuration validated
- [ ] HAIPE devices configured (if required)
- [ ] SIEM integration tested
- [ ] Active Directory connectivity verified

### 7.2 Security Validation
- [ ] FIPS 140-2 mode enabled and validated
- [ ] TLS 1.3 enforced for all connections
- [ ] Certificate pinning configured
- [ ] Audit logging verified in SIEM
- [ ] STIG compliance checked
- [ ] Vulnerability scan completed

### 7.3 Operational Testing
- [ ] End-to-end communication test
- [ ] Failover and recovery procedures tested
- [ ] Performance baseline established
- [ ] Monitoring and alerting configured
- [ ] Incident response procedures validated

## 8. MAINTENANCE PROCEDURES

### 8.1 Certificate Management
```bash
#!/bin/bash
# scripts/cert-maintenance.sh

# Check certificate expiration
openssl x509 -in server.crt -noout -dates

# Renew certificates before expiration
if [ $(openssl x509 -in server.crt -noout -checkend 2592000) ]; then
    echo "Certificate expires within 30 days - renewal required"
    # Automated renewal process
fi

# Update certificate pinning
sha256sum server.crt | cut -d' ' -f1 > current-pin.txt
```

### 8.2 Security Updates
```bash
#!/bin/bash
# scripts/security-updates.sh

# Check for vulnerabilities
govulncheck ./...

# Update dependencies
go get -u all
go mod tidy

# Rebuild with latest security patches
make clean build

# Re-run security tests
make security-test
```

---
**Classification**: UNCLASSIFIED//FOR OFFICIAL USE ONLY  
**Distribution**: AUTHORIZED PERSONNEL ONLY  
**Next Review**: Quarterly