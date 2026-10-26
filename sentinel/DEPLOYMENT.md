# Aegis Sentinel // Production Hosting & Deployment Guide

This guide covers deploying the **Aegis Sentinel Unified Platform** (FastAPI Backend + React SOC HUD + Real-Time WebSocket Telemetry) in production using Docker & Docker Compose.

---

## 1. Architecture Overview

```
                                [ Operator / SOC Analyst ]
                                            │
                                            ▼  HTTPS (Port 443 / 8000)
┌─────────────────────────────────────────────────────────────────────────────┐
│ Docker Host / Cloud VPS (Ubuntu, Debian, or Windows Server)                 │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ Container: sentinel-server                                          │   │
│   │                                                                     │   │
│   │   ├── Port 8000: Unified HTTP & WebSocket                          │   │
│   │   ├── FastAPI REST Engine (/api/events, /api/incidents, etc.)       │   │
│   │   ├── WebSocket Telemetry Hub (/ws)                                 │   │
│   │   ├── React SOC HUD (Static files mounted on /)                     │   │
│   │   ├── Pure-Python ML Classifier & Platt Calibrator                  │   │
│   │   └── Forensics Generator (YARA, STIX 2.1, PCAP, Markdown)          │   │
│   │                                                                     │   │
│   │   Volumes:                                                          │   │
│   │     • sentinel_data       -> /app/data/sentinel.db (SQLite)         │   │
│   │     • sentinel_evidence   -> /app/sandbox_evidence                  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────▲──────────────────────────────────────┘
                                       │
                      Telemtry Stream  │ (POST /api/events, WS /ws)
                                       │
     ┌─────────────────────────────────┴─────────────────────────────────┐
     │ Protected Endpoints (Windows Workstations, Linux File Servers)     │
     │   • endpoint.agent --watch C:\Data --url https://sentinel.corp... │
     │   • Shannon Entropy Analyzer + OpenXML/PDF Canary Monitors        │
     │   • Win32 Killswitch Mutexes (WannaCry, LockBit vaccine)          │
     └───────────────────────────────────────────────────────────────────┘
```

---

## 2. Quickstart with Docker Compose

### Prerequisites
- Docker Engine $\ge 24.0$
- Docker Compose v2 (`docker compose`)

### Step 1: Clone and Configure Environment
```bash
git clone https://github.com/Helan-Rogy/Sentinel.git
cd Sentinel

# Copy environment template
cp .env.example .env
```

Edit `.env` to configure your production security token:
```ini
SENTINEL_TOKEN=generate-a-strong-secret-token-here
PORT=8000
SENTINEL_ALLOW_SUSPEND=1
SENTINEL_ALLOW_AUTO_CONTAIN=0
```

### Step 2: Build and Launch Containers
```bash
docker compose up --build -d
```

### Step 3: Verify Status & Health
```bash
# Check container status
docker compose ps

# Check backend health
curl -f http://localhost:8000/api/health

# View live container logs
docker compose logs -f sentinel-server
```

### Step 4: Open the SOC HUD
Open your browser to:
```
http://<your-server-ip>:8000
```
Enter your `SENTINEL_TOKEN` when prompted on the lockscreen to access the HUD.

---

## 3. Production Cloud VPS Deployment (Ubuntu / Debian / AWS EC2)

For production internet-facing deployments with custom domains and SSL (HTTPS), place **Nginx** in front of Sentinel.

### Step 1: Install Nginx and Certbot
```bash
sudo apt update && sudo apt install -y nginx certbot python3-certbot-nginx
```

### Step 2: Configure Nginx Reverse Proxy
Create `/etc/nginx/sites-available/sentinel`:

```nginx
server {
    server_name sentinel.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
```

Enable the site and obtain a free SSL certificate:
```bash
sudo ln -s /etc/nginx/sites-available/sentinel /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d sentinel.yourdomain.com
```

Your Aegis Sentinel HUD is now live at `https://sentinel.yourdomain.com` with TLS encryption!

---

## 4. Connecting Remote Endpoints to the Central Server

Protected machines run the lightweight Sentinel Endpoint Agent to monitor local filesystems and stream telemetry back to your hosted server.

### On Protected Windows Workstations / Servers:
```powershell
# In PowerShell:
cd C:\Sentinel
.venv\Scripts\python.exe -m endpoint.agent `
    --watch "C:\Users\Helan\Documents" `
    --url "https://sentinel.yourdomain.com" `
    --token "generate-a-strong-secret-token-here"
```

### On Protected Linux File Servers:
```bash
python3 -m endpoint.agent \
    --watch /var/shared/finance \
    --url https://sentinel.yourdomain.com \
    --token generate-a-strong-secret-token-here
```

When an attack occurs on any protected machine, telemetry is streamed in real time to the central server, the ML classifier evaluates risk, and the incident immediately surfaces on the central HUD for one-click containment and Kali sandbox detonation.

---

## 5. Maintenance, Backups & Operations

### Database Backups
All incident dossiers, audit logs, and risk assessments are stored in SQLite inside the `sentinel_data` volume:
```bash
# Backup database without stopping container:
docker compose exec sentinel-server sqlite3 /app/data/sentinel.db ".backup '/app/data/backup_$(date +%Y%m%d).db'"

# Copy backup to host:
docker compose cp sentinel-server:/app/data/backup_*.db ./backups/
```

### Stopping and Updating
```bash
# Stop stack
docker compose down

# Update and rebuild
git pull
docker compose up --build -d
```
