# x2y AV Ultimate v8.0.5

> Production-grade antivirus suite. Dark UI · No paid APIs · 100% Python

---

## Quick Start

```bash
# Windows
build.bat

# Linux / macOS
pip install -r requirements.txt
python main.py
```

---

## File Structure

```
x2y_av/
├── main.py            Entry point
├── app.py             Full UI — all 6 pages with right-click menus
├── scanner.py         Multi-layer scan engine (hash/ClamAV/YARA/PE/entropy)
├── netmon.py          Network monitor + block/kill/capture/WHOIS/MITRE
├── persistence.py     Startup auditor + disable/delete/analyze/STIX export
├── quarantine.py      Vault manager (SQLite-backed)
├── settings_mgr.py    Settings + background scheduler
├── theme.py           Colors and fonts
├── requirements.txt
├── build.bat          Windows one-click installer
├── README.md          This file
└── signatures/
    ├── hashes.db      SQLite hash database (auto-created)
    ├── yara/          Place .yar rule files here
    ├── ioc_c2_ips.txt Known C2 IP addresses (one per line)
    ├── urlhaus.txt    URLhaus malicious URLs (auto-downloaded)
    └── openphish.txt  OpenPhish phishing URLs (auto-downloaded)
```

---

## Pages & Features

### ⬚ Integrity Scan
- Quick Scan (temp/appdata/downloads)
- Full drive scan
- Scan single file or folder
- Scan history with clear button
- Auto-quarantine threats on detection

### ∿ Network Monitor
- Real-time connections via `psutil`
- Live traffic sparkline chart
- **Right-click a connection:**
  - 🔒 Block IP — `netsh advfirewall` (Win) / `iptables` (Linux)
  - ⚡ Terminate Process — `psutil.kill()`
  - 📡 Capture Traffic 10s — `scapy.sniff()` → `.pcap` file
  - 🔍 WHOIS Lookup — `ip-api.com` + raw WHOIS port 43 fallback
  - 🔎 Reverse DNS
  - 🎯 Tag as MITRE ATT&CK — T1078/T1059/T1041 etc., logged to `~/.x2y_av/mitre_tags.jsonl`
  - 📋 Copy IP / Process name
- Export all connections to CSV
- Suspicious heuristics:
  - Known C2 IPs (`signatures/ioc_c2_ips.txt`)
  - High-entropy domains (DGA detection)
  - Bad port+process combos (cmd.exe:443, powershell:80)
  - Known RAT ports (4444, 1337, 31337, etc.)

### 💾 Persistence Audit
- Windows: Registry Run keys (HKCU/HKLM), Startup Folder, Scheduled Tasks, WMI Startup, Services
- Linux: systemd, cron, init.d, rc.local, .bashrc hooks
- **Right-click an entry:**
  - 🚫 Disable — sets registry value to empty / renames file `.disabled`
  - 🗑 Delete Permanently — removes from registry + filesystem
  - 🔬 Analyze Behavior — heuristic score + PE import analysis + entropy
  - 📤 Export as STIX 2.1 — generates MISP/Splunk-compatible JSON
  - 🔍 Scan Parent Process — scans the parent PID's executable
  - 📋 Copy path / name
- Export all entries to CSV

### ☠ Quarantine Vault
- SQLite-backed manifest
- Right-click: Restore or Permanently Delete
- File info dialog (SHA256, original path, size, quarantine time)
- Delete All button

### 🌐 Threat Intelligence
- Signature update center with per-source buttons:
  - MalwareBazaar Recent (latest ~1000 hashes)
  - MalwareBazaar Full (entire DB — may be large)
  - URLhaus malicious URLs
  - OpenPhish phishing URLs
  - ClamAV freshclam
  - All Sources at once
- Real-time update log
- Hash lookup (SHA256 or MD5) against local DB
- Database statistics (total signatures, last update)

### ⚙ Settings & Policy
All settings are functional and persisted to `~/.x2y_av/settings.json`:
- **Threat Intelligence:** auto-update interval slider (1–72 hours)
- **Real-Time Protection:** Background Shield toggle, Auto-quarantine, Heuristic sensitivity (low/medium/high), Max scan file size slider
- **Startup:** Run on startup (writes Windows registry / Linux autostart .desktop)
- **Automated Tasks:** Daily Quick Scan with time picker, Weekly Full Scan with day + time picker
- **Exclusion Zones:** Add by typing or Browse button, remove with ✕
- **Quarantine:** Change vault directory
- **Notifications:** Desktop toast toggle
- **Logging:** Log level selector, Open Log File button

---

## Detection Layers

| Layer | Method | Detail |
|-------|--------|--------|
| 1 | **Hash DB** | SHA256 + MD5 lookup in SQLite. Seeded with EICAR. Updated from MalwareBazaar |
| 2 | **ClamAV** | clamd socket → clamscan binary fallback |
| 3 | **YARA** | yara-python rules from `signatures/yara/*.yar` |
| 4 | **PE Heuristics** | UPX/MPRESS/Themida packer detection, excessive sections |
| 5 | **String Patterns** | 20 regex patterns: PowerShell obfuscation, process injection, LOLBins, ransomware |
| 6 | **Entropy** | Files with >7.4 bits/byte flagged as possibly packed/encrypted |

---

## Setting Up ClamAV (Recommended)

ClamAV adds a professional scan engine with millions of signatures.

### Windows

1. Download from **https://www.clamav.net/downloads** (pick the `.msi` installer)
2. Install to default path (`C:\Program Files\ClamAV`)
3. Copy `freshclam.conf.sample` → `freshclam.conf`, remove the `Example` line
4. Run in CMD (admin):
   ```cmd
   cd "C:\Program Files\ClamAV"
   freshclam
   clamd --install-service
   net start clamd
   ```
5. Verify: `clamscan --version`

### Ubuntu / Debian

```bash
sudo apt install clamav clamav-daemon -y
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-daemon
sudo systemctl enable clamav-daemon
# Test
echo "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" > /tmp/eicar.txt
clamscan /tmp/eicar.txt
```

### macOS (Homebrew)

```bash
brew install clamav
cp /opt/homebrew/etc/clamav/freshclam.conf.sample /opt/homebrew/etc/clamav/freshclam.conf
sed -i '' 's/^Example//' /opt/homebrew/etc/clamav/freshclam.conf
freshclam
```

### Auto-Update ClamAV Signatures

`freshclam` self-schedules. To also update on app startup, enable
**"Auto-Update Signatures"** in Settings and include ClamAV in the update.

---

## Adding YARA Rules (Free)

1. Download community rules:
   ```bash
   # Yara-Rules project
   git clone https://github.com/Yara-Rules/rules.git signatures/yara/

   # Florian Roth signature base (excellent quality)
   git clone https://github.com/Neo23x0/signature-base.git signatures/yara/signature-base/
   ```
2. Only `.yar` files in `signatures/yara/` are loaded (not subdirectories).
   Copy or symlink specific rule files:
   ```bash
   cp signatures/yara/signature-base/yara/gen_*.yar signatures/yara/
   ```
3. Restart the app — YARA loads at startup.

Install the Python binding:
```bash
pip install yara-python
```

---

## Free Signature Sources

| Source | URL | Update method |
|--------|-----|---------------|
| **MalwareBazaar** | https://bazaar.abuse.ch | Threat Intel page → button |
| **URLhaus** | https://urlhaus.abuse.ch | Threat Intel page → button |
| **OpenPhish** | https://openphish.com | Threat Intel page → button |
| **ClamAV** | https://www.clamav.net | Settings → Update, or `freshclam` |
| **Yara-Rules** | https://github.com/Yara-Rules/rules | git pull + copy to signatures/yara/ |
| **signature-base** | https://github.com/Neo23x0/signature-base | git pull + copy to signatures/yara/ |
| **Abuse.ch IOCs** | https://feodotracker.abuse.ch/downloads/ipblocklist.csv | Save IPs to signatures/ioc_c2_ips.txt |

### Adding C2 IP IOCs

The file `signatures/ioc_c2_ips.txt` contains known C2 server IPs (one per line):
```
# Feodo Tracker C2 IPs
185.220.101.47
45.142.212.100
...
```

Download the latest Feodo Tracker blocklist:
```bash
curl https://feodotracker.abuse.ch/downloads/ipblocklist.txt > signatures/ioc_c2_ips.txt
```

---

## Optional Dependencies

| Package | Feature | Install |
|---------|---------|---------|
| `yara-python` | YARA rule scanning | `pip install yara-python` |
| `pefile` | PE binary behavior analysis | `pip install pefile` |
| `scapy` | Traffic capture to .pcap | `pip install scapy` |
| `watchdog` | Real-time file system shield | `pip install watchdog` |
| `wmi` | WMI startup query (Windows) | `pip install wmi` |

---

## Data Locations

| Data | Path |
|------|------|
| Settings | `~/.x2y_av/settings.json` |
| Scan history | `~/.x2y_av/scan_history.txt` |
| Log file | `~/.x2y_av/x2yav.log` |
| MITRE tags | `~/.x2y_av/mitre_tags.jsonl` |
| Quarantine vault | `~/.x2y_quarantine/` |
| Vault manifest | `~/.x2y_quarantine/vault.db` |
| Hash DB | `signatures/hashes.db` |
| YARA rules | `signatures/yara/` |
| C2 IOCs | `signatures/ioc_c2_ips.txt` |

---

## Running with Elevated Privileges (Recommended)

Some features require admin/root:
- Block IP via firewall (`netsh` / `iptables`)
- Packet capture (`scapy`)
- Scanning protected system directories
- Terminating system processes

```bash
# Windows (run CMD as Administrator, then:)
python main.py

# Linux
sudo python main.py
```

---

## Architecture

```
main.py
  └─ app.py (UI)
       ├─ ScanPage        → scanner.py
       ├─ NetworkPage     → netmon.py
       ├─ PersistencePage → persistence.py
       ├─ QuarantinePage  → quarantine.py
       ├─ ThreatIntelPage → scanner.py (updaters)
       └─ SettingsPage    → settings_mgr.py

Background:
  settings_mgr.Scheduler  (daemon thread)
    ├─ Daily quick scan
    ├─ Weekly full scan
    └─ Periodic sig updates

Storage:
  SQLite: signatures/hashes.db   (hash DB)
  SQLite: ~/.x2y_quarantine/vault.db
  JSON:   ~/.x2y_av/settings.json
```

---

## Version History

| Version | Changes |
|---------|---------|
| 8.0.5 | Right-click menus (Network + Persistence), STIX 2.1 export, MITRE tagging, WHOIS, traffic capture, behavior analysis, Threat Intel page, scheduler, full settings, auto-quarantine, ClamAV integration, YARA, entropy detection, MalwareBazaar + URLhaus + OpenPhish feeds |
| 5.0.0 | Initial release — basic scan, network monitor, persistence audit |