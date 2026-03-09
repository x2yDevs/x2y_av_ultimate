"""
x2y AV Ultimate v8.0.5 - Scanner Engine
Detection layers:
  1. ClamAV via clamd socket / clamscan subprocess
  2. Local SHA256/MD5 hash DB (SQLite, auto-updated from MalwareBazaar/URLhaus daily)
  3. YARA rules (yara-python if installed, else pattern fallback)
  4. PE heuristics (UPX, MPRESS, Themida, section anomalies)
  5. String pattern matching (PowerShell, injection, LOLBins, ransomware)
  6. Entropy analysis (packed/encrypted payloads > 7.4 bits)
"""

import os, re, sys, json, math, time, struct, hashlib, logging, sqlite3
import threading, subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

log = logging.getLogger("x2yav.scanner")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SIG_DIR  = os.path.join(BASE_DIR, "signatures")
DB_PATH  = os.path.join(SIG_DIR, "hashes.db")
YARA_DIR = os.path.join(SIG_DIR, "yara")
IOC_PATH = os.path.join(SIG_DIR, "ioc_c2_ips.txt")
os.makedirs(SIG_DIR, exist_ok=True)
os.makedirs(YARA_DIR, exist_ok=True)

BUILTIN_HASHES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-File",
}

RAW_PATTERNS = [
    (rb"cmd\.exe.{0,40}/c.{0,120}powershell",           "SuspCmd.PowerShell"),
    (rb"powershell.{0,30}-[Ee]n[Cc]",                   "Obfuscated.PowerShell"),
    (rb"powershell.{0,30}-[Ww]indow[Ss]tyle.{0,20}[Hh]idden", "Hidden.PowerShell"),
    (rb"VirtualAlloc.{0,80}WriteProcessMemory",          "ProcessInjection.Classic"),
    (rb"CreateRemoteThread",                             "ProcessInjection.RemoteThread"),
    (rb"NtUnmapViewOfSection",                           "ProcessHollowing"),
    (rb"IsDebuggerPresent",                              "AntiDebug.IsDebuggerPresent"),
    (rb"CheckRemoteDebuggerPresent",                     "AntiDebug.Remote"),
    (rb"RegSetValueEx.{0,80}CurrentVersion\\\\Run",      "Persistence.RegistryRun"),
    (rb"\\\\Device\\\\PhysicalMemory",                   "PrivilegeEsc.PhysicalMem"),
    (rb"net user.{0,40}\/add",                           "Lateral.AddUser"),
    (rb"certutil.{0,40}-decode",                         "LOLBin.CertutilDecode"),
    (rb"mshta.{0,60}http",                               "LOLBin.MshtaRemote"),
    (rb"regsvr32.{0,60}/[Ss]",                           "LOLBin.Regsvr32"),
    (rb"bitsadmin.{0,60}/transfer",                      "LOLBin.BITSAdmin"),
    (rb"schtasks.{0,60}/create",                         "Persistence.ScheduledTask"),
    (rb"bcdedit.{0,40}recoveryenabled.{0,10}no",         "Ransomware.DisableRecovery"),
    (rb"vssadmin.{0,40}delete shadows",                  "Ransomware.DeleteShadows"),
    (rb"wbadmin.{0,40}delete catalog",                   "Ransomware.DeleteCatalog"),
    (rb"wscript.{0,60}\.vbs",                            "Script.WScript"),
]
COMPILED_PATTERNS = [(re.compile(p, re.I | re.S), n) for p, n in RAW_PATTERNS]

# ── C2 IPs ────────────────────────────────────────────────────────────────────
C2_IPS: set = set()
def reload_c2_ips():
    global C2_IPS
    if os.path.exists(IOC_PATH):
        with open(IOC_PATH) as f:
            C2_IPS = {l.strip() for l in f if l.strip() and not l.startswith("#")}
reload_c2_ips()

# ── Hash DB ───────────────────────────────────────────────────────────────────
class HashDB:
    def __init__(self, path=DB_PATH):
        self.path = path
        self._lock = threading.Lock()
        self._init()

    def _init(self):
        with sqlite3.connect(self.path) as c:
            c.execute("""CREATE TABLE IF NOT EXISTS hashes(
                hash TEXT PRIMARY KEY, name TEXT NOT NULL,
                source TEXT DEFAULT 'builtin',
                added_at TEXT DEFAULT(datetime('now')))""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_h ON hashes(hash)")
            for h, n in BUILTIN_HASHES.items():
                c.execute("INSERT OR IGNORE INTO hashes(hash,name) VALUES(?,?)", (h, n))
            c.commit()

    def lookup(self, h: str) -> Optional[str]:
        with self._lock:
            with sqlite3.connect(self.path) as c:
                r = c.execute("SELECT name FROM hashes WHERE hash=?", (h,)).fetchone()
                return r[0] if r else None

    def bulk_insert(self, rows: list, source: str = "external"):
        with self._lock:
            with sqlite3.connect(self.path) as c:
                c.executemany("INSERT OR IGNORE INTO hashes(hash,name,source) VALUES(?,?,?)",
                              [(h, n, source) for h, n in rows])
                c.commit()

    def count(self) -> int:
        with sqlite3.connect(self.path) as c:
            return c.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]

# ── YARA ──────────────────────────────────────────────────────────────────────
_YARA = None
def _load_yara():
    global _YARA
    try:
        import yara
        fps = {f.stem: str(f) for f in Path(YARA_DIR).glob("*.yar")}
        if fps:
            _YARA = yara.compile(filepaths=fps)
            log.info(f"YARA: {len(fps)} rule files loaded")
    except ImportError:
        pass
    except Exception as e:
        log.warning(f"YARA: {e}")
_load_yara()

def yara_scan(filepath: str) -> Optional[str]:
    if not _YARA:
        return None
    try:
        m = _YARA.match(filepath, timeout=30)
        return m[0].rule if m else None
    except Exception:
        return None

# ── Entropy ───────────────────────────────────────────────────────────────────
def byte_entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = [0] * 256
    for b in data: freq[b] += 1
    n = len(data)
    return -sum((c/n)*math.log2(c/n) for c in freq if c)

# ── PE Heuristics ─────────────────────────────────────────────────────────────
def pe_heuristic(data: bytes) -> Optional[str]:
    if len(data) < 64 or data[:2] != b"MZ": return None
    try:
        off = struct.unpack_from("<I", data, 0x3C)[0]
        if off + 24 > len(data) or data[off:off+4] != b"PE\x00\x00": return None
        for sig in (b"UPX0", b"UPX1"):
            if sig in data[:512]: return "Packer.UPX"
        for sig in (b"MPRESS1", b"MPRESS2"):
            if sig in data[:512]: return "Packer.MPRESS"
        if b"Themida" in data[:2048]: return "Packer.Themida"
        secs = struct.unpack_from("<H", data, off + 6)[0]
        if secs > 25: return "Heuristic.ExcessiveSections"
    except Exception:
        pass
    return None

# ── ClamAV ────────────────────────────────────────────────────────────────────
def clam_scan(filepath: str) -> Optional[str]:
    import socket as _s
    for ctl in ("/var/run/clamav/clamd.ctl", "/tmp/clamd.socket"):
        if os.path.exists(ctl):
            try:
                s = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
                s.settimeout(10)
                s.connect(ctl)
                s.send(b"SCAN " + filepath.encode() + b"\n")
                resp = s.recv(4096).decode(errors="ignore")
                s.close()
                if "FOUND" in resp:
                    return resp.split(":")[-1].replace(" FOUND","").strip()
                return None
            except Exception:
                pass
    try:
        r = subprocess.run(["clamscan","--no-summary","--infected", filepath],
                           capture_output=True, text=True, timeout=60)
        if r.returncode == 1:
            for l in r.stdout.splitlines():
                if "FOUND" in l:
                    return l.split(":")[-1].replace(" FOUND","").strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None

# ── Result ────────────────────────────────────────────────────────────────────
@dataclass
class ScanResult:
    filepath: str
    status: str = "clean"
    threat_name: str = ""
    detection_type: str = ""
    sha256: str = ""
    md5: str = ""
    file_size: int = 0
    entropy: float = 0.0
    scan_time: float = 0.0

# ── Engine ────────────────────────────────────────────────────────────────────
class ScannerEngine:
    def __init__(self):
        self.db = HashDB()

    def hash_file(self, path: str) -> tuple:
        md5, sha = hashlib.md5(), hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk); sha.update(chunk)
        return md5.hexdigest(), sha.hexdigest()

    def scan_file(self, filepath: str) -> ScanResult:
        t0 = time.time()
        r = ScanResult(filepath=filepath)
        try:
            r.file_size = os.path.getsize(filepath)
            r.md5, r.sha256 = self.hash_file(filepath)

            hit = self.db.lookup(r.sha256) or self.db.lookup(r.md5)
            if hit:
                r.status, r.threat_name, r.detection_type = "threat", hit, "hash"
                r.scan_time = time.time()-t0; return r

            clam = clam_scan(filepath)
            if clam:
                r.status, r.threat_name, r.detection_type = "threat", clam, "clamav"
                r.scan_time = time.time()-t0; return r

            yara_hit = yara_scan(filepath)
            if yara_hit:
                r.status, r.threat_name, r.detection_type = "suspicious", yara_hit, "yara"
                r.scan_time = time.time()-t0; return r

            if r.file_size < 32 * 1024 * 1024:
                with open(filepath, "rb") as f:
                    data = f.read()
                r.entropy = byte_entropy(data[:65536])
                pe = pe_heuristic(data)
                if pe:
                    r.status, r.threat_name, r.detection_type = "suspicious", pe, "heuristic"
                    r.scan_time = time.time()-t0; return r
                for pat, name in COMPILED_PATTERNS:
                    if pat.search(data):
                        r.status, r.threat_name, r.detection_type = "suspicious", name, "pattern"
                        r.scan_time = time.time()-t0; return r
                if r.entropy > 7.4:
                    r.status, r.threat_name, r.detection_type = "suspicious", "HighEntropy.PossiblyPacked", "entropy"
                    r.scan_time = time.time()-t0; return r
            r.status = "clean"
        except PermissionError:
            r.status, r.threat_name, r.detection_type = "error", "PermissionDenied", "error"
        except Exception as e:
            r.status, r.threat_name, r.detection_type = "error", str(e)[:80], "error"
        r.scan_time = time.time()-t0
        return r

    def scan_directory(self, directory: str, callback: Callable,
                       stop_event: threading.Event, progress_cb=None):
        skip = {"proc","sys","dev","$Recycle.Bin","WinSxS","__pycache__",".git"}
        try:
            import settings_mgr
            excl = set(settings_mgr.get("exclusion_zones") or [])
        except Exception:
            excl = set()
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in skip
                       and os.path.join(root,d) not in excl]
            if stop_event.is_set(): return
            if root in excl: continue
            for fname in files:
                if stop_event.is_set(): return
                fp = os.path.join(root, fname)
                if fp in excl: continue
                if progress_cb: progress_cb(fp)
                try: callback(self.scan_file(fp))
                except Exception: pass

    def get_quick_scan_dirs(self):
        if sys.platform == "win32":
            d = [os.path.expandvars(p) for p in
                 ["%TEMP%","%APPDATA%","%LOCALAPPDATA%\\Temp"]]
            d += [os.path.expanduser("~/Downloads"), os.path.expanduser("~/Desktop")]
        else:
            d = ["/tmp","/var/tmp", os.path.expanduser("~/Downloads")]
        return [x for x in d if os.path.isdir(x)]

    def scan_pid(self, pid: int) -> ScanResult:
        try:
            import psutil
            return self.scan_file(psutil.Process(pid).exe())
        except Exception as e:
            return ScanResult(filepath=f"pid:{pid}", status="error",
                              threat_name=str(e), detection_type="error")

# ── Updaters ──────────────────────────────────────────────────────────────────
BAZAAR_RECENT = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
BAZAAR_FULL   = "https://bazaar.abuse.ch/export/txt/sha256/full/"
URLHAUS_URL   = "https://urlhaus.abuse.ch/downloads/text/"
OPENPHISH_URL = "https://openphish.com/feed.txt"

def _fetch(url: str, timeout=60) -> Optional[str]:
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="ignore")
    except Exception as e:
        log.error(f"Fetch failed {url}: {e}")
        return None

def update_malwarebazaar(db: HashDB, full=False, cb=None) -> int:
    url = BAZAAR_FULL if full else BAZAAR_RECENT
    if cb: cb(f"↓ MalwareBazaar {'full' if full else 'recent'} feed...")
    text = _fetch(url)
    if not text: return 0
    rows = [(l.strip(), "MalwareBazaar") for l in text.splitlines()
            if l.strip() and not l.startswith("#") and len(l.strip())==64]
    if rows:
        db.bulk_insert(rows, "malwarebazaar")
    if cb: cb(f"✔ MalwareBazaar: +{len(rows)} hashes")
    return len(rows)

def update_urlhaus(cb=None) -> int:
    if cb: cb("↓ URLhaus malicious URL feed...")
    text = _fetch(URLHAUS_URL)
    if not text: return 0
    urls = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")]
    path = os.path.join(SIG_DIR, "urlhaus.txt")
    with open(path, "w") as f: f.write("\n".join(urls))
    if cb: cb(f"✔ URLhaus: {len(urls)} malicious URLs saved")
    return len(urls)

def update_openphish(cb=None) -> int:
    if cb: cb("↓ OpenPhish feed...")
    text = _fetch(OPENPHISH_URL)
    if not text: return 0
    urls = [l.strip() for l in text.splitlines() if l.strip()]
    path = os.path.join(SIG_DIR, "openphish.txt")
    with open(path, "w") as f: f.write("\n".join(urls))
    if cb: cb(f"✔ OpenPhish: {len(urls)} phishing URLs saved")
    return len(urls)

def update_clamav(cb=None) -> bool:
    if cb: cb("↓ Running freshclam (ClamAV)...")
    try:
        r = subprocess.run(["freshclam"], capture_output=True, text=True, timeout=180)
        ok = r.returncode == 0
        if cb: cb("✔ ClamAV updated" if ok else f"⚠ freshclam: {r.stderr[:80]}")
        return ok
    except FileNotFoundError:
        if cb: cb("⚠ freshclam not found — install ClamAV (see README)")
        return False

def full_sig_update(db: HashDB, cb=None) -> dict:
    res = {}
    res["malwarebazaar"] = update_malwarebazaar(db, cb=cb)
    res["urlhaus"]       = update_urlhaus(cb=cb)
    res["openphish"]     = update_openphish(cb=cb)
    res["clamav"]        = update_clamav(cb=cb)
    res["total_hashes"]  = db.count()
    import settings_mgr
    settings_mgr.set_val("signatures_loaded", res["total_hashes"])
    settings_mgr.set_val("last_sig_update", time.strftime("%Y-%m-%d %H:%M:%S"))
    return res