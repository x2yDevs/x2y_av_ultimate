"""
x2y AV Ultimate v8.0.5 - Settings Manager
Persists all config to ~/.x2y_av/settings.json
Includes background scheduler for daily scans and sig updates.
"""

import os, json, time, threading, logging
from typing import Optional  # <--- ADD THIS LINE TO FIX THE ERROR

log = logging.getLogger("x2yav.settings")

SETTINGS_DIR  = os.path.join(os.path.expanduser("~"), ".x2y_av")
SETTINGS_PATH = os.path.join(SETTINGS_DIR, "settings.json")
LOG_PATH      = os.path.join(SETTINGS_DIR, "x2yav.log")
os.makedirs(SETTINGS_DIR, exist_ok=True)

DEFAULTS = {
    # Real-time
    "background_shield":       True,
    "run_on_startup":          False,
    # Scans
    "daily_quick_scan":        False,
    "daily_quick_scan_time":   "02:00",   # HH:MM
    "weekly_full_scan":        False,
    "weekly_full_scan_day":    "Sunday",
    "weekly_full_scan_time":   "03:00",
    # Sig updates
    "auto_sig_update":         True,
    "sig_update_interval_h":   24,
    "last_sig_update":         "",
    "signatures_loaded":       0,
    # Exclusions
    "exclusion_zones":         [],
    # Quarantine
    "auto_quarantine":         True,
    "quarantine_dir":          os.path.join(os.path.expanduser("~"), ".x2y_quarantine"),
    # Alerts
    "show_notifications":      True,
    # Logging
    "log_level":               "INFO",
    # Advanced
    "max_file_size_mb":        32,
    "scan_archives":           False,
    "heuristic_sensitivity":   "medium",   # low | medium | high
}


def load() -> dict:
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH) as f:
                data = json.load(f)
            return {**DEFAULTS, **data}
        except Exception:
            pass
    return dict(DEFAULTS)


def save(settings: dict):
    os.makedirs(SETTINGS_DIR, exist_ok=True)
    with open(SETTINGS_PATH, "w") as f:
        json.dump(settings, f, indent=2)


def get(key: str):
    return load().get(key, DEFAULTS.get(key))


def set_val(key: str, value):
    s = load()
    s[key] = value
    save(s)


# Convenience aliases used by app.py
load_settings = load
save_settings  = save


# ── Startup registration ──────────────────────────────────────────────────────
def enable_startup(enable: bool):
    import sys
    exe = sys.executable
    script = os.path.abspath(os.path.join(os.path.dirname(__file__), "main.py"))
    cmd = f'"{exe}" "{script}"'

    if sys.platform == "win32":
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            if enable:
                winreg.SetValueEx(key, "x2yAVUltimate", 0, winreg.REG_SZ, cmd)
            else:
                try: winreg.DeleteValue(key, "x2yAVUltimate")
                except Exception: pass
            winreg.CloseKey(key)
            set_val("run_on_startup", enable)
            return True, "Startup entry updated"
        except Exception as e:
            return False, str(e)
    else:
        autostart = os.path.expanduser("~/.config/autostart/x2yav.desktop")
        if enable:
            os.makedirs(os.path.dirname(autostart), exist_ok=True)
            with open(autostart, "w") as f:
                f.write(f"[Desktop Entry]\nType=Application\nName=x2y AV Ultimate\n"
                        f"Exec={cmd}\nHidden=false\nX-GNOME-Autostart-enabled=true\n")
        elif os.path.exists(autostart):
            os.remove(autostart)
        set_val("run_on_startup", enable)
        return True, "Autostart updated"


# ── Background scheduler ──────────────────────────────────────────────────────
class Scheduler(threading.Thread):
    """Runs periodic tasks: daily quick scan, weekly full scan, sig updates."""

    def __init__(self):
        super().__init__(daemon=True, name="x2yAV-Scheduler")
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        log.info("Scheduler started")
        while not self._stop.wait(60):   # check every minute
            s = load()
            now = time.strftime("%H:%M")
            day = time.strftime("%A")

            # Daily quick scan
            if s.get("daily_quick_scan") and now == s.get("daily_quick_scan_time","02:00"):
                self._run_quick_scan()

            # Weekly full scan
            if (s.get("weekly_full_scan") and day == s.get("weekly_full_scan_day","Sunday")
                    and now == s.get("weekly_full_scan_time","03:00")):
                self._run_full_scan()

            # Auto sig update
            if s.get("auto_sig_update"):
                last = s.get("last_sig_update","")
                interval = s.get("sig_update_interval_h", 24)
                if self._hours_since(last) >= interval:
                    self._run_sig_update()

    @staticmethod
    def _hours_since(ts_str: str) -> float:
        if not ts_str:
            return 9999.0
        try:
            t = time.mktime(time.strptime(ts_str, "%Y-%m-%d %H:%M:%S"))
            return (time.time() - t) / 3600
        except Exception:
            return 9999.0

    def _run_quick_scan(self):
        log.info("Scheduler: quick scan starting")
        try:
            import scanner as sc
            engine = sc.ScannerEngine()
            stop = threading.Event()
            threats = []
            for d in engine.get_quick_scan_dirs():
                engine.scan_directory(d, lambda r: threats.append(r) if r.status=="threat" else None, stop)
            log.info(f"Scheduler quick scan done: {len(threats)} threats")
        except Exception as e:
            log.error(f"Scheduler quick scan: {e}")

    def _run_full_scan(self):
        log.info("Scheduler: full scan starting")
        try:
            import scanner as sc
            root = "C:\\" if __import__("sys").platform=="win32" else "/"
            engine = sc.ScannerEngine()
            stop = threading.Event()
            engine.scan_directory(root, lambda r: None, stop)
            log.info("Scheduler full scan done")
        except Exception as e:
            log.error(f"Scheduler full scan: {e}")

    def _run_sig_update(self):
        log.info("Scheduler: signature update starting")
        try:
            import scanner as sc
            sc.full_sig_update(sc.ScannerEngine().db, cb=log.info)
            log.info("Scheduler: signatures updated")
        except Exception as e:
            log.error(f"Scheduler sig update: {e}")


_scheduler: Optional[Scheduler] = None

def start_scheduler():
    global _scheduler
    if _scheduler and _scheduler.is_alive():
        return
    _scheduler = Scheduler()
    _scheduler.start()

def stop_scheduler():
    global _scheduler
    if _scheduler:
        _scheduler.stop()