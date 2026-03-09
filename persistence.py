"""
x2y AV Ultimate v8.0.5 - Persistence Auditor
Windows: winreg Run keys, WMI startup commands, Scheduled Tasks, Services
Linux: systemd, cron, init.d, rc.local, ~/.bashrc hooks
Right-click: Disable, Delete, Analyze, Export STIX 2.1, Scan Parent PID
"""

import os, sys, json, time, logging, subprocess, threading
from dataclasses import dataclass, asdict
from typing import Optional

log = logging.getLogger("x2yav.persistence")

SUSPICIOUS_KEYWORDS = [
    "temp","tmp","appdata\\local\\temp",
    "powershell -enc","cmd /c","wscript","cscript",
    "mshta","regsvr32","rundll32","certutil","bitsadmin",
    "%temp%","%tmp%","curl ","wget ","invoke-expression",
    "iex(","bypass","hidden","encodedcommand",
]

MITRE_MAP = {
    "Registry [HKCU]": "T1547.001 - Registry Run Keys (HKCU)",
    "Registry [HKLM]": "T1547.001 - Registry Run Keys (HKLM)",
    "Startup Folder":  "T1547.001 - Startup Folder",
    "Scheduled Task":  "T1053.005 - Scheduled Task",
    "Service":         "T1543.003 - Windows Service",
    "WMI Startup":     "T1546.003 - WMI Event Subscription",
    "Systemd":         "T1543.002 - Systemd Service",
    "Cron":            "T1053.003 - Cron Job",
}


@dataclass
class PersistenceEntry:
    name:        str
    entry_type:  str
    path:        str
    risk:        str = "normal"     # normal | suspicious
    reg_hive:    str = ""           # for registry entries: full key path
    reg_value:   str = ""
    mitre:       str = ""


def _assess(path: str) -> str:
    lo = path.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lo:
            return "suspicious"
    return "normal"


# ── Windows audit ─────────────────────────────────────────────────────────────
def _win_registry() -> list[PersistenceEntry]:
    import winreg
    entries = []
    keys = [
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run",     "Registry [HKCU]"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run",     "Registry [HKLM]"),
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "Registry [HKCU]"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "Registry [HKLM]"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Registry [HKLM]"),
    ]
    for hive, key_path, label in keys:
        try:
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(key, i)
                    risk = _assess(str(val))
                    entries.append(PersistenceEntry(
                        name=name, entry_type=label, path=str(val),
                        risk=risk, reg_hive=key_path, reg_value=name,
                        mitre=MITRE_MAP.get(label,"")
                    ))
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass
    return entries


def _win_startup_folder() -> list[PersistenceEntry]:
    entries = []
    for base in [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.expandvars(r"%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup"),
    ]:
        if os.path.isdir(base):
            for f in os.listdir(base):
                fp = os.path.join(base, f)
                entries.append(PersistenceEntry(
                    name=f, entry_type="Startup Folder", path=fp,
                    risk=_assess(fp), mitre=MITRE_MAP["Startup Folder"]
                ))
    return entries


def _win_scheduled_tasks() -> list[PersistenceEntry]:
    entries = []
    try:
        r = subprocess.run(
            ["schtasks","/query","/fo","CSV","/v"],
            capture_output=True, text=True, timeout=15
        )
        lines = r.stdout.splitlines()
        for line in lines[1:]:
            parts = line.split('","')
            if len(parts) > 8:
                name = parts[0].strip('"')
                cmd  = parts[8].strip('"') if len(parts)>8 else ""
                if name and cmd:
                    entries.append(PersistenceEntry(
                        name=name, entry_type="Scheduled Task", path=cmd,
                        risk=_assess(cmd), mitre=MITRE_MAP["Scheduled Task"]
                    ))
    except Exception:
        pass
    return entries


def _win_wmi() -> list[PersistenceEntry]:
    entries = []
    try:
        import wmi
        c = wmi.WMI()
        for item in c.Win32_StartupCommand():
            entries.append(PersistenceEntry(
                name=item.Name, entry_type="WMI Startup",
                path=item.Command or "",
                risk=_assess(item.Command or ""),
                mitre=MITRE_MAP["WMI Startup"]
            ))
    except Exception:
        pass
    return entries


def _win_services() -> list[PersistenceEntry]:
    entries = []
    try:
        r = subprocess.run(
            ["sc","query","type=","all","state=","all"],
            capture_output=True, text=True, timeout=15
        )
        # Simple parse — just get service names
        for line in r.stdout.splitlines():
            if line.strip().startswith("SERVICE_NAME:"):
                name = line.split(":",1)[1].strip()
                entries.append(PersistenceEntry(
                    name=name, entry_type="Service",
                    path=f"Service: {name}",
                    risk="normal", mitre=MITRE_MAP["Service"]
                ))
    except Exception:
        pass
    return entries[:30]  # cap at 30 for UI


def audit_windows() -> list[PersistenceEntry]:
    results = []
    results += _win_registry()
    results += _win_startup_folder()
    results += _win_scheduled_tasks()
    results += _win_wmi()
    results += _win_services()
    return results


# ── Linux audit ───────────────────────────────────────────────────────────────
def audit_linux() -> list[PersistenceEntry]:
    entries = []
    checks = [
        ("/etc/init.d",              "Init.d"),
        ("/etc/systemd/system",      "Systemd"),
        (os.path.expanduser("~/.config/systemd/user"), "Systemd"),
        ("/etc/cron.d",              "Cron"),
        ("/var/spool/cron/crontabs", "Cron"),
        ("/etc/cron.daily",          "Cron"),
        ("/etc/cron.weekly",         "Cron"),
    ]
    for d, label in checks:
        if os.path.isdir(d):
            for f in os.listdir(d):
                fp = os.path.join(d, f)
                entries.append(PersistenceEntry(
                    name=f, entry_type=label, path=fp,
                    risk=_assess(fp), mitre=MITRE_MAP.get(label,"")
                ))
    # rc.local
    if os.path.exists("/etc/rc.local"):
        entries.append(PersistenceEntry(
            name="rc.local", entry_type="Init.d",
            path="/etc/rc.local", risk="normal"
        ))
    # ~/.bashrc hooks (basic check)
    bash = os.path.expanduser("~/.bashrc")
    if os.path.exists(bash):
        with open(bash) as f:
            content = f.read()
        if any(kw in content.lower() for kw in ["curl","wget","python","nc ","ncat"]):
            entries.append(PersistenceEntry(
                name=".bashrc", entry_type="Shell Hook",
                path=bash, risk="suspicious"
            ))
    return entries


def audit_persistence() -> list[PersistenceEntry]:
    if sys.platform == "win32":
        return audit_windows()
    return audit_linux()


# ── Right-click actions ───────────────────────────────────────────────────────

def disable_registry_entry(hive_path: str, value_name: str) -> tuple[bool, str]:
    """Set registry run value to empty string (disables without deleting)."""
    if sys.platform != "win32":
        return False, "Windows only"
    try:
        import winreg
        hive = winreg.HKEY_CURRENT_USER if "HKCU" in hive_path or "CURRENT_USER" in hive_path else winreg.HKEY_LOCAL_MACHINE
        key = winreg.OpenKey(hive, hive_path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, "")
        winreg.CloseKey(key)
        return True, f"Disabled: {value_name}"
    except Exception as e:
        return False, str(e)


def delete_registry_entry(hive_path: str, value_name: str) -> tuple[bool, str]:
    if sys.platform != "win32":
        return False, "Windows only"
    try:
        import winreg
        hive = winreg.HKEY_CURRENT_USER if "HKCU" in hive_path else winreg.HKEY_LOCAL_MACHINE
        key = winreg.OpenKey(hive, hive_path, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, value_name)
        winreg.CloseKey(key)
        return True, f"Deleted: {value_name}"
    except Exception as e:
        return False, str(e)


def delete_file_entry(filepath: str) -> tuple[bool, str]:
    try:
        if os.path.isfile(filepath):
            os.remove(filepath)
            return True, f"Deleted: {filepath}"
        return False, "File not found"
    except Exception as e:
        return False, str(e)


def analyze_behavior(filepath: str) -> dict:
    """Heuristic + pefile analysis of a startup entry."""
    result = {"filepath": filepath, "score": 0, "flags": [], "verdict": "clean"}
    if not os.path.isfile(filepath):
        return {**result, "verdict": "not_found"}
    try:
        import scanner as sc
        sr = sc.ScannerEngine().scan_file(filepath)
        if sr.status == "threat":
            result["score"] += 100
            result["flags"].append(f"Malware: {sr.threat_name}")
        elif sr.status == "suspicious":
            result["score"] += 50
            result["flags"].append(f"Suspicious: {sr.threat_name}")
        result["entropy"] = sr.entropy
        if sr.entropy > 7.0:
            result["score"] += 30
            result["flags"].append(f"High entropy: {sr.entropy:.2f}")
    except Exception as e:
        result["flags"].append(f"Scan error: {e}")
    try:
        import pefile
        pe = pefile.PE(filepath)
        # Check for no debug info, suspicious imports
        imps = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for imp in pe.DIRECTORY_ENTRY_IMPORT:
                for sym in imp.imports:
                    if sym.name:
                        imps.append(sym.name.decode(errors="ignore"))
        suspicious_imps = {"VirtualAllocEx","WriteProcessMemory","CreateRemoteThread",
                           "NtUnmapViewOfSection","IsDebuggerPresent"}
        found = suspicious_imps & set(imps)
        if found:
            result["score"] += 40
            result["flags"].append(f"Suspicious imports: {', '.join(found)}")
        result["imports_count"] = len(imps)
    except ImportError:
        result["flags"].append("pefile not installed (pip install pefile)")
    except Exception as e:
        result["flags"].append(f"PE parse: {e}")
    if result["score"] >= 100:
        result["verdict"] = "malware"
    elif result["score"] >= 40:
        result["verdict"] = "suspicious"
    return result


def export_stix(entry: PersistenceEntry) -> dict:
    """Generate a STIX 2.1 indicator JSON snippet."""
    import uuid
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    stix = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": ts,
                "modified": ts,
                "name": entry.name,
                "description": f"Persistence entry: {entry.entry_type}",
                "indicator_types": ["malicious-activity"] if entry.risk=="suspicious" else ["anomalous-activity"],
                "pattern": f"[file:name = '{os.path.basename(entry.path)}']",
                "pattern_type": "stix",
                "valid_from": ts,
                "labels": [entry.entry_type.lower().replace(" ","_")],
                "external_references": [{"source_name":"MITRE ATT&CK","external_id":entry.mitre}] if entry.mitre else [],
                "x_x2yav_path": entry.path,
                "x_x2yav_risk": entry.risk,
            }
        ]
    }
    return stix


def scan_parent_process(pid: int) -> dict:
    """Scan the parent process of the given PID."""
    try:
        import psutil, scanner as sc
        p = psutil.Process(pid)
        parent = p.parent()
        if not parent:
            return {"error": "No parent process"}
        exe = parent.exe()
        engine = sc.ScannerEngine()
        result = engine.scan_file(exe)
        return {
            "parent_pid":  parent.pid,
            "parent_name": parent.name(),
            "parent_exe":  exe,
            "status":      result.status,
            "threat":      result.threat_name,
        }
    except Exception as e:
        return {"error": str(e)}