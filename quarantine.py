"""
x2y AV Ultimate v8.0.5 - Quarantine Vault
Moves threats to encrypted-named vault, maintains SQLite manifest.
"""

import os, json, shutil, time, hashlib, sqlite3, threading
from dataclasses import dataclass, asdict
from typing import Optional

VAULT_DIR = os.path.join(os.path.expanduser("~"), ".x2y_quarantine")
DB_PATH   = os.path.join(VAULT_DIR, "vault.db")
os.makedirs(VAULT_DIR, exist_ok=True)

_lock = threading.Lock()

def _init_db():
    with sqlite3.connect(DB_PATH) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS vault(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_path TEXT, vault_path TEXT,
            threat_name TEXT, detection_type TEXT,
            sha256 TEXT, quarantine_time TEXT, file_size INTEGER)""")
        c.commit()
_init_db()

@dataclass
class QuarantinedFile:
    id: int
    original_path: str
    vault_path: str
    threat_name: str
    detection_type: str
    sha256: str
    quarantine_time: str
    file_size: int


def quarantine_file(filepath, threat_name, detection_type, sha256) -> Optional[QuarantinedFile]:
    os.makedirs(VAULT_DIR, exist_ok=True)
    safe_name = sha256[:24] + ".x2y_quarantine"
    vault_path = os.path.join(VAULT_DIR, safe_name)
    try:
        shutil.move(filepath, vault_path)
    except Exception as e:
        return None
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    sz = os.path.getsize(vault_path)
    with _lock, sqlite3.connect(DB_PATH) as c:
        cur = c.execute(
            "INSERT INTO vault(original_path,vault_path,threat_name,detection_type,sha256,quarantine_time,file_size)"
            " VALUES(?,?,?,?,?,?,?)",
            (filepath, vault_path, threat_name, detection_type, sha256, ts, sz))
        c.commit()
        row_id = cur.lastrowid
    return QuarantinedFile(id=row_id, original_path=filepath, vault_path=vault_path,
                           threat_name=threat_name, detection_type=detection_type,
                           sha256=sha256, quarantine_time=ts, file_size=sz)


def list_quarantined() -> list[QuarantinedFile]:
    with sqlite3.connect(DB_PATH) as c:
        rows = c.execute("SELECT id,original_path,vault_path,threat_name,detection_type,sha256,quarantine_time,file_size FROM vault").fetchall()
    return [QuarantinedFile(*r) for r in rows if os.path.exists(r[2])]


def restore_file(qid: int) -> tuple[bool, str]:
    with sqlite3.connect(DB_PATH) as c:
        row = c.execute("SELECT original_path,vault_path FROM vault WHERE id=?", (qid,)).fetchone()
    if not row: return False, "Not found"
    orig, vault = row
    try:
        os.makedirs(os.path.dirname(orig), exist_ok=True)
        shutil.move(vault, orig)
        with sqlite3.connect(DB_PATH) as c:
            c.execute("DELETE FROM vault WHERE id=?", (qid,)); c.commit()
        return True, f"Restored to {orig}"
    except Exception as e:
        return False, str(e)


def delete_from_vault(qid: int) -> tuple[bool, str]:
    with sqlite3.connect(DB_PATH) as c:
        row = c.execute("SELECT vault_path FROM vault WHERE id=?", (qid,)).fetchone()
    if not row: return False, "Not found"
    try:
        if os.path.exists(row[0]): os.remove(row[0])
        with sqlite3.connect(DB_PATH) as c:
            c.execute("DELETE FROM vault WHERE id=?", (qid,)); c.commit()
        return True, "Deleted"
    except Exception as e:
        return False, str(e)