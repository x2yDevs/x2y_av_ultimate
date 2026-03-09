"""
x2y AV Ultimate v8.0.5 - Network Monitor
Real-time socket enumeration via psutil.
Right-click actions: Block IP, Kill Process, Capture Traffic, WHOIS, MITRE tag.
Suspicious heuristics: high-entropy domains, C2 IPs, bad port+process combos.
"""

import os, sys, re, json, math, socket, signal, logging, subprocess, threading, time
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("x2yav.netmon")

# ── Known suspicious ports (RAT / backdoor / C2) ─────────────────────────────
SUSPICIOUS_PORTS = {
    4444,5555,6666,7777,8888,9999,1337,31337,12345,54321,
    65535,3333,2222,6969,8765,9001,9090,4899,4545,6667,
    1080,3128,8080,8443,  # proxies not always suspicious but flag non-browser
}

# port+process combos that are definitely bad
BAD_COMBOS = {
    ("cmd.exe",  443), ("powershell.exe", 443), ("powershell.exe", 80),
    ("wscript.exe", 443), ("mshta.exe", 443), ("cscript.exe", 443),
    ("regsvr32.exe", 443), ("rundll32.exe", 443),
}

MITRE_TAGS = [
    "T1078 - Valid Accounts",
    "T1059 - Command Scripting",
    "T1041 - Exfiltration Over C2",
    "T1071 - App Layer Protocol",
    "T1095 - Non-App Layer Protocol",
    "T1105 - Ingress Tool Transfer",
    "T1219 - Remote Access Software",
    "T1048 - Exfil Over Alt Protocol",
    "T1090 - Proxy",
    "T1021 - Remote Services",
]

HIGH_ENTROPY_RE = re.compile(r"xn--[a-z0-9-]+\.")
LONG_RANDOM_RE  = re.compile(r"[a-z0-9]{20,}\.(com|net|ru|cn|xyz|top|cc)$")


@dataclass
class ConnectionInfo:
    protocol:      str
    local_addr:    str
    remote_addr:   str
    remote_ip:     str
    remote_port:   int
    status:        str
    pid:           int
    process_name:  str
    risk:          str = "clean"     # clean | warning | suspicious
    risk_reason:   str = ""
    mitre_tag:     str = ""
    hostname:      str = ""


def _is_private(ip: str) -> bool:
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except Exception:
        return False


def _entropy(s: str) -> float:
    if not s: return 0.0
    from collections import Counter
    c = Counter(s)
    n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in c.values())


def _assess_risk(conn) -> tuple[str, str]:
    raddr = getattr(conn, "raddr", None)
    if not raddr:
        return "clean", ""
    ip   = getattr(raddr, "ip",   raddr[0] if raddr else "")
    port = getattr(raddr, "port", raddr[1] if raddr else 0)
    pname = ""
    try:
        import psutil
        if conn.pid:
            pname = psutil.Process(conn.pid).name().lower()
    except Exception:
        pass

    # C2 IP check
    from scanner import C2_IPS
    if ip in C2_IPS:
        return "suspicious", f"Known C2 IP: {ip}"

    # Bad combo
    if (pname, port) in BAD_COMBOS:
        return "suspicious", f"Suspicious {pname}:{port}"

    # Suspicious ports
    if port in SUSPICIOUS_PORTS and not _is_private(ip):
        return "suspicious", f"Suspicious port {port}"

    # High-entropy domain (try resolve)
    try:
        host = socket.getfqdn(ip)
        if HIGH_ENTROPY_RE.search(host) or LONG_RANDOM_RE.search(host):
            return "suspicious", f"High-entropy domain: {host}"
        if _entropy(host.split(".")[0]) > 3.8 and not _is_private(ip):
            return "warning", f"Possibly DGA domain: {host}"
    except Exception:
        pass

    if not _is_private(ip) and port not in (80, 443, 8080, 8443, 53, 587, 993, 25):
        return "warning", f"Unusual port {port}"

    return "clean", ""


def get_connections() -> list[ConnectionInfo]:
    import psutil
    results = []
    pid_cache = {}
    try:
        conns = psutil.net_connections(kind="inet")
    except PermissionError:
        return []
    for c in conns:
        try:
            pid = c.pid or 0
            if pid not in pid_cache:
                try:
                    pid_cache[pid] = psutil.Process(pid).name() if pid else "System"
                except Exception:
                    pid_cache[pid] = "Unknown"
            rip   = c.raddr.ip   if c.raddr else ""
            rport = c.raddr.port if c.raddr else 0
            risk, reason = _assess_risk(c)
            results.append(ConnectionInfo(
                protocol    = "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                local_addr  = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "—",
                remote_addr = f"{rip}:{rport}" if rip else "—",
                remote_ip   = rip,
                remote_port = rport,
                status      = c.status or "—",
                pid         = pid,
                process_name= pid_cache[pid],
                risk        = risk,
                risk_reason = reason,
            ))
        except Exception:
            continue
    order = {"suspicious":0,"warning":1,"clean":2}
    results.sort(key=lambda x: order.get(x.risk,3))
    return results


# ── Actions ───────────────────────────────────────────────────────────────────

def block_ip(ip: str) -> tuple[bool, str]:
    """Add Windows firewall rule to block IP (requires admin) or iptables on Linux."""
    if sys.platform == "win32":
        try:
            name = f"x2yAV_Block_{ip}"
            r = subprocess.run([
                "netsh","advfirewall","firewall","add","rule",
                f"name={name}", "dir=out", "action=block",
                f"remoteip={ip}", "enable=yes"
            ], capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                return True, f"Blocked {ip} via Windows Firewall"
            return False, r.stderr.strip()[:120]
        except Exception as e:
            return False, str(e)
    else:
        try:
            r = subprocess.run(["iptables","-A","OUTPUT","-d",ip,"-j","DROP"],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                return True, f"Blocked {ip} via iptables"
            return False, r.stderr.strip()[:120]
        except Exception as e:
            return False, str(e)


def terminate_process(pid: int) -> tuple[bool, str]:
    try:
        import psutil
        p = psutil.Process(pid)
        name = p.name()
        p.terminate()
        time.sleep(0.5)
        if p.is_running():
            p.kill()
        return True, f"Terminated {name} (PID {pid})"
    except Exception as e:
        return False, str(e)


def capture_traffic(ip: str, duration: int = 10,
                    out_dir: str = None) -> tuple[bool, str]:
    """Capture packets for an IP using scapy (requires elevated + scapy installed)."""
    out_dir = out_dir or os.path.expanduser("~/.x2y_av/captures")
    os.makedirs(out_dir, exist_ok=True)
    ts  = time.strftime("%Y%m%d_%H%M%S")
    out = os.path.join(out_dir, f"capture_{ip.replace('.','_')}_{ts}.pcap")
    try:
        from scapy.all import sniff, wrpcap
        packets = sniff(filter=f"host {ip}", timeout=duration)
        wrpcap(out, packets)
        return True, out
    except ImportError:
        # Fallback: tshark
        try:
            r = subprocess.run(
                ["tshark","-i","any","-f",f"host {ip}",
                 "-a",f"duration:{duration}","-w", out],
                timeout=duration+10, capture_output=True
            )
            if os.path.exists(out) and os.path.getsize(out) > 0:
                return True, out
            return False, "tshark produced no output — try running as admin"
        except FileNotFoundError:
            return False, "scapy and tshark not found — pip install scapy or install Wireshark"
        except Exception as e:
            return False, str(e)
    except Exception as e:
        return False, str(e)


def whois_lookup(ip: str) -> dict:
    """WHOIS via socket (port 43) with fallback to ip-api.com."""
    result = {"ip": ip, "org": "—", "country": "—", "asn": "—", "source": "—"}
    # Try ip-api.com (free, no auth)
    try:
        import urllib.request
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=org,country,as,isp,city", timeout=8) as r:
            data = json.loads(r.read())
        result.update({
            "org":     data.get("org","—"),
            "isp":     data.get("isp","—"),
            "country": data.get("country","—"),
            "city":    data.get("city","—"),
            "asn":     data.get("as","—"),
            "source":  "ip-api.com"
        })
        return result
    except Exception:
        pass
    # Fallback: raw WHOIS port 43
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("whois.iana.org", 43))
        s.send((ip + "\r\n").encode())
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            resp += chunk
        s.close()
        result["raw"] = resp.decode(errors="ignore")[:500]
        result["source"] = "IANA WHOIS"
    except Exception as e:
        result["error"] = str(e)
    return result


def reverse_dns(ip: str) -> str:
    try:
        return socket.getfqdn(ip)
    except Exception:
        return ip