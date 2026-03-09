"""
x2y AV Ultimate v8.0.5 - Main UI
All pages: Scan, Network Monitor, Persistence Audit, Quarantine Vault,
           Threat Intelligence, Settings
Right-click menus on Network Monitor and Persistence Audit.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import threading, time, os, sys, json, queue
from typing import Optional

import theme as T
import scanner as sc
import netmon
import persistence
import quarantine
import settings_mgr

APP_VERSION = "8.0.5"


def _send_os_notification(title: str, message: str):
    """Send a native OS desktop notification (non-blocking)."""
    try:
        if sys.platform == "win32":
            # Use win10toast if available, else plyer, else silent
            try:
                from win10toast import ToastNotifier
                t = ToastNotifier()
                threading.Thread(
                    target=lambda: t.show_toast(title, message, duration=5, threaded=True),
                    daemon=True).start()
                return
            except ImportError:
                pass
            try:
                from plyer import notification
                notification.notify(title=title, message=message, app_name="x2y AV", timeout=5)
                return
            except ImportError:
                pass
            # PowerShell balloon fallback (no extra deps)
            ps = (
                f"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
                f"ContentType = WindowsRuntime] | Out-Null;"
                f"$t = [Windows.UI.Notifications.ToastNotificationManager];"
                f"$xml = $t::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
                f"$xml.GetElementsByTagName('text')[0].AppendChild($xml.CreateTextNode('{title}')) | Out-Null;"
                f"$xml.GetElementsByTagName('text')[1].AppendChild($xml.CreateTextNode('{message}')) | Out-Null;"
                f"$toast = [Windows.UI.Notifications.ToastNotification]::new($xml);"
                f"$t::CreateToastNotifier('x2y AV').Show($toast);"
            )
            import subprocess
            subprocess.Popen(["powershell", "-WindowStyle", "Hidden", "-Command", ps],
                             creationflags=0x08000000)
        elif sys.platform == "darwin":
            import subprocess
            subprocess.Popen(["osascript", "-e",
                              f'display notification "{message}" with title "{title}"'])
        else:
            # Linux: notify-send
            import subprocess
            subprocess.Popen(["notify-send", "-a", "x2y AV", title, message])
    except Exception:
        pass

# ── Helpers ───────────────────────────────────────────────────────────────────
def _fr(parent, bg=T.BG_DARK, **kw):
    return tk.Frame(parent, bg=bg, **kw)

def _lbl(parent, text="", fg=T.TEXT_PRIMARY, bg=T.BG_DARK, font=T.FONT_BODY, **kw):
    return tk.Label(parent, text=text, fg=fg, bg=bg, font=font, **kw)

def _btn(parent, text, cmd, fg=T.TEXT_PRIMARY, bg=T.BG_PANEL, font=T.FONT_BODY, **kw):
    return tk.Button(parent, text=text, command=cmd, fg=fg, bg=bg, font=font,
                     relief="flat", bd=0, cursor="hand2",
                     activebackground=T.BG_HOVER, activeforeground=T.TEXT_PRIMARY, **kw)

def _sep(parent, bg=T.BORDER_COLOR):
    return tk.Frame(parent, bg=bg, height=1)

def _context_menu(event, items):
    """Show a right-click context menu. items = list of (label, cmd) or None for separator."""
    m = tk.Menu(tearoff=0, bg=T.BG_PANEL, fg=T.TEXT_PRIMARY,
                activebackground=T.ACCENT_BLUE, activeforeground="white",
                font=T.FONT_BODY, bd=0, relief="flat")
    for item in items:
        if item is None:
            m.add_separator()
        else:
            label, cmd = item
            m.add_command(label=label, command=cmd)
    try:
        m.tk_popup(event.x_root, event.y_root)
    finally:
        m.grab_release()

def _toast(root, msg: str, color=T.ACCENT_GREEN, duration=4000):
    t = tk.Toplevel(root)
    t.overrideredirect(True)
    t.attributes("-topmost", True)
    t.configure(bg=T.BG_PANEL)
    root.update_idletasks()
    pw = root.winfo_toplevel()
    x = pw.winfo_x() + pw.winfo_width() - 340
    y = pw.winfo_y() + pw.winfo_height() - 100
    t.geometry(f"320x60+{x}+{y}")
    _lbl(t, msg, fg=color, bg=T.BG_PANEL, font=T.FONT_SMALL,
         wraplength=290, justify="left").pack(expand=True, padx=12, pady=8)
    t.after(duration, t.destroy)

def _info_dialog(title: str, content: str):
    win = tk.Toplevel()
    win.title(title)
    win.configure(bg=T.BG_DARK)
    win.geometry("560x400")
    txt = tk.Text(win, bg=T.BG_PANEL, fg=T.TEXT_PRIMARY, font=T.FONT_MONO,
                  relief="flat", bd=0, wrap="word")
    sb = ttk.Scrollbar(win, command=txt.yview)
    txt.configure(yscrollcommand=sb.set)
    txt.insert("1.0", content)
    txt.config(state="disabled")
    sb.pack(side="right", fill="y")
    txt.pack(fill="both", expand=True, padx=8, pady=8)
    _btn(win, "Close", win.destroy, bg=T.BG_HOVER).pack(pady=6)


# ─────────────────────────────────────────────────────────────────────────────
# Scan Page
# ─────────────────────────────────────────────────────────────────────────────
class ScanPage(tk.Frame):
    def __init__(self, master, engine, **kw):
        super().__init__(master, bg=T.BG_DARK, **kw)
        self._engine  = engine
        self._stop    = threading.Event()
        self._results = []
        self._scanning = False
        self._build()

    def _build(self):
        bar = _fr(self)
        bar.pack(fill="x")
        self._tnew  = self._tab_btn(bar, "⟳  New Scan",    self._show_new,  True)
        self._thist = self._tab_btn(bar, "⏱  Scan History", self._show_hist)
        self._tnew.pack(side="left", padx=(0,4))
        self._thist.pack(side="left")
        _sep(bar, T.ACCENT_BLUE).pack(side="bottom", fill="x")

        self._fnew  = _fr(self)
        self._fhist = _fr(self)
        self._build_new()
        self._build_hist()
        self._show_new()

    def _tab_btn(self, p, txt, cmd, active=False):
        return tk.Button(p, text=txt, command=cmd,
                         fg=T.ACCENT_BLUE if active else T.TEXT_SECONDARY,
                         bg=T.BG_DARK, font=T.FONT_BODY,
                         relief="flat", bd=0, cursor="hand2",
                         activebackground=T.BG_DARK, activeforeground=T.ACCENT_BLUE,
                         padx=10, pady=8)

    def _show_new(self):
        self._tnew.config(fg=T.ACCENT_BLUE)
        self._thist.config(fg=T.TEXT_SECONDARY)
        self._fhist.pack_forget()
        self._fnew.pack(fill="both", expand=True)

    def _show_hist(self):
        self._thist.config(fg=T.ACCENT_BLUE)
        self._tnew.config(fg=T.TEXT_SECONDARY)
        self._fnew.pack_forget()
        self._fhist.pack(fill="both", expand=True)
        self._refresh_hist()

    def _build_new(self):
        p = self._fnew
        p.config(bg=T.BG_DARK)
        banner = _fr(p, T.BG_PANEL)
        banner.pack(fill="x", pady=(12,10), padx=2)
        _lbl(banner, "✔", T.ACCENT_GREEN, T.BG_PANEL, ("Consolas",28)).pack(pady=(14,2))
        self._status = _lbl(banner, "System Protected", T.TEXT_PRIMARY, T.BG_PANEL,
                            ("Consolas",13,"bold"))
        self._status.pack(pady=(0,14))

        grid = _fr(p)
        grid.pack(fill="both", expand=True, pady=4, padx=2)
        grid.columnconfigure(0, weight=1); grid.columnconfigure(1, weight=1)
        grid.rowconfigure(0, weight=1);    grid.rowconfigure(1, weight=1)

        for icon,title,sub,cmd,r,c in [
            ("⚡","Quick Scan",  "System Criticals", self._quick,  0,0),
            ("💾","Full Scan",   "Entire Drive",      self._full,   0,1),
            ("📄","Scan File",   "Single Target",     self._file,   1,0),
            ("📁","Scan Folder", "Custom Directory",  self._folder, 1,1),
        ]:
            self._card(grid, icon, title, sub, cmd).grid(
                row=r, column=c, padx=4, pady=4, sticky="nsew")

        self._pfr  = _fr(p)
        self._pfr.pack(fill="x", padx=2, pady=4)
        self._plbl = _lbl(self._pfr, "", T.TEXT_SECONDARY, T.BG_DARK, T.FONT_SMALL)
        self._plbl.pack(anchor="w")
        self._pbar = ttk.Progressbar(self._pfr, mode="indeterminate",
                                     style="Green.Horizontal.TProgressbar")
        self._pbar.pack(fill="x", pady=2)
        self._pfr.pack_forget()

        self._rfr = _fr(p)
        self._rfr.pack(fill="both", expand=True, padx=2)
        self._rtxt = tk.Text(self._rfr, bg=T.BG_PANEL, fg=T.TEXT_PRIMARY,
                             font=T.FONT_MONO, relief="flat", bd=0,
                             state="disabled", height=8)
        sb = ttk.Scrollbar(self._rfr, command=self._rtxt.yview)
        self._rtxt.config(yscrollcommand=sb.set)
        self._rtxt.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self._rfr.pack_forget()

    def _card(self, p, icon, title, sub, cmd):
        card = tk.Frame(p, bg=T.BG_PANEL, cursor="hand2")
        card.bind("<Button-1>", lambda e: cmd())
        card.bind("<Enter>",    lambda e: card.config(bg=T.BG_HOVER))
        card.bind("<Leave>",    lambda e: card.config(bg=T.BG_PANEL))
        inn = _fr(card, T.BG_PANEL)
        inn.pack(expand=True, pady=30, padx=20, anchor="w")
        inn.bind("<Button-1>", lambda e: cmd())
        _lbl(inn, icon, T.ACCENT_BLUE, T.BG_PANEL, ("Consolas",16)).pack(anchor="w")
        _lbl(inn, title, T.TEXT_PRIMARY, T.BG_PANEL, T.FONT_CARD).pack(anchor="w", pady=(4,0))
        _lbl(inn, sub,   T.TEXT_SECONDARY, T.BG_PANEL, T.FONT_SMALL).pack(anchor="w")
        return card

    def _build_hist(self):
        p = self._fhist
        p.config(bg=T.BG_DARK)
        h = _fr(p)
        h.pack(fill="x", pady=8, padx=4)
        _lbl(h, "Scan History", font=T.FONT_TITLE).pack(side="left")
        _btn(h, "Clear", self._clear_hist, bg=T.BG_PANEL).pack(side="right")
        self._htxt = tk.Text(p, bg=T.BG_PANEL, fg=T.TEXT_PRIMARY, font=T.FONT_MONO,
                             relief="flat", bd=0, state="disabled")
        sb = ttk.Scrollbar(p, command=self._htxt.yview)
        self._htxt.config(yscrollcommand=sb.set)
        self._htxt.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        sb.pack(side="right", fill="y", pady=4)

    def _refresh_hist(self):
        p = os.path.join(os.path.expanduser("~"), ".x2y_av", "scan_history.txt")
        self._htxt.config(state="normal")
        self._htxt.delete("1.0","end")
        self._htxt.insert("1.0", open(p).read() if os.path.exists(p) else "No scan history.")
        self._htxt.config(state="disabled")

    def _clear_hist(self):
        p = os.path.join(os.path.expanduser("~"), ".x2y_av", "scan_history.txt")
        if os.path.exists(p): os.remove(p)
        self._refresh_hist()

    def _quick(self):  self._start(self._engine.get_quick_scan_dirs(), "Quick Scan")
    def _full(self):
        root = "C:\\" if sys.platform=="win32" else "/"
        if messagebox.askyesno("Full Scan", f"Scan {root}? This may take a while."):
            self._start([root], "Full Scan")
    def _file(self):
        p = filedialog.askopenfilename(title="Select file")
        if p: self._start([p], "File Scan", single=True)
    def _folder(self):
        p = filedialog.askdirectory(title="Select folder")
        if p: self._start([p], "Folder Scan")

    def _start(self, targets, label, single=False):
        if self._scanning: self._stop.set(); return
        self._scanning = True
        self._stop.clear()
        self._results.clear()
        self._rtxt.config(state="normal"); self._rtxt.delete("1.0","end"); self._rtxt.config(state="disabled")
        self._rfr.pack(fill="both", expand=True, padx=2)
        self._pfr.pack(fill="x", padx=2, pady=4)
        self._pbar.start(10)
        self._status.config(text=f"Scanning — {label}...", fg=T.ACCENT_BLUE)

        def worker():
            threats = scanned = 0
            t0 = time.time()
            def on_result(r):
                nonlocal threats, scanned
                scanned += 1
                if r.status in ("threat","suspicious"):
                    threats += 1; self._results.append(r); self._append(r)
                self._plbl.config(text=f"Scanned: {scanned}  Threats: {threats}  {os.path.basename(r.filepath)[:55]}")
                if settings_mgr.get("auto_quarantine") and r.status == "threat":
                    quarantine.quarantine_file(r.filepath, r.threat_name, r.detection_type, r.sha256)

            if single:
                for t in targets: on_result(self._engine.scan_file(t))
            else:
                for t in targets:
                    if os.path.isfile(t): on_result(self._engine.scan_file(t))
                    else: self._engine.scan_directory(t, on_result, self._stop,
                                                      progress_cb=lambda p: self._plbl.config(text=f"Scanning: {p[-65:]}"))
            self._finish(scanned, threats, label, time.time()-t0)

        threading.Thread(target=worker, daemon=True).start()

    def _finish(self, scanned, threats, label, elapsed):
        self._scanning = False
        self._pbar.stop(); self._pfr.pack_forget()
        if threats == 0:
            self._status.config(text="System Protected", fg=T.ACCENT_GREEN)
            self._rtxt.config(state="normal")
            self._rtxt.insert("end", f"\n✔  No threats. ({scanned} files in {elapsed:.1f}s)\n")
            self._rtxt.config(state="disabled")
        else:
            self._status.config(text=f"⚠  {threats} Threat(s) Found", fg=T.ACCENT_RED)
        hp = os.path.join(os.path.expanduser("~"),".x2y_av","scan_history.txt")
        os.makedirs(os.path.dirname(hp), exist_ok=True)
        with open(hp,"a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {label} — {scanned} files — {threats} threats — {elapsed:.1f}s\n")
            for r in self._results:
                f.write(f"  {r.status.upper()}: {r.threat_name} | {r.filepath}\n")

    def _append(self, r):
        color = T.ACCENT_RED if r.status=="threat" else T.ACCENT_YELLOW
        icon  = "⛔" if r.status=="threat" else "⚠"
        tag   = r.status
        self._rtxt.config(state="normal")
        self._rtxt.tag_config(tag, foreground=color)
        self._rtxt.insert("end", f"{icon} [{r.status.upper()}] {r.threat_name} [{r.detection_type}]\n"
                                 f"   {r.filepath}\n\n", tag)
        self._rtxt.see("end")
        self._rtxt.config(state="disabled")

    def on_show(self): pass


# ─────────────────────────────────────────────────────────────────────────────
# Network Monitor Page
# ─────────────────────────────────────────────────────────────────────────────
class NetworkPage(tk.Frame):
    def __init__(self, master, **kw):
        super().__init__(master, bg=T.BG_DARK, **kw)
        self._running    = False
        self._loading    = False
        self._conns:     list[netmon.ConnectionInfo] = []
        self._samples:   list[float] = [0.0] * 60
        self._spark_q:   queue.Queue = queue.Queue(maxsize=1)
        self._build()

    def _build(self):
        hdr = _fr(self)
        hdr.pack(fill="x", pady=(8,4), padx=10)
        _lbl(hdr, "Network Activity Monitor", font=T.FONT_TITLE).pack(anchor="w")
        _lbl(hdr, "Real-time Process Mapping & Traffic Flow", fg=T.TEXT_SECONDARY,
             font=T.FONT_SUBTITLE).pack(anchor="w")

        # Sparkline canvas
        self._canvas = tk.Canvas(self, bg="#0d1f3c", height=110, highlightthickness=0)
        self._canvas.pack(fill="x")

        # Loading indicator
        self._loading_lbl = _lbl(self, "Loading connections...",
                                 T.TEXT_SECONDARY, T.BG_DARK, T.FONT_SMALL)

        # Treeview
        lf = _fr(self)
        lf.pack(fill="both", expand=True, pady=4)
        cols = ("proto","remote","pid","proc","status","risk")
        self._tree = ttk.Treeview(lf, columns=cols, show="headings", style="Dark.Treeview")
        for col, w, txt in [
            ("proto",  70,  "Proto"),
            ("remote", 220, "Remote"),
            ("pid",    60,  "PID"),
            ("proc",   160, "Process"),
            ("status", 110, "State"),
            ("risk",   120, "Risk"),
        ]:
            self._tree.heading(col, text=txt)
            self._tree.column(col, width=w, stretch=(col in ("remote","proc")))
        self._tree.tag_configure("suspicious", foreground=T.ACCENT_YELLOW)
        self._tree.tag_configure("warning",    foreground=T.TEXT_WARN)
        self._tree.tag_configure("clean",      foreground=T.TEXT_SECONDARY)
        sb = ttk.Scrollbar(lf, command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self._tree.bind("<Button-3>", self._on_rightclick)
        self._tree.bind("<Button-2>", self._on_rightclick)

        # Bottom bar
        bf = _fr(self)
        bf.pack(fill="x", pady=4, padx=6)
        _btn(bf, "⟳  Refresh", self._trigger_refresh, bg=T.BG_PANEL).pack(side="left")
        self._stat_lbl = _lbl(bf, "", T.TEXT_SECONDARY, T.BG_DARK, T.FONT_SMALL)
        self._stat_lbl.pack(side="left", padx=12)
        _btn(bf, "Export CSV", self._export_csv, bg=T.BG_PANEL).pack(side="right")

    def on_show(self):
        self._trigger_refresh()
        self._start_sparkline()

    def on_hide(self):
        self._running = False

    def _trigger_refresh(self):
        """Kick off connection fetch in a background thread — never blocks UI."""
        if self._loading:
            return
        self._loading = True
        self._loading_lbl.config(text="Loading connections...")
        self._loading_lbl.pack(pady=4)
        threading.Thread(target=self._fetch_conns_worker, daemon=True).start()

    def _fetch_conns_worker(self):
        """Run in background thread — does the slow psutil work."""
        try:
            conns = netmon.get_connections()
        except Exception:
            conns = []
        # Always schedule UI update back on main thread
        self.after(0, lambda c=conns: self._populate_table(c))

    def _populate_table(self, conns: list):
        """Must be called on main thread only."""
        self._loading = False
        self._loading_lbl.pack_forget()
        self._conns = conns
        self._tree.delete(*self._tree.get_children())
        sus = warn = 0
        for c in conns:
            risk_txt = ("SUSPICIOUS" if c.risk == "suspicious"
                        else "WARNING" if c.risk == "warning" else "")
            self._tree.insert("", "end",
                values=(c.protocol, c.remote_addr or c.local_addr,
                        c.pid, c.process_name, c.status, risk_txt),
                tags=(c.risk,))
            if c.risk == "suspicious": sus += 1
            elif c.risk == "warning":  warn += 1
        self._stat_lbl.config(
            text=f"{len(conns)} connections  |  {sus} suspicious  |  {warn} warnings")

    def _get_selected_conn(self) -> Optional[netmon.ConnectionInfo]:
        sel = self._tree.selection()
        if not sel: return None
        idx = self._tree.index(sel[0])
        return self._conns[idx] if idx < len(self._conns) else None

    def _on_rightclick(self, event):
        row = self._tree.identify_row(event.y)
        if not row: return
        self._tree.selection_set(row)
        conn = self._get_selected_conn()
        if not conn: return

        items = [
            (f"🔒  Block IP: {conn.remote_ip}",      lambda c=conn: self._block_ip(c)),
            (f"⚡  Terminate PID {conn.pid}",          lambda c=conn: self._kill_proc(c)),
            None,
            ("📡  Capture Traffic (10s)",              lambda c=conn: self._capture(c)),
            ("🔍  WHOIS Lookup",                       lambda c=conn: self._whois(c)),
            ("🔎  Reverse DNS",                        lambda c=conn: self._rdns(c)),
            None,
            ("🎯  Tag as MITRE ATT&CK...",             lambda c=conn: self._mitre_tag(c)),
            ("📋  Copy IP",                            lambda c=conn: self._copy(c.remote_ip)),
            ("📋  Copy Process",                       lambda c=conn: self._copy(c.process_name)),
        ]
        _context_menu(event, items)

    def _block_ip(self, conn):
        if not conn.remote_ip or conn.remote_ip == "—":
            messagebox.showwarning("Block IP", "No remote IP for this connection.")
            return
        def worker():
            ok, msg = netmon.block_ip(conn.remote_ip)
            self.after(0, lambda: (
                _toast(self.winfo_toplevel(),
                       f"{'✔' if ok else '✘'} {msg}",
                       T.ACCENT_GREEN if ok else T.ACCENT_RED),
                self._trigger_refresh() if ok else None
            ))
        threading.Thread(target=worker, daemon=True).start()

    def _kill_proc(self, conn):
        if not conn.pid:
            messagebox.showwarning("Terminate", "No PID for this connection.")
            return
        if messagebox.askyesno("Terminate Process",
                               f"Kill {conn.process_name} (PID {conn.pid})?"):
            def worker():
                ok, msg = netmon.terminate_process(conn.pid)
                self.after(0, lambda: (
                    _toast(self.winfo_toplevel(),
                           f"{'✔' if ok else '✘'} {msg}",
                           T.ACCENT_GREEN if ok else T.ACCENT_RED),
                    self._trigger_refresh() if ok else None
                ))
            threading.Thread(target=worker, daemon=True).start()

    def _capture(self, conn):
        if not conn.remote_ip:
            messagebox.showwarning("Capture", "No remote IP."); return
        _toast(self.winfo_toplevel(), f"Capturing {conn.remote_ip} for 10s...", T.ACCENT_BLUE)
        def worker():
            ok, out = netmon.capture_traffic(conn.remote_ip, 10)
            msg = f"Saved: {out}" if ok else f"Capture failed: {out}"
            self.after(0, lambda: _toast(self.winfo_toplevel(), msg,
                                         T.ACCENT_GREEN if ok else T.ACCENT_RED))
        threading.Thread(target=worker, daemon=True).start()

    def _whois(self, conn):
        if not conn.remote_ip: return
        _toast(self.winfo_toplevel(), f"WHOIS {conn.remote_ip}...", T.ACCENT_BLUE)
        def worker():
            data = netmon.whois_lookup(conn.remote_ip)
            text = "\n".join(f"{k}: {v}" for k,v in data.items())
            self.after(0, lambda: _info_dialog(f"WHOIS — {conn.remote_ip}", text))
        threading.Thread(target=worker, daemon=True).start()

    def _rdns(self, conn):
        if not conn.remote_ip: return
        _toast(self.winfo_toplevel(), f"Resolving {conn.remote_ip}...", T.ACCENT_BLUE, 1500)
        def worker():
            hostname = netmon.reverse_dns(conn.remote_ip)
            self.after(0, lambda: _info_dialog(
                "Reverse DNS", f"IP: {conn.remote_ip}\nHostname: {hostname}"))
        threading.Thread(target=worker, daemon=True).start()

    def _mitre_tag(self, conn):
        win = tk.Toplevel(self)
        win.title("Tag MITRE ATT&CK")
        win.configure(bg=T.BG_DARK)
        win.geometry("400x300")
        _lbl(win, f"Connection: {conn.remote_addr}", font=T.FONT_SMALL,
             fg=T.TEXT_SECONDARY).pack(pady=(10,4), padx=12, anchor="w")
        lb = tk.Listbox(win, bg=T.BG_PANEL, fg=T.TEXT_PRIMARY, font=T.FONT_SMALL,
                        selectbackground=T.ACCENT_BLUE, relief="flat", bd=0)
        for tag in netmon.MITRE_TAGS:
            lb.insert("end", tag)
        lb.pack(fill="both", expand=True, padx=8, pady=4)

        def apply():
            sel = lb.curselection()
            if not sel: return
            tag = lb.get(sel[0])
            log_path = os.path.join(os.path.expanduser("~"),".x2y_av","mitre_tags.jsonl")
            with open(log_path,"a") as f:
                json.dump({"ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                           "remote": conn.remote_addr, "pid": conn.pid,
                           "process": conn.process_name, "mitre": tag}, f)
                f.write("\n")
            _toast(self.winfo_toplevel(), f"Tagged: {tag}", T.ACCENT_BLUE)
            win.destroy()

        _btn(win, "Apply Tag", apply, bg=T.ACCENT_BLUE, fg="white").pack(pady=6)

    def _copy(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)
        _toast(self.winfo_toplevel(), f"Copied: {text}", T.ACCENT_BLUE, 1500)

    def _export_csv(self):
        p = filedialog.asksaveasfilename(defaultextension=".csv",
                                         filetypes=[("CSV","*.csv")])
        if not p: return
        import csv
        with open(p,"w",newline="") as f:
            w = csv.writer(f)
            w.writerow(["Protocol","Remote","PID","Process","Status","Risk","Reason"])
            for c in self._conns:
                w.writerow([c.protocol,c.remote_addr,c.pid,c.process_name,
                            c.status,c.risk,c.risk_reason])
        _toast(self.winfo_toplevel(), f"Exported: {p}", T.ACCENT_GREEN)

    def _start_sparkline(self):
        if self._running:
            return
        self._running = True
        threading.Thread(target=self._sparkline_worker, daemon=True).start()
        self._poll_sparkline()

    def _sparkline_worker(self):
        """Background thread: only collects numbers, never touches tkinter."""
        try:
            import psutil
            prev = psutil.net_io_counters()
        except Exception:
            return
        while self._running:
            time.sleep(0.6)
            try:
                import psutil
                curr = psutil.net_io_counters()
                delta = (curr.bytes_sent + curr.bytes_recv
                         - prev.bytes_sent - prev.bytes_recv) / 1024
                sample = max(0.0, delta)
                prev = curr
                # Drop if queue full (non-blocking)
                try:
                    self._spark_q.put_nowait(sample)
                except queue.Full:
                    pass
            except Exception:
                break

    def _poll_sparkline(self):
        """Main-thread poller: drains queue and redraws canvas safely."""
        if not self._running:
            return
        try:
            while True:
                sample = self._spark_q.get_nowait()
                self._samples.append(sample)
                if len(self._samples) > 60:
                    self._samples.pop(0)
        except queue.Empty:
            pass
        self._draw_sparkline()
        # Schedule next poll in 700 ms (main thread safe)
        self.after(700, self._poll_sparkline)

    def _draw_sparkline(self):
        c = self._canvas
        w = c.winfo_width() or 900; h = 110
        c.delete("all")
        s = self._samples[-60:]
        if not s or max(s) == 0: return
        peak = max(s)
        pts = []
        step = w / max(len(s)-1, 1)
        for i, v in enumerate(s):
            pts.extend([i*step, h-(v/peak)*(h-8)-4])
        if len(pts) >= 4:
            c.create_polygon([0,h]+pts+[w,h], fill="#0a2a5e", outline="")
            c.create_line(pts, fill=T.ACCENT_BLUE, width=2, smooth=True)
        # KB/s label
        if s: c.create_text(w-4, 6, anchor="ne",
                             text=f"{s[-1]:.1f} KB/s", fill=T.TEXT_SECONDARY,
                             font=T.FONT_SMALL)


# ─────────────────────────────────────────────────────────────────────────────
# Persistence Audit Page
# ─────────────────────────────────────────────────────────────────────────────
class PersistencePage(tk.Frame):
    def __init__(self, master, engine, **kw):
        super().__init__(master, bg=T.BG_DARK, **kw)
        self._engine  = engine
        self._entries: list[persistence.PersistenceEntry] = []
        self._build()

    def _build(self):
        hdr = _fr(self)
        hdr.pack(fill="x", pady=(8,4), padx=10)
        _lbl(hdr, "Persistence Auditor", font=T.FONT_TITLE).pack(anchor="w")
        _lbl(hdr, "Registry Run Keys · Startup Folders · Scheduled Tasks · Services",
             fg=T.TEXT_SECONDARY, font=T.FONT_SUBTITLE).pack(anchor="w")

        bf = _fr(self)
        bf.pack(fill="x", padx=8, pady=4)
        _btn(bf, "⟳  Re-Audit", self.on_show, bg=T.BG_PANEL).pack(side="left")
        _btn(bf, "Export CSV", self._export_csv, bg=T.BG_PANEL).pack(side="left", padx=6)
        self._stat = _lbl(bf, "", T.TEXT_SECONDARY, T.BG_DARK, T.FONT_SMALL)
        self._stat.pack(side="left", padx=10)

        # Treeview
        lf = _fr(self)
        lf.pack(fill="both", expand=True, padx=6, pady=4)
        cols = ("name","type","path","risk","mitre")
        self._tree = ttk.Treeview(lf, columns=cols, show="headings", style="Dark.Treeview")
        for col,w,txt in [("name",160,"Name"),("type",130,"Type"),
                          ("path",300,"Path"),("risk",90,"Risk"),("mitre",200,"MITRE")]:
            self._tree.heading(col, text=txt)
            self._tree.column(col, width=w, stretch=(col=="path"))
        self._tree.tag_configure("suspicious", foreground=T.ACCENT_YELLOW)
        self._tree.tag_configure("normal",     foreground=T.TEXT_SECONDARY)
        sb = ttk.Scrollbar(lf, command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self._tree.bind("<Button-3>", self._on_rightclick)
        self._tree.bind("<Button-2>", self._on_rightclick)

    def on_show(self):
        self._stat.config(text="Auditing...")
        self._tree.delete(*self._tree.get_children())
        def worker():
            entries = persistence.audit_persistence()
            self.after(0, lambda: self._render(entries))
        threading.Thread(target=worker, daemon=True).start()

    def _render(self, entries):
        self._entries = entries
        self._tree.delete(*self._tree.get_children())
        sus = 0
        for e in entries:
            tag = "suspicious" if e.risk=="suspicious" else "normal"
            self._tree.insert("","end",
                values=(e.name, e.entry_type, e.path[:80], e.risk.upper(), e.mitre[:40]),
                tags=(tag,))
            if e.risk == "suspicious": sus += 1
        self._stat.config(text=f"{len(entries)} entries | {sus} suspicious")
        self._show_toast(f"Audit Complete\nScanned {len(entries)} startup items.")

    def _get_entry(self) -> Optional[persistence.PersistenceEntry]:
        sel = self._tree.selection()
        if not sel: return None
        idx = self._tree.index(sel[0])
        return self._entries[idx] if idx < len(self._entries) else None

    def _on_rightclick(self, event):
        row = self._tree.identify_row(event.y)
        if not row: return
        self._tree.selection_set(row)
        e = self._get_entry()
        if not e: return
        items = [
            ("🚫  Disable Entry",         lambda: self._disable(e)),
            ("🗑  Delete Permanently",     lambda: self._delete(e)),
            None,
            ("🔬  Analyze Behavior",       lambda: self._analyze(e)),
            ("📤  Export as STIX 2.1",     lambda: self._export_stix(e)),
            ("🔍  Scan Parent Process",     lambda: self._scan_parent(e)),
            None,
            ("📋  Copy Path",              lambda: self._copy(e.path)),
            ("📋  Copy Name",              lambda: self._copy(e.name)),
        ]
        _context_menu(event, items)

    def _disable(self, e: persistence.PersistenceEntry):
        if e.reg_hive and e.reg_value:
            ok, msg = persistence.disable_registry_entry(e.reg_hive, e.reg_value)
        elif os.path.isfile(e.path):
            # Rename with .disabled suffix
            try:
                os.rename(e.path, e.path+".disabled")
                ok, msg = True, f"Renamed to {e.path}.disabled"
            except Exception as ex:
                ok, msg = False, str(ex)
        else:
            ok, msg = False, "Cannot disable this entry type automatically"
        _toast(self.winfo_toplevel(), f"{'✔' if ok else '✘'} {msg}",
               T.ACCENT_GREEN if ok else T.ACCENT_RED)
        if ok: self.on_show()

    def _delete(self, e: persistence.PersistenceEntry):
        if not messagebox.askyesno("Delete", f"Permanently delete '{e.name}'?"): return
        ok1, msg1 = (False,"")
        ok2, msg2 = (False,"")
        if e.reg_hive and e.reg_value:
            ok1, msg1 = persistence.delete_registry_entry(e.reg_hive, e.reg_value)
        if os.path.isfile(e.path):
            ok2, msg2 = persistence.delete_file_entry(e.path)
        ok = ok1 or ok2
        _toast(self.winfo_toplevel(), f"{'✔' if ok else '✘'} {msg1 or msg2}",
               T.ACCENT_GREEN if ok else T.ACCENT_RED)
        if ok: self.on_show()

    def _analyze(self, e: persistence.PersistenceEntry):
        _toast(self.winfo_toplevel(), f"Analyzing {e.name}...", T.ACCENT_BLUE)
        def worker():
            r = persistence.analyze_behavior(e.path)
            text = f"File: {r.get('filepath','—')}\n"
            text += f"Verdict: {r.get('verdict','—').upper()}\n"
            text += f"Score: {r.get('score',0)}/100\n"
            text += f"Entropy: {r.get('entropy',0):.2f}\n\n"
            text += "Flags:\n" + "\n".join(f"  • {f}" for f in r.get('flags',[]))
            if r.get('imports_count'):
                text += f"\n\nTotal PE imports: {r['imports_count']}"
            self.after(0, lambda: _info_dialog(f"Behavior Analysis — {e.name}", text))
        threading.Thread(target=worker, daemon=True).start()

    def _export_stix(self, e: persistence.PersistenceEntry):
        stix = persistence.export_stix(e)
        p = filedialog.asksaveasfilename(
            defaultextension=".json", initialfile=f"stix_{e.name}.json",
            filetypes=[("JSON","*.json")])
        if not p: return
        with open(p,"w") as f:
            json.dump(stix, f, indent=2)
        _toast(self.winfo_toplevel(), f"STIX exported: {p}", T.ACCENT_GREEN)

    def _scan_parent(self, e: persistence.PersistenceEntry):
        _toast(self.winfo_toplevel(), "Scanning parent process...", T.ACCENT_BLUE)
        def worker():
            # Try to find PID by exe path
            try:
                import psutil
                for proc in psutil.process_iter(["pid","exe","name"]):
                    if proc.info["exe"] and e.path.lower() in proc.info["exe"].lower():
                        r = persistence.scan_parent_process(proc.info["pid"])
                        txt = "\n".join(f"{k}: {v}" for k,v in r.items())
                        self.after(0, lambda t=txt: _info_dialog("Parent Process Scan", t))
                        return
                self.after(0, lambda: _info_dialog("Parent Process Scan",
                                                    "Process not currently running."))
            except Exception as ex:
                self.after(0, lambda: _info_dialog("Error", str(ex)))
        threading.Thread(target=worker, daemon=True).start()

    def _export_csv(self):
        p = filedialog.asksaveasfilename(defaultextension=".csv",
                                         filetypes=[("CSV","*.csv")])
        if not p: return
        import csv
        with open(p,"w",newline="") as f:
            w = csv.writer(f)
            w.writerow(["Name","Type","Path","Risk","MITRE"])
            for e in self._entries:
                w.writerow([e.name,e.entry_type,e.path,e.risk,e.mitre])
        _toast(self.winfo_toplevel(), f"Exported: {p}", T.ACCENT_GREEN)

    def _copy(self, text):
        self.clipboard_clear(); self.clipboard_append(text)
        _toast(self.winfo_toplevel(), f"Copied: {text[:60]}", T.ACCENT_BLUE, 1500)

    def _show_toast(self, msg):
        t = tk.Toplevel(self)
        t.overrideredirect(True)
        t.configure(bg=T.BG_PANEL)
        t.attributes("-topmost", True)
        pw = self.winfo_toplevel()
        pw.update_idletasks()
        x = pw.winfo_x()+pw.winfo_width()-340
        y = pw.winfo_y()+pw.winfo_height()-110
        t.geometry(f"320x80+{x}+{y}")
        frm = _fr(t, T.BG_PANEL); frm.pack(fill="both",expand=True,padx=1,pady=1)
        _lbl(frm,"x2yDevsTools.X2yAVUltimate",T.TEXT_SECONDARY,T.BG_PANEL,T.FONT_SMALL).pack(anchor="w",padx=10,pady=(8,0))
        for i,line in enumerate(msg.split("\n")):
            _lbl(frm,line,T.TEXT_PRIMARY,T.BG_PANEL,
                 ("Consolas",10,"bold") if i==0 else T.FONT_SMALL).pack(anchor="w",padx=10)
        _btn(frm,"✕",t.destroy,T.TEXT_SECONDARY,T.BG_PANEL,T.FONT_SMALL).place(relx=1,x=-8,y=4,anchor="ne")
        t.after(5000, t.destroy)


# ─────────────────────────────────────────────────────────────────────────────
# Quarantine Vault Page
# ─────────────────────────────────────────────────────────────────────────────
class QuarantinePage(tk.Frame):
    def __init__(self, master, **kw):
        super().__init__(master, bg=T.BG_DARK, **kw)
        self._build()

    def _build(self):
        hdr = _fr(self)
        hdr.pack(fill="x", pady=(8,4), padx=10)
        _lbl(hdr, "Quarantine Vault", font=T.FONT_TITLE).pack(anchor="w")
        _lbl(hdr, "Isolated Threats (.x2y_quarantine)", fg=T.TEXT_SECONDARY,
             font=T.FONT_SUBTITLE).pack(anchor="w")

        bf = _fr(self)
        bf.pack(fill="x", padx=8, pady=4)
        _btn(bf, "⟳  Refresh", self.on_show, bg=T.BG_PANEL).pack(side="left")
        _btn(bf, "Delete All", self._delete_all, bg=T.BG_PANEL, fg=T.ACCENT_RED).pack(side="left", padx=6)
        self._stat = _lbl(bf,"",T.TEXT_SECONDARY,T.BG_DARK,T.FONT_SMALL)
        self._stat.pack(side="left",padx=10)

        lf = _fr(self)
        lf.pack(fill="both", expand=True, padx=6, pady=4)
        cols = ("name","threat","type","size","time")
        self._tree = ttk.Treeview(lf, columns=cols, show="headings", style="Dark.Treeview")
        for col,w,txt in [("name",180,"File"),("threat",180,"Threat"),
                          ("type",100,"Detection"),("size",80,"Size"),("time",160,"Quarantined")]:
            self._tree.heading(col, text=txt)
            self._tree.column(col, width=w, stretch=(col=="threat"))
        sb = ttk.Scrollbar(lf, command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        self._tree.pack(side="left",fill="both",expand=True)
        sb.pack(side="right",fill="y")
        self._tree.bind("<Button-3>", self._on_rightclick)
        self._tree.bind("<Button-2>", self._on_rightclick)
        self._items: list[quarantine.QuarantinedFile] = []

    def on_show(self):
        self._tree.delete(*self._tree.get_children())
        items = quarantine.list_quarantined()
        self._items = items
        if not items:
            self._stat.config(text="Vault Empty")
            return
        for i in items:
            sz = f"{i.file_size/1024:.1f} KB"
            self._tree.insert("","end",
                values=(os.path.basename(i.original_path), i.threat_name,
                        i.detection_type, sz, i.quarantine_time),
                tags=("threat",))
        self._tree.tag_configure("threat", foreground=T.ACCENT_RED)
        self._stat.config(text=f"{len(items)} isolated files")

    def _get_item(self) -> Optional[quarantine.QuarantinedFile]:
        sel = self._tree.selection()
        if not sel: return None
        idx = self._tree.index(sel[0])
        return self._items[idx] if idx < len(self._items) else None

    def _on_rightclick(self, event):
        row = self._tree.identify_row(event.y)
        if not row: return
        self._tree.selection_set(row)
        item = self._get_item()
        if not item: return
        _context_menu(event, [
            ("♻  Restore File",        lambda: self._restore(item)),
            ("🗑  Delete Permanently",  lambda: self._delete(item)),
            None,
            ("📋  Copy Original Path", lambda: self._copy(item.original_path)),
            ("ℹ  File Info",           lambda: self._info(item)),
        ])

    def _restore(self, item):
        if messagebox.askyesno("Restore", f"Restore to original location?\n{item.original_path}"):
            ok, msg = quarantine.restore_file(item.id)
            _toast(self.winfo_toplevel(), f"{'✔' if ok else '✘'} {msg}",
                   T.ACCENT_GREEN if ok else T.ACCENT_RED)
            self.on_show()

    def _delete(self, item):
        if messagebox.askyesno("Delete", "Permanently delete this file?"):
            ok, msg = quarantine.delete_from_vault(item.id)
            _toast(self.winfo_toplevel(), f"{'✔' if ok else '✘'} {msg}",
                   T.ACCENT_GREEN if ok else T.ACCENT_RED)
            self.on_show()

    def _delete_all(self):
        if not self._items: return
        if messagebox.askyesno("Delete All", f"Permanently delete all {len(self._items)} quarantined files?"):
            for i in self._items:
                quarantine.delete_from_vault(i.id)
            self.on_show()

    def _info(self, item):
        text = (f"Original: {item.original_path}\n"
                f"Vault:    {item.vault_path}\n"
                f"Threat:   {item.threat_name}\n"
                f"Detect:   {item.detection_type}\n"
                f"SHA256:   {item.sha256}\n"
                f"Size:     {item.file_size} bytes\n"
                f"Time:     {item.quarantine_time}")
        _info_dialog("File Info", text)

    def _copy(self, text):
        self.clipboard_clear(); self.clipboard_append(text)


# ─────────────────────────────────────────────────────────────────────────────
# Threat Intelligence Page (NEW)
# ─────────────────────────────────────────────────────────────────────────────
class ThreatIntelPage(tk.Frame):
    def __init__(self, master, engine, **kw):
        super().__init__(master, bg=T.BG_DARK, **kw)
        self._engine = engine
        self._build()

    def _build(self):
        hdr = _fr(self)
        hdr.pack(fill="x", pady=(8,4), padx=10)
        _lbl(hdr, "Threat Intelligence", font=T.FONT_TITLE).pack(anchor="w")
        _lbl(hdr, "Signature Sources · Hash Lookup · IOC Feed Manager",
             fg=T.TEXT_SECONDARY, font=T.FONT_SUBTITLE).pack(anchor="w")

        # Update panel
        upd = _fr(self, T.BG_PANEL)
        upd.pack(fill="x", padx=6, pady=6)
        _lbl(upd, "Signature Update Center", fg=T.TEXT_PRIMARY, bg=T.BG_PANEL,
             font=T.FONT_CARD).pack(anchor="w", padx=12, pady=(8,4))

        self._log = tk.Text(upd, bg=T.BG_DARK, fg=T.TEXT_PRIMARY, font=T.FONT_MONO,
                            relief="flat", bd=0, height=8, state="disabled")
        self._log.pack(fill="x", padx=8, pady=4)

        bf = _fr(upd, T.BG_PANEL)
        bf.pack(fill="x", padx=8, pady=(0,8))
        for txt,cmd in [
            ("⬇  MalwareBazaar (Recent)", lambda: self._update("mb_recent")),
            ("⬇  MalwareBazaar (Full)",   lambda: self._update("mb_full")),
            ("⬇  URLhaus",                lambda: self._update("urlhaus")),
            ("⬇  OpenPhish",              lambda: self._update("openphish")),
            ("⬇  ClamAV freshclam",       lambda: self._update("clamav")),
            ("⬇  All Sources",            lambda: self._update("all")),
        ]:
            _btn(bf, txt, cmd, bg=T.BG_HOVER, pady=3).pack(side="left", padx=3)

        self._count_lbl = _lbl(self, "", T.ACCENT_GREEN, T.BG_DARK, T.FONT_BODY)
        self._count_lbl.pack(pady=4)

        # Hash lookup
        lookup_fr = _fr(self, T.BG_PANEL)
        lookup_fr.pack(fill="x", padx=6, pady=4)
        _lbl(lookup_fr, "Hash Lookup", fg=T.TEXT_PRIMARY, bg=T.BG_PANEL,
             font=T.FONT_CARD).pack(anchor="w", padx=12, pady=(8,4))
        row = _fr(lookup_fr, T.BG_PANEL)
        row.pack(fill="x", padx=8, pady=(0,8))
        self._hash_entry = tk.Entry(row, bg=T.BG_DARK, fg=T.TEXT_PRIMARY,
                                    font=T.FONT_MONO, relief="flat", bd=0,
                                    insertbackground=T.TEXT_PRIMARY, width=68)
        self._hash_entry.insert(0, "Enter SHA256 or MD5 hash...")
        self._hash_entry.bind("<FocusIn>", lambda e: self._hash_entry.delete(0,"end")
                              if "Enter" in self._hash_entry.get() else None)
        self._hash_entry.pack(side="left", fill="x", expand=True, padx=(0,6), pady=4)
        _btn(row, "Lookup", self._hash_lookup, bg=T.ACCENT_BLUE, fg="white").pack(side="right")
        self._lookup_result = _lbl(lookup_fr, "", T.TEXT_SECONDARY, T.BG_PANEL, T.FONT_BODY)
        self._lookup_result.pack(anchor="w", padx=12, pady=(0,8))

        # Stats
        stats_fr = _fr(self, T.BG_PANEL)
        stats_fr.pack(fill="x", padx=6, pady=4)
        _lbl(stats_fr,"Database Statistics",fg=T.TEXT_PRIMARY,bg=T.BG_PANEL,font=T.FONT_CARD).pack(anchor="w",padx=12,pady=(8,4))
        self._stats_lbl = _lbl(stats_fr,"",T.TEXT_SECONDARY,T.BG_PANEL,T.FONT_SMALL)
        self._stats_lbl.pack(anchor="w",padx=12,pady=(0,8))
        self._refresh_stats()

    def _log_line(self, msg: str):
        self._log.config(state="normal")
        self._log.insert("end", f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self._log.see("end")
        self._log.config(state="disabled")

    def _update(self, source: str):
        def worker():
            db = self._engine.db
            if source == "mb_recent":
                sc.update_malwarebazaar(db, full=False, cb=lambda m: self.after(0,lambda msg=m:self._log_line(msg)))
            elif source == "mb_full":
                sc.update_malwarebazaar(db, full=True,  cb=lambda m: self.after(0,lambda msg=m:self._log_line(msg)))
            elif source == "urlhaus":
                sc.update_urlhaus(cb=lambda m: self.after(0,lambda msg=m:self._log_line(msg)))
            elif source == "openphish":
                sc.update_openphish(cb=lambda m: self.after(0,lambda msg=m:self._log_line(msg)))
            elif source == "clamav":
                sc.update_clamav(cb=lambda m: self.after(0,lambda msg=m:self._log_line(msg)))
            elif source == "all":
                sc.full_sig_update(db, cb=lambda m: self.after(0,lambda msg=m:self._log_line(msg)))
            self.after(0, self._refresh_stats)
        threading.Thread(target=worker, daemon=True).start()

    def _hash_lookup(self):
        h = self._hash_entry.get().strip().lower()
        if not h or "enter" in h.lower(): return
        result = self._engine.db.lookup(h)
        if result:
            self._lookup_result.config(text=f"⛔  THREAT FOUND: {result}", fg=T.ACCENT_RED)
        else:
            self._lookup_result.config(text="✔  Hash not found in database (clean)", fg=T.ACCENT_GREEN)

    def _refresh_stats(self):
        count = self._engine.db.count()
        last  = settings_mgr.get("last_sig_update") or "Never"
        self._count_lbl.config(text=f"Total signatures: {count:,}")
        self._stats_lbl.config(text=f"Signatures: {count:,}   |   Last update: {last}")

    def on_show(self):
        self._refresh_stats()


# ─────────────────────────────────────────────────────────────────────────────
# Settings Page
# ─────────────────────────────────────────────────────────────────────────────
class SettingsPage(tk.Frame):
    def __init__(self, master, **kw):
        super().__init__(master, bg=T.BG_DARK, **kw)
        self._s = settings_mgr.load()
        self._build()

    def _reload(self):
        self._s = settings_mgr.load()

    def _save(self):
        settings_mgr.save(self._s)

    def _section(self, p, title):
        _lbl(p, title, T.ACCENT_BLUE, T.BG_DARK, T.FONT_SMALL).pack(anchor="w", pady=(14,3), padx=10)
        _sep(p).pack(fill="x", padx=10)

    def _toggle(self, p, title, sub, key, on_change=None):
        row = _fr(p, T.BG_PANEL)
        row.pack(fill="x", padx=10, pady=1)
        info = _fr(row, T.BG_PANEL)
        info.pack(side="left", fill="x", expand=True, padx=12, pady=8)
        _lbl(info, title, T.TEXT_PRIMARY, T.BG_PANEL, T.FONT_BODY).pack(anchor="w")
        _lbl(info, sub, T.TEXT_SECONDARY, T.BG_PANEL, T.FONT_SMALL).pack(anchor="w")
        var = tk.BooleanVar(value=self._s.get(key, False))
        def on_toggle():
            self._s[key] = var.get()
            self._save()
            if on_change: on_change(var.get())
        tk.Checkbutton(row, variable=var, command=on_toggle,
                       bg=T.BG_PANEL, activebackground=T.BG_PANEL,
                       fg=T.ACCENT_GREEN, selectcolor=T.BG_PANEL,
                       relief="flat", bd=0, cursor="hand2").pack(side="right", padx=12)
        return var

    def _time_row(self, p, title, key):
        row = _fr(p, T.BG_PANEL)
        row.pack(fill="x", padx=10, pady=1)
        _lbl(row, title, T.TEXT_SECONDARY, T.BG_PANEL, T.FONT_SMALL).pack(side="left",padx=12,pady=6)
        var = tk.StringVar(value=self._s.get(key,"02:00"))
        ent = tk.Entry(row, textvariable=var, bg=T.BG_DARK, fg=T.TEXT_PRIMARY,
                       font=T.FONT_MONO, relief="flat", bd=0, width=8,
                       insertbackground=T.TEXT_PRIMARY)
        ent.pack(side="right", padx=12, pady=6)
        def save_time(*_):
            self._s[key] = var.get()
            self._save()
        var.trace_add("write", save_time)

    def _combo_row(self, p, title, key, options):
        row = _fr(p, T.BG_PANEL)
        row.pack(fill="x", padx=10, pady=1)
        _lbl(row, title, T.TEXT_SECONDARY, T.BG_PANEL, T.FONT_SMALL).pack(side="left",padx=12,pady=6)
        var = tk.StringVar(value=self._s.get(key, options[0]))
        combo = ttk.Combobox(row, textvariable=var, values=options, state="readonly",
                             font=T.FONT_SMALL, width=14)
        combo.pack(side="right", padx=12, pady=6)
        def save_combo(*_):
            self._s[key] = var.get(); self._save()
        var.trace_add("write", save_combo)

    def _slider_row(self, p, title, key, frm, to):
        row = _fr(p, T.BG_PANEL)
        row.pack(fill="x", padx=10, pady=1)
        _lbl(row, title, T.TEXT_SECONDARY, T.BG_PANEL, T.FONT_SMALL).pack(side="left",padx=12,pady=6)
        var = tk.IntVar(value=self._s.get(key, frm))
        val_lbl = _lbl(row, str(var.get()), T.ACCENT_BLUE, T.BG_PANEL, T.FONT_SMALL)
        val_lbl.pack(side="right", padx=(0,12))
        def on_slide(v):
            self._s[key] = int(float(v)); self._save()
            val_lbl.config(text=str(int(float(v))))
        tk.Scale(row, variable=var, from_=frm, to=to, orient="horizontal",
                 command=on_slide, bg=T.BG_PANEL, fg=T.TEXT_SECONDARY,
                 highlightthickness=0, sliderrelief="flat",
                 troughcolor=T.BG_DARK, activebackground=T.ACCENT_BLUE,
                 length=180).pack(side="right", padx=4)

    def _build(self):
        _lbl(self, "Settings & Policy", font=T.FONT_TITLE).pack(anchor="w", padx=10, pady=(8,4))

        canvas = tk.Canvas(self, bg=T.BG_DARK, highlightthickness=0)
        sb = ttk.Scrollbar(self, command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = _fr(canvas, T.BG_DARK)
        canvas.create_window((0,0), window=inner, anchor="nw")

        # ── Threat Intelligence
        self._section(inner, "THREAT INTELLIGENCE")
        sig_row = _fr(inner, T.BG_PANEL)
        sig_row.pack(fill="x", padx=10, pady=1)
        sig_info = _fr(sig_row, T.BG_PANEL)
        sig_info.pack(side="left", fill="x", expand=True, padx=12, pady=8)
        _lbl(sig_info,"Update Virus Definitions",T.TEXT_PRIMARY,T.BG_PANEL,T.FONT_BODY).pack(anchor="w")
        n = settings_mgr.get("signatures_loaded") or 0
        self._sig_sub = _lbl(sig_info, f"{n} signatures loaded", T.TEXT_SECONDARY, T.BG_PANEL, T.FONT_SMALL)
        self._sig_sub.pack(anchor="w")
        _btn(sig_row, "⟳", self._do_sig_update, fg=T.ACCENT_BLUE, bg=T.BG_PANEL,
             font=("Consolas",16)).pack(side="right", padx=12)

        self._toggle(inner, "Auto-Update Signatures",
                     "Download fresh signatures automatically",
                     "auto_sig_update")
        self._slider_row(inner, "Update interval (hours)", "sig_update_interval_h", 1, 72)

        # ── Real-Time Protection
        self._section(inner, "REAL-TIME PROTECTION")
        self._toggle(inner, "Background Shield",
                     "Monitor file creation and process execution events.",
                     "background_shield",
                     on_change=self._toggle_shield)
        self._toggle(inner, "Auto Quarantine Threats",
                     "Automatically move threats to vault upon detection.",
                     "auto_quarantine")
        self._combo_row(inner, "Heuristic Sensitivity", "heuristic_sensitivity",
                        ["low","medium","high"])
        self._slider_row(inner, "Max file scan size (MB)", "max_file_size_mb", 1, 256)

        # ── Startup
        self._section(inner, "STARTUP")
        self._toggle(inner, "Run on Startup",
                     "Launch x2y AV automatically when OS boots.",
                     "run_on_startup",
                     on_change=lambda v: settings_mgr.enable_startup(v))

        # ── Automated Tasks
        self._section(inner, "AUTOMATED TASKS")
        self._toggle(inner, "Daily Quick Scan",
                     "Scan critical directories on schedule.", "daily_quick_scan")
        self._time_row(inner, "Daily scan time (HH:MM)", "daily_quick_scan_time")
        self._toggle(inner, "Weekly Full Scan",
                     "Full drive scan on a weekly schedule.", "weekly_full_scan")
        self._combo_row(inner, "Full scan day", "weekly_full_scan_day",
                        ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"])
        self._time_row(inner, "Weekly scan time (HH:MM)", "weekly_full_scan_time")

        # ── Exclusion Zones
        self._section(inner, "EXCLUSION ZONES")
        ex_row = _fr(inner, T.BG_PANEL)
        ex_row.pack(fill="x", padx=10, pady=1)
        self._excl_ent = tk.Entry(ex_row, bg=T.BG_PANEL, fg=T.TEXT_SECONDARY,
                                  font=T.FONT_BODY, relief="flat", bd=0,
                                  insertbackground=T.TEXT_PRIMARY)
        self._excl_ent.insert(0, "Add path ...")
        self._excl_ent.bind("<FocusIn>", lambda e: self._excl_ent.delete(0,"end")
                            if self._excl_ent.get()=="Add path ..." else None)
        self._excl_ent.pack(side="left", fill="x", expand=True, padx=12, pady=10)
        _btn(ex_row, "+", self._add_excl, T.TEXT_PRIMARY, T.BG_PANEL,
             font=("Consolas",16)).pack(side="right", padx=8)
        _btn(ex_row, "Browse", self._browse_excl, T.TEXT_SECONDARY, T.BG_PANEL,
             font=T.FONT_SMALL).pack(side="right")
        self._excl_list = _fr(inner, T.BG_DARK)
        self._excl_list.pack(fill="x", padx=10)
        self._refresh_excl()

        # ── Quarantine
        self._section(inner, "QUARANTINE")
        qrow = _fr(inner, T.BG_PANEL)
        qrow.pack(fill="x", padx=10, pady=1)
        _lbl(qrow, "Vault location:", T.TEXT_SECONDARY, T.BG_PANEL, T.FONT_SMALL).pack(side="left",padx=12,pady=8)
        self._qdir_lbl = _lbl(qrow, settings_mgr.get("quarantine_dir") or quarantine.VAULT_DIR,
                               T.TEXT_MONO, T.BG_PANEL, T.FONT_SMALL)
        self._qdir_lbl.pack(side="left")
        _btn(qrow, "Change", self._change_vault_dir, T.ACCENT_BLUE, T.BG_PANEL,
             T.FONT_SMALL).pack(side="right", padx=8)

        # ── Notifications
        self._section(inner, "NOTIFICATIONS")
        self._toggle(inner, "Desktop Notifications",
                     "Show toast alerts for threats detected.", "show_notifications")

        # ── Logging
        self._section(inner, "LOGGING")
        self._combo_row(inner, "Log level", "log_level",
                        ["DEBUG","INFO","WARNING","ERROR"])
        lp = settings_mgr.LOG_PATH
        log_row = _fr(inner, T.BG_PANEL)
        log_row.pack(fill="x", padx=10, pady=1)
        _lbl(log_row, f"Log file: {lp}", T.TEXT_SECONDARY, T.BG_PANEL, T.FONT_SMALL).pack(side="left",padx=12,pady=6)
        _btn(log_row, "Open Log", lambda: self._open_log(lp), T.ACCENT_BLUE, T.BG_PANEL, T.FONT_SMALL).pack(side="right",padx=8)

        # ── Support
        self._section(inner, "SUPPORT")
        sup = _fr(inner, T.BG_PANEL)
        sup.pack(fill="x", padx=10, pady=1)
        _lbl(sup,"✉",T.TEXT_SECONDARY,T.BG_PANEL,("Consolas",14)).pack(side="left",padx=12,pady=10)
        si = _fr(sup, T.BG_PANEL); si.pack(side="left",pady=8)
        _lbl(si,"Contact Support",T.TEXT_PRIMARY,T.BG_PANEL,T.FONT_BODY).pack(anchor="w")
        _lbl(si,"support@x2ydevs.xyz",T.ACCENT_BLUE,T.BG_PANEL,T.FONT_SMALL).pack(anchor="w")

        inner.update_idletasks()
        canvas.config(scrollregion=canvas.bbox("all"))

    def _do_sig_update(self):
        self._sig_sub.config(text="Updating...")
        def worker():
            import scanner as sc
            n = sc.update_malwarebazaar(sc.ScannerEngine().db,
                                        cb=lambda m: None)
            total = sc.ScannerEngine().db.count()
            self.after(0, lambda: self._sig_sub.config(text=f"{total} signatures — updated now"))
        threading.Thread(target=worker, daemon=True).start()

    def _toggle_shield(self, enabled: bool):
        if settings_mgr.get("show_notifications"):
            threading.Thread(
                target=lambda: _send_os_notification(
                    "x2y AV — Shield " + ("Enabled" if enabled else "Disabled"),
                    "Background Shield is now " + ("active." if enabled else "off. Your system is unprotected.")
                ), daemon=True).start()
        _toast(self.winfo_toplevel(),
               f"Background Shield {'enabled' if enabled else 'disabled'}",
               T.ACCENT_GREEN if enabled else T.ACCENT_YELLOW)

    def _add_excl(self):
        p = self._excl_ent.get().strip()
        if p and p != "Add path ...":
            zones = settings_mgr.get("exclusion_zones") or []
            if p not in zones:
                zones.append(p)
                settings_mgr.set_val("exclusion_zones", zones)
            self._excl_ent.delete(0,"end")
            self._refresh_excl()

    def _browse_excl(self):
        p = filedialog.askdirectory(title="Select exclusion folder")
        if p:
            self._excl_ent.delete(0,"end")
            self._excl_ent.insert(0, p)
            self._add_excl()

    def _refresh_excl(self):
        for w in self._excl_list.winfo_children(): w.destroy()
        for z in (settings_mgr.get("exclusion_zones") or []):
            r = _fr(self._excl_list, T.BG_PANEL)
            r.pack(fill="x", pady=1)
            _lbl(r, z, T.TEXT_SECONDARY, T.BG_PANEL, T.FONT_SMALL).pack(side="left",padx=12,pady=4)
            _btn(r,"✕",lambda p=z: self._rm_excl(p),T.ACCENT_RED,T.BG_PANEL,T.FONT_SMALL).pack(side="right",padx=4)

    def _rm_excl(self, p):
        zones = [z for z in (settings_mgr.get("exclusion_zones") or []) if z!=p]
        settings_mgr.set_val("exclusion_zones", zones)
        self._refresh_excl()

    def _change_vault_dir(self):
        p = filedialog.askdirectory(title="Select quarantine vault location")
        if p:
            settings_mgr.set_val("quarantine_dir", p)
            self._qdir_lbl.config(text=p)

    def _open_log(self, path):
        if os.path.exists(path):
            try:
                if sys.platform=="win32": os.startfile(path)
                elif sys.platform=="darwin": os.system(f"open '{path}'")
                else: os.system(f"xdg-open '{path}'")
            except Exception:
                _info_dialog("Log File", open(path).read()[-5000:])
        else:
            _info_dialog("Log File", "No log file created yet.")

    def on_show(self):
        self._reload()


# ─────────────────────────────────────────────────────────────────────────────
# Main App
# ─────────────────────────────────────────────────────────────────────────────
class X2yAVApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"x2y AV Ultimate v{APP_VERSION}")
        self.geometry("1340x820")
        self.minsize(1000, 620)
        self.configure(bg=T.BG_DARK)
        try: self.iconbitmap("icon.ico")
        except Exception: pass

        self._engine  = sc.ScannerEngine()
        self._current = None
        self._setup_styles()
        self._build_ui()
        self._nav_to("scan")
        settings_mgr.start_scheduler()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._setup_logging()

        # Send desktop notification if enabled
        if settings_mgr.get("show_notifications"):
            self.after(1500, lambda: threading.Thread(
                target=lambda: _send_os_notification(
                    "x2y AV — Protection Active",
                    "Real-time protection is active. Monitoring background processes."
                ), daemon=True).start()
            )

    def _setup_logging(self):
        import logging
        logging.basicConfig(
            filename=settings_mgr.LOG_PATH,
            level=getattr(logging, settings_mgr.get("log_level") or "INFO", logging.INFO),
            format="%(asctime)s %(name)s %(levelname)s: %(message)s"
        )

    def _on_close(self):
        settings_mgr.stop_scheduler()
        self.destroy()

    def _setup_styles(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("Dark.Treeview", background=T.BG_PANEL, foreground=T.TEXT_SECONDARY,
                    fieldbackground=T.BG_PANEL, borderwidth=0, rowheight=40, font=T.FONT_MONO)
        s.configure("Dark.Treeview.Heading", background=T.BG_DARK,
                    foreground=T.TEXT_SECONDARY, borderwidth=0, font=T.FONT_SMALL)
        s.map("Dark.Treeview", background=[("selected",T.BG_HOVER)],
              foreground=[("selected",T.TEXT_PRIMARY)])
        s.configure("Green.Horizontal.TProgressbar",
                    troughcolor=T.BG_PANEL, background=T.ACCENT_GREEN)
        s.configure("Vertical.TScrollbar", background=T.BG_PANEL,
                    troughcolor=T.BG_DARK, arrowcolor=T.TEXT_SECONDARY)

    def _build_ui(self):
        # No green status bar — protection status shown as OS notification (see __init__)

        # Sidebar
        sidebar = _fr(self, T.BG_SIDEBAR, width=T.SIDEBAR_WIDTH)
        sidebar.pack(fill="y", side="left")
        sidebar.pack_propagate(False)

        brand = _fr(sidebar, T.BG_SIDEBAR)
        brand.pack(fill="x", pady=(20,24), padx=16)
        _lbl(brand, "🛡", T.ACCENT_BLUE, T.BG_SIDEBAR, ("Consolas",20)).pack(side="left")
        nf = _fr(brand, T.BG_SIDEBAR); nf.pack(side="left", padx=8)
        _lbl(nf, "x2y AV", T.TEXT_PRIMARY, T.BG_SIDEBAR, T.FONT_BRAND).pack(anchor="w")
        _lbl(nf, "ULTIMATE", T.ACCENT_BLUE, T.BG_SIDEBAR, T.FONT_TAG).pack(anchor="w")

        self._nav_btns = {}
        nav = [
            ("⬚  Integrity Scan",      "scan"),
            ("∿  Network Monitor",     "network"),
            ("💾  Persistence Audit",   "persistence"),
            ("☠  Quarantine Vault",    "quarantine"),
            ("🌐  Threat Intelligence", "intel"),
        ]
        for label, key in nav:
            b = self._mkbtn(sidebar, label, key)
            b.pack(fill="x", pady=1)
            self._nav_btns[key] = b

        bot = _fr(sidebar, T.BG_SIDEBAR)
        bot.pack(side="bottom", fill="x", pady=(0,30))
        _lbl(bot, f"Developed by x2y devs tools\nv{APP_VERSION}",
             T.TEXT_SECONDARY, T.BG_SIDEBAR, T.FONT_SMALL, justify="center").pack(pady=(0,8))
        b = self._mkbtn(bot, "⚙  Settings", "settings")
        b.pack(fill="x")
        self._nav_btns["settings"] = b

        self._content = _fr(self)
        self._content.pack(fill="both", expand=True, side="left", padx=16, pady=12)

        self._pages = {
            "scan":        ScanPage(self._content, self._engine),
            "network":     NetworkPage(self._content),
            "persistence": PersistencePage(self._content, self._engine),
            "quarantine":  QuarantinePage(self._content),
            "intel":       ThreatIntelPage(self._content, self._engine),
            "settings":    SettingsPage(self._content),
        }

    def _mkbtn(self, parent, text, key):
        def click(): self._nav_to(key)
        b = tk.Button(parent, text=text, command=click,
                      fg=T.TEXT_SECONDARY, bg=T.BG_SIDEBAR, font=T.FONT_BODY,
                      relief="flat", bd=0, activebackground=T.BG_SELECTED,
                      activeforeground=T.TEXT_PRIMARY,
                      anchor="w", padx=20, pady=10, cursor="hand2")
        b.bind("<Enter>", lambda e: b.config(bg=T.BG_HOVER, fg=T.TEXT_PRIMARY)
               if b.cget("bg")!=T.BG_SELECTED else None)
        b.bind("<Leave>", lambda e: b.config(
            bg=T.BG_SIDEBAR if b.cget("bg")==T.BG_HOVER else b.cget("bg"),
            fg=T.TEXT_SECONDARY if b.cget("bg")==T.BG_SIDEBAR else b.cget("fg")))
        return b

    def _nav_to(self, key: str):
        if self._current and hasattr(self._pages.get(self._current),"on_hide"):
            self._pages[self._current].on_hide()
        for k,b in self._nav_btns.items():
            b.config(fg=T.TEXT_PRIMARY if k==key else T.TEXT_SECONDARY,
                     bg=T.BG_SELECTED if k==key else T.BG_SIDEBAR)
        for k,p in self._pages.items():
            p.pack(fill="both",expand=True) if k==key else p.pack_forget()
        self._current = key
        page = self._pages[key]
        if hasattr(page,"on_show"): page.on_show()