#!/usr/bin/env python3

import sys, subprocess, importlib

def _auto_install():
    """Auto-install missing dependencies. Works on live Kali, VM, and fresh installs."""
    packages = {
        "requests": "requests",
        "scapy": "scapy",
        "rich": "rich",
    }
    missing = []
    for import_name, pip_name in packages.items():
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing.append(pip_name)
    if missing:
        print(f"[PriViSecurity] Installing missing packages: {', '.join(missing)}")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install",
            "--break-system-packages", "-q",
            *missing
        ])
        print("[PriViSecurity] Done. Launching tool...\n")

_auto_install()

import time
import sys
import threading
import os
import re
import requests
from collections import deque
from scapy.all import sniff, IP, TCP, UDP, Raw, Ether, ARP
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.console import Console

console = Console()

class WireExplorerSentinel:
    def __init__(self):
        self.lock = threading.Lock()
        self.packet_history  = deque(maxlen=15)
        self.last_analysis   = "Sentinel Engine Active..."
        self.carved_strings  = "Awaiting payload data..."
        self.alerts          = deque(maxlen=200)
        self.ip_mac_map      = {}
        self.vendor_cache    = {}
        self.stats           = {"TCP": 0, "UDP": 0, "ARP": 0}
        self.active_filter   = ""
        self.running         = True

        # Vendor Lookup Queue (Background Thread)
        self._vendor_queue  = deque()
        self._vendor_thread = threading.Thread(target=self._vendor_worker, daemon=True)
        self._vendor_thread.start()
        self._vendor_last_call    = 0.0
        self._vendor_min_interval = 2.0
        self._cmd_queue = deque()

    def _vendor_worker(self):
        while self.running:
            if self._vendor_queue:
                mac = self._vendor_queue.popleft()
                with self.lock:
                    if mac in self.vendor_cache: continue
                    now = time.time()
                    if now - self._vendor_last_call < self._vendor_min_interval:
                        self._vendor_queue.appendleft(mac)
                        time.sleep(0.2); continue
                    self._vendor_last_call = now
                try:
                    response = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
                    vendor = response.text.strip() if response.status_code == 200 else "Unknown Hardware"
                except requests.exceptions.RequestException: vendor = "Unknown Hardware"
                with self.lock: self.vendor_cache[mac] = vendor
            else: time.sleep(0.05)

    def get_vendor(self, mac):
        with self.lock:
            if mac in self.vendor_cache: return self.vendor_cache[mac]
        if mac not in self._vendor_queue: self._vendor_queue.append(mac)
        return "Looking up..."

    def detect_spoof(self, pkt):
        if not (pkt.haslayer(ARP) and pkt[ARP].op == 2): return
        src_ip, src_mac = pkt[ARP].psrc, pkt[ARP].hwsrc
        with self.lock:
            if src_ip in self.ip_mac_map:
                if self.ip_mac_map[src_ip].lower() != src_mac.lower():
                    vendor = self.vendor_cache.get(src_mac, "Unknown")
                    self.alerts.appendleft(f"[bold red]!! MITM: {src_ip} SPOOFED BY {src_mac} ({vendor}) !![/bold red]")
                    sys.stderr.write('\a\a\a'); sys.stderr.flush()
            else: self.ip_mac_map[src_ip] = src_mac

    def carve_intel(self, pkt):
        if not pkt.haslayer(Raw): return "[grey]No readable data.[/grey]"
        try:
            raw_data = pkt[Raw].load.decode('utf-8', errors='replace')
        except: return "[grey]Binary Stream.[/grey]"
        found = re.findall(r"[\x20-\x7E]{4,}", raw_data)
        if not found: return "[grey]Encrypted Stream.[/grey]"
        text = " ".join(found)
        keywords = ["user", "pass", "login", "auth", "admin", "GET", "POST"]
        found_sensitive = False
        for word in keywords:
            if word.lower() in text.lower():
                text = re.sub(re.escape(word), f"[bold yellow]{word}[/bold yellow]", text, flags=re.IGNORECASE)
                found_sensitive = True
        if found_sensitive:
            sys.stderr.write('\a'); sys.stderr.flush()
        return text[:280]

    def translate_packet(self, pkt):
        if pkt.haslayer(ARP): return f"[bold magenta]ARP:[/bold magenta] {pkt[ARP].psrc} is advertising its MAC."
        if not pkt.haslayer(IP): return "Network Management Frame"
        src, dst = pkt[IP].src, pkt[IP].dst
        vendor = self.get_vendor(pkt[Ether].src) if pkt.haslayer(Ether) else "Unknown"
        narrative = [f"[bold white]TRAFFIC:[/bold white] {src} ([cyan]{vendor}[/cyan]) → {dst}"]
        if pkt.haslayer(TCP):
            narrative.append("[bold yellow]TCP:[/bold yellow] Active Session.")
            if pkt[TCP].dport == 80: narrative.append("[bold red]WARNING:[/bold red] Unsecured HTTP Detected!")
        return "\n".join(narrative)

    def packet_callback(self, pkt):
        self.detect_spoof(pkt)
        if not (pkt.haslayer(IP) or pkt.haslayer(ARP)): return
        proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "ARP" if pkt.haslayer(ARP) else "OTHER"
        with self.lock: flt = self.active_filter.upper()
        if flt and (flt not in proto and flt not in str(pkt.summary())): return
        analysis, carved, ts, src = self.translate_packet(pkt), self.carve_intel(pkt), time.strftime("%H:%M:%S"), (pkt.src if hasattr(pkt, 'src') else "??")
        with self.lock:
            self.stats[proto] = self.stats.get(proto, 0) + 1
            self.last_analysis, self.carved_strings = analysis, carved
            self.packet_history.append([ts, src, proto])

    def _stdin_reader(self):
        while self.running:
            try:
                line = sys.stdin.readline()
                if line: self._cmd_queue.append(line.strip())
            except: break

    def _process_commands(self):
        while self._cmd_queue:
            cmd = self._cmd_queue.popleft()
            if cmd.lower() in ("exit", "quit"): self.running = False
            elif cmd.lower() == "save":
                try:
                    with self.lock: a, c = self.last_analysis, self.carved_strings
                    with open("sentinel_log.txt", "a") as f: f.write(f"\n[{time.ctime()}] {a}\nDATA: {c}\n")
                except OSError as e:
                    with self.lock: self.alerts.appendleft(f"[yellow]Save Error: {e}[/yellow]")
            else:
                with self.lock: self.active_filter = cmd; self.packet_history.clear()

    def make_layout(self):
        layout = Layout()
        layout.split_column(Layout(name="header", size=3), Layout(name="body", ratio=1), Layout(name="footer", size=5))
        layout["body"].split_row(Layout(name="stream", ratio=1), Layout(name="intel", ratio=2), Layout(name="alerts", ratio=1))
        return layout

    def run(self):
        if os.getuid() != 0:
            console.print("[bold red]Error: Sudo required.[/bold red]"); return
        layout = self.make_layout()
        threading.Thread(target=sniff, kwargs={"prn": self.packet_callback, "store": 0}, daemon=True).start()
        threading.Thread(target=self._stdin_reader, daemon=True).start()
        with Live(layout, screen=True, refresh_per_second=4):
            while self.running:
                self._process_commands()
                layout["header"].update(Panel("[bold cyan]PriVi-WireExplorer v6.0[/bold cyan] | [white]Sentinel MITM Detection Engine[/white]", style="blue"))
                with self.lock:
                    h, a_s, c_s, al_s, st_s, f_s = list(self.packet_history), self.last_analysis, self.carved_strings, list(self.alerts), dict(self.stats), self.active_filter
                st_table = Table(expand=True, box=None)
                st_table.add_column("TIME"); st_table.add_column("SOURCE"); st_table.add_column("PROTO")
                for row in h: st_table.add_row(*row)
                layout["stream"].update(Panel(st_table, title="Live Stream", border_style="cyan"))
                layout["intel"].update(Panel(f"{a_s}\n\n[bold yellow]DPI STRING CARVER:[/bold yellow]\n{c_s}", title="Forensic Interpretation", border_style="magenta"))
                layout["alerts"].update(Panel("\n".join(al_s[:12]), title="🚨 SECURITY ALERTS", border_style="red"))
                footer_txt = f"FILTER: {f_s or 'NONE'} | TCP: {st_s.get('TCP', 0)} | ARP: {st_s.get('ARP', 0)} | Type 'save' for forensics."
                layout["footer"].update(Panel(footer_txt, title="Sentinel Command Center", border_style="white"))
                time.sleep(0.1)

if __name__ == "__main__":
    try:
        explorer = WireExplorerSentinel(); explorer.run()
    except KeyboardInterrupt: sys.exit(0)
                  
