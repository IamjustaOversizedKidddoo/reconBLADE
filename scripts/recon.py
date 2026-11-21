#!/usr/bin/env python3
"""
ReconBLADE — an AI recon ORCHESTRATOR.

This is NOT another scanner. It exposes recon as a set of normalized *capabilities*
(ports, web, subs, cve), each returning JSON, so an AI agent can chain them
adaptively and reason over the results. Each capability wraps a best-in-class tool
when it's installed (nmap, subfinder, searchsploit) and falls back to a built-in
implementation otherwise — so it always runs, but gets sharper with real tools.

Usage:
    python3 recon.py ports <target>
    python3 recon.py web   <target>
    python3 recon.py subs  <domain>
    python3 recon.py cve   "<product version>"
"""

import argparse
import json
import shutil
import subprocess
import socket
import re
import random
import string
import urllib.request
from concurrent.futures import ThreadPoolExecutor


def have(tool):
    """Is a command-line tool installed?"""
    return shutil.which(tool) is not None


def run(cmd, timeout=120):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout
    except Exception:
        return ""


# ---------------- PORTS ----------------
def ports(target):
    """Open ports + service/version. Uses nmap if present, else a built-in scanner."""
    if have("nmap"):
        out = run(["nmap", "-sV", "-T4", "--top-ports", "100", "-oG", "-", target])
        found = []
        for line in out.splitlines():
            if "Ports:" in line:
                for m in re.findall(r"(\d+)/open/tcp//([^/]*)//([^/]*)/", line):
                    found.append({"port": int(m[0]), "service": m[1], "version": m[2]})
        return {"action": "ports", "tool": "nmap", "target": target, "open_ports": found}

    # fallback: built-in threaded scanner + banner grab
    common = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
              443, 445, 3306, 3389, 8080, 8443]
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {"action": "ports", "error": f"cannot resolve {target}"}

    open_ = []

    def scan(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        if s.connect_ex((ip, p)) == 0:
            banner = ""
            try:
                s.settimeout(1.5)
                banner = s.recv(1024).decode(errors="ignore").strip()
            except Exception:
                pass
            open_.append({"port": p, "service": "unknown", "version": banner})
        s.close()

    with ThreadPoolExecutor(max_workers=100) as pool:
        pool.map(scan, common)
    return {"action": "ports", "tool": "builtin", "target": target, "ip": ip,
            "open_ports": sorted(open_, key=lambda x: x["port"])}


# ---------------- WEB ----------------
def web(target):
    """Web server + security headers (missing ones are a finding)."""
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{target}",
                                         headers={"User-Agent": "ReconBLADE"})
            r = urllib.request.urlopen(req, timeout=6)
            h = dict(r.headers)
            return {
                "action": "web", "target": target, "url": f"{scheme}://{target}",
                "status": r.status,
                "server": h.get("Server", ""),
                "powered_by": h.get("X-Powered-By", ""),
                "security_headers": {k: h.get(k, "MISSING") for k in
                    ["Content-Security-Policy", "X-Frame-Options",
                     "Strict-Transport-Security"]},
            }
        except Exception:
            continue
    return {"action": "web", "target": target, "error": "no web service reachable"}


# ---------------- SUBS ----------------
def subs(target):
    """Subdomains. Uses subfinder if present, else a built-in list with wildcard filtering."""
    if have("subfinder"):
        out = run(["subfinder", "-silent", "-d", target])
        return {"action": "subs", "tool": "subfinder", "target": target,
                "subdomains": [s for s in out.splitlines() if s.strip()]}

    def res(host):
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None

    rand = "".join(random.choices(string.ascii_lowercase, k=12))
    wildcard = res(f"{rand}.{target}")          # wildcard-DNS baseline
    words = ["www", "mail", "ftp", "dev", "test", "admin", "api",
             "vpn", "staging", "portal", "blog", "shop"]
    found = []
    for w in words:
        ip = res(f"{w}.{target}")
        if ip and ip != wildcard:               # skip wildcard false positives
            found.append({"host": f"{w}.{target}", "ip": ip})
    return {"action": "subs", "tool": "builtin", "target": target,
            "wildcard_dns": bool(wildcard), "subdomains": found}


# ---------------- CVE ----------------
def cve(product):
    """Known exploits for a product/version. Uses searchsploit if present."""
    if have("searchsploit"):
        out = run(["searchsploit", "--json", product])
        try:
            data = json.loads(out)
        except Exception:
            data = {}
        hits = [{"title": e.get("Title"), "path": e.get("Path")}
                for e in data.get("RESULTS_EXPLOIT", [])][:10]
        return {"action": "cve", "tool": "searchsploit", "query": product, "results": hits}
    return {"action": "cve", "query": product,
            "note": "searchsploit not installed — check NVD / Exploit-DB for this version"}


def main():
    ap = argparse.ArgumentParser(
        description="ReconBLADE — AI recon orchestrator (JSON capabilities)")
    sub = ap.add_subparsers(dest="action", required=True)
    for a in ("ports", "web", "subs"):
        sp = sub.add_parser(a)
        sp.add_argument("target", help="AUTHORIZED target only")
    cp = sub.add_parser("cve")
    cp.add_argument("product", help='e.g. "OpenSSH 6.6.1"')
    args = ap.parse_args()

    fn = {"ports": ports, "web": web, "subs": subs, "cve": cve}[args.action]
    arg = args.product if args.action == "cve" else args.target
    print(json.dumps(fn(arg), indent=2))


if __name__ == "__main__":
    main()
