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
import errno
import json
import sys
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
    refused = {errno.ECONNREFUSED, 10061}   # 10061 = WSAECONNREFUSED on Windows

    def scan(p):
        # A refused connection is a definite "closed"; a timeout may just be a slow or
        # lossy network, so retry those instead of silently missing an open port.
        for _ in range(3):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.5)
                try:
                    rc = s.connect_ex((ip, p))
                except OSError:
                    rc = -1
                if rc == 0:
                    banner = ""
                    try:
                        s.settimeout(1.5)
                        banner = s.recv(1024).decode(errors="ignore").strip()
                    except Exception:
                        pass
                    open_.append({"port": p, "service": "unknown", "version": banner})
                    return
                if rc in refused:
                    return

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


# --- built-in knowledge base (so the standalone tool can reason, not just dump) ---
HEADER_KB = {
    "Content-Security-Policy": ("MEDIUM", "Weak XSS defense — if an XSS bug exists, the browser won't block injected scripts.",
                                "Add a Content-Security-Policy tuned to your site's resources (strict policies can break external scripts/fonts, so tune carefully)."),
    "X-Frame-Options": ("MEDIUM", "Clickjacking — your page can be embedded in an attacker's hidden iframe to trick users into clicks.",
                        "Add header 'X-Frame-Options: DENY' (or SAMEORIGIN)."),
    "Strict-Transport-Security": ("MEDIUM", "No HTTPS enforcement — users can be downgraded to HTTP and MITM'd.",
                                  "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."),
}
PORT_KB = {
    21: ("FTP", "HIGH", "Often cleartext and allows anonymous login.", "Check anonymous access and weak credentials; disable if unused."),
    22: ("SSH", "INFO", "Remote login service.", "Check the version for CVEs and ensure key-based auth, no root login."),
    23: ("Telnet", "HIGH", "Cleartext remote login — credentials sent in plaintext.", "Disable Telnet; use SSH instead."),
    25: ("SMTP", "INFO", "Mail service.", "Check for open relay and version CVEs."),
    80: ("HTTP", "INFO", "Web server (cleartext).", "Test for web vulns (SQLi/XSS/IDOR); redirect to HTTPS."),
    110: ("POP3", "INFO", "Mail retrieval.", "Prefer encrypted (POP3S)."),
    139: ("NetBIOS", "MEDIUM", "Legacy Windows networking.", "Restrict from the internet."),
    143: ("IMAP", "INFO", "Mail retrieval.", "Prefer encrypted (IMAPS)."),
    443: ("HTTPS", "INFO", "Web server over TLS.", "Test web vulns and TLS config (weak ciphers, cert)."),
    445: ("SMB", "HIGH", "File sharing — historically high-risk (EternalBlue etc.).", "Never expose to the internet; patch and restrict."),
    3306: ("MySQL", "HIGH", "Database exposed.", "Databases should not face the internet; firewall it, strong auth."),
    3389: ("RDP", "HIGH", "Remote Desktop exposed.", "Brute-force/CVE risk; restrict by VPN/IP, enable NLA + MFA."),
    5432: ("PostgreSQL", "HIGH", "Database exposed.", "Firewall it off the internet; strong auth."),
    8080: ("HTTP-alt", "INFO", "Alternate web server.", "Test for web vulns; often admin/dev panels."),
    8443: ("HTTPS-alt", "INFO", "Alternate TLS web server.", "Test web vulns and TLS config."),
}
SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}


def run_all(target):
    """Zero-config full recon + a reasoned report. No AI needed — rule-based triage."""
    WEB_PORTS = {80, 443, 8080, 8443}
    print(f"\n╔═ ReconBLADE ═ {target} ═══════════════════════")

    p = ports(target)
    if p.get("error"):
        print(f"║ [!] {p['error']}\n╚═══════════════════════════════════")
        return
    opens = p.get("open_ports", [])
    print(f"║ IP: {p.get('ip', '?')}   ·   tool: {p.get('tool')}   ·   open ports: {len(opens)}")
    print("║")
    for s in opens:
        print(f"║  {s['port']:>5}/tcp  {s.get('service',''):<8} {s.get('version','')}".rstrip())

    findings = []   # (severity, title, risk, fix)

    # web headers
    w = None
    if any(s["port"] in WEB_PORTS for s in opens):
        w = web(target)
        if not w.get("error"):
            print("║")
            print(f"║  WEB  {w['url']} [{w['status']}]  Server: {w.get('server','-')}")
            for h, v in w.get("security_headers", {}).items():
                if v == "MISSING" and h in HEADER_KB:
                    sev, risk, fix = HEADER_KB[h]
                    findings.append((sev, f"Missing header: {h}", risk, fix))

    # port-based triage
    for s in opens:
        info = PORT_KB.get(s["port"])
        if info:
            name, sev, risk, fix = info
            findings.append((sev, f"Port {s['port']} open ({name})", risk, fix))

    # cve lookup per versioned service
    cve_hits = []
    for s in opens:
        ver = s.get("version", "")
        if ver and s.get("service") not in ("", "unknown"):
            query = " ".join(ver.split()[:2])
            hits = cve(query).get("results", [])
            if hits:
                cve_hits.append((query, hits[:3]))
                findings.append(("HIGH", f"Known exploits for {query}",
                                 f"{len(hits)} public exploit(s) match this version.",
                                 "Patch/upgrade; verify each exploit's applicability in a lab."))

    # --- ANALYSIS (chat-style reasoning) ---
    print("╠═ ANALYSIS " + "═" * 36)
    if not findings:
        print("║  No notable issues from this quick pass.")
    else:
        findings.sort(key=lambda f: SEV_ORDER.get(f[0], 3))
        for sev, title, risk, fix in findings:
            print(f"║  [{sev}] {title}")
            print(f"║     risk: {risk}")
            print(f"║     fix:  {fix}")
            print("║")

    if cve_hits:
        print("╠═ KNOWN EXPLOITS " + "═" * 31)
        for q, hits in cve_hits:
            print(f"║  {q}:")
            for h in hits:
                print(f"║     - {h['title']}")
        print("║")

    # --- NEXT STEPS ---
    print("╠═ NEXT STEPS " + "═" * 35)
    steps = []
    highs = [f for f in findings if f[0] == "HIGH"]
    if highs:
        steps.append("Prioritize the HIGH items above first.")
    if w and not w.get("error"):
        steps.append("Run a web vuln scan (OWASP ZAP / nuclei) on the web service.")
    steps.append("Confirm each finding manually before reporting — no false positives.")
    for st in steps:
        print(f"║  - {st}")
    print("╚" + "═" * 47)
    print("Note: standalone triage is rule-based. For deeper, adaptive reasoning + attack paths,")
    print("run ReconBLADE as a Claude Code plugin (see README).")


def main():
    # Windows consoles/pipes default to cp1252, which can't print the report's box characters.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(
        description="ReconBLADE — AI recon orchestrator. "
                    "Run `all <target>` for a full report, or a single capability.")
    sub = ap.add_subparsers(dest="action", required=True)
    ap_all = sub.add_parser("all", help="full recon + readable report (start here)")
    ap_all.add_argument("target", help="AUTHORIZED target only")
    for a in ("ports", "web", "subs"):
        sp = sub.add_parser(a)
        sp.add_argument("target", help="AUTHORIZED target only")
    cp = sub.add_parser("cve")
    cp.add_argument("product", help='e.g. "OpenSSH 6.6.1"')
    args = ap.parse_args()

    if args.action == "all":
        run_all(args.target)
        return

    fn = {"ports": ports, "web": web, "subs": subs, "cve": cve}[args.action]
    arg = args.product if args.action == "cve" else args.target
    print(json.dumps(fn(arg), indent=2))


if __name__ == "__main__":
    main()
