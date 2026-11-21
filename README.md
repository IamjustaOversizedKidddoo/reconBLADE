<!-- ░▒▓█ RECONBLADE █▓▒░ -->
<div align="center">

![banner](https://capsule-render.vercel.app/api?type=waving&height=180&color=0:0ff5d0,45:b000ff,100:ff005c&text=RECONBLADE&fontColor=0d0014&fontSize=58&fontAlignY=36&desc=jack%20in%20·%20scan%20·%20reason&descSize=18&descAlignY=60&animation=fadeIn)

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗ ██╗      █████╗ ██████╗ ███████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██║     ██╔══██╗██╔══██╗██╔════╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██████╔╝██║     ███████║██║  ██║█████╗
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══██╗██║     ██╔══██║██║  ██║██╔══╝
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██████╔╝███████╗██║  ██║██████╔╝███████╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝
```

### `// an AI recon ORCHESTRATOR — not another scanner`

![status](https://img.shields.io/badge/STATUS-ONLINE-0ff5d0?style=for-the-badge&labelColor=0d0014)
![type](https://img.shields.io/badge/TYPE-AI_ORCHESTRATOR-b000ff?style=for-the-badge&labelColor=0d0014)
![interface](https://img.shields.io/badge/INTERFACE-CLAUDE_CODE-ff005c?style=for-the-badge&labelColor=0d0014)
![scope](https://img.shields.io/badge/SCOPE-AUTHORIZED_ONLY-ffb000?style=for-the-badge&labelColor=0d0014)

</div>

---

> ```
> > jack into the target. the scanners are the muscle.
> > RECONBLADE is the brain that decides, chains, and correlates.
> ```

Run `/recon <target>` in Claude Code and ReconBLADE doesn't just dump a scan — the AI
agent **decides what to probe next from what it finds**, **correlates** results across
tools, and returns a **prioritized, reasoned report**: the judgment a human analyst
normally does by hand.

> ⚠️ **`AUTHORIZED TARGETS ONLY`** — your own systems, labs (`scanme.nmap.org`), or
> in-scope engagements. Unauthorized scanning is illegal.

---

## `> QUICKSTART`

**Option 1 — just run it (no setup, no AI):**
```bash
git clone https://github.com/IamjustaOversizedKidddoo/reconBLADE.git
cd reconBLADE
python3 scripts/recon.py all scanme.nmap.org
```
That's it — one command gives a full report (ports, web headers, known exploits).
Uses `nmap`/`searchsploit` if installed, falls back to pure Python otherwise.

**Option 2 — AI-driven mode (Claude Code):**
```
/plugin marketplace add IamjustaOversizedKidddoo/reconBLADE
/plugin install reconblade
/recon scanme.nmap.org
```
Now Claude drives the recon adaptively and writes a prioritized, reasoned report.

---

## `// WHY THIS IS DIFFERENT`

Tools like **nmap · subfinder · nuclei** are powerful — but they are *dumb muscle*: they
scan and dump raw output. A human still has to interpret it, decide the next move,
correlate findings, and work out the attack path. **That reasoning is the slow,
expert-dependent part — and no scanner does it.**

ReconBLADE is the **brain**:

| ░ | `TRADITIONAL SCANNER` | `RECONBLADE` |
|---|---|---|
| **does** | runs a fixed scan, dumps output | decides the next action from findings |
| **flow** | static pipeline | **adaptive** loop (findings drive it) |
| **output** | raw data | **correlated · prioritized** risks + reasoning |
| **built for** | a human to read | **an AI agent to drive** |

The engine exposes recon as composable **capabilities** that emit JSON. It wraps
best-in-class tools (`nmap` / `subfinder` / `searchsploit`) when installed and falls back
to built-ins otherwise. The **orchestration + reasoning** is done by the agent.

---

## `> SYSTEM.CAPABILITIES`

```bash
python3 scripts/recon.py ports <target>     # open ports + service/version
python3 scripts/recon.py web   <target>     # web server + missing security headers
python3 scripts/recon.py subs  <domain>     # subdomains (wildcard-filtered)
python3 scripts/recon.py cve   "<product>"  # known exploits for a version
```

## `> RUN.AS_AGENT`

```bash
# in Claude Code:
/recon scanme.nmap.org
#   → ports → sees OpenSSH 6.6.1 → cve → correlates → prioritized report
```

---

## `// THE ADAPTIVE LOOP`

```
   ┌─────────────┐
   │   TARGET    │
   └──────┬──────┘
          ▼
   [ run ports ] ──► read services
          │
          ├─ web port?      → run web   → flag missing headers
          ├─ has version?   → run cve   → match known exploits
          └─ is a domain?   → run subs  → recurse on interesting hits
          │
          ▼
   [ CORRELATE ] ──► old version + known CVE + exposed port = HIGH
          │
          ▼
   [ PRIORITIZED REPORT + NEXT STEPS ]
```

---

## `> ROADMAP.exe`

- [x] `capability engine` — ports / web / subs / cve, tool-wrapping + fallbacks
- [x] `adaptive /recon` — the orchestration brain
- [ ] `more capabilities` — nuclei templates, tech fingerprint, screenshots
- [ ] `MCP server` — so **any** AI agent (not just Claude Code) can drive ReconBLADE
- [ ] `recon memory` — past runs inform the next

---

<div align="center">

```
[ built in the agent age — by Ayan Abbas ]
```

![footer](https://capsule-render.vercel.app/api?type=waving&section=footer&height=120&color=0:ff005c,50:b000ff,100:0ff5d0)

</div>
