# ReconBLADE ⚔️🧠

**An AI recon _orchestrator_ — not another scanner.**

Run `/recon <target>` in Claude Code and ReconBLADE doesn't just dump a scan: the AI
agent **decides what to probe next from what it finds**, **correlates** results across
tools, and hands you a **prioritized, reasoned report** — the judgment a human analyst
normally does by hand.

> ⚠️ **Authorized targets only** — your own systems, labs (`scanme.nmap.org`), or
> in-scope engagements. Unauthorized scanning is illegal.

---

## 🤔 Why this is different

Tools like **nmap, subfinder, nuclei** are powerful — but they are *dumb muscle*: they
scan and dump raw output. A human still has to interpret it, decide the next step,
correlate findings, and work out the attack path. **That reasoning is the slow,
expert-dependent part — and no scanner does it.**

ReconBLADE is the **brain**, not another scanner:

| | Traditional scanner | ReconBLADE |
|---|---|---|
| What it does | Runs a fixed scan, dumps output | Decides the next action from findings |
| Workflow | Static pipeline | **Adaptive** loop (findings drive it) |
| Output | Raw data | **Correlated, prioritized** risks + reasoning |
| Built for | A human to read | **An AI agent to drive** |

The engine exposes recon as composable **capabilities** (`ports`, `web`, `subs`, `cve`),
each emitting JSON. It wraps best-in-class tools (nmap / subfinder / searchsploit) when
installed and falls back to built-ins otherwise. The **orchestration + reasoning** is
done by the agent via the `/recon` command.

## Use (Claude Code plugin)
```
/recon scanme.nmap.org
```

## Use the capabilities standalone
```
python3 scripts/recon.py ports scanme.nmap.org
python3 scripts/recon.py web   scanme.nmap.org
python3 scripts/recon.py subs  example.com
python3 scripts/recon.py cve   "OpenSSH 6.6.1"
```

## Roadmap
- [x] Capability engine (ports / web / subs / cve) with tool-wrapping + fallbacks
- [x] Adaptive `/recon` orchestration command
- [ ] More capabilities (nuclei templates, tech fingerprint, screenshots)
- [ ] **MCP server** — so *any* AI agent (not just Claude Code) can call ReconBLADE
- [ ] Memory of past recon to inform the next run

---
*Built by Ayan Abbas.*
