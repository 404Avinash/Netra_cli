# NETRA_CLI

```text
  _   _ _____ _____ ____      _       ____ _     ___ 
 | \ | | ____|_   _|  _ \    / \     / ___| |   |_ _|
 |  \| |  _|   | | | |_) |  / _ \   | |   | |    | | 
 | |\  | |___  | | |  _ <  / ___ \  | |___| |___ | | 
 |_| \_|_____| |_| |_| \_\/_/   \_\  \____|_____|___|
      Network & Endpoint Threat & Resilience Assessor
```

[![NETRA_CLI CI](https://github.com/404Avinash/Netra_cli/actions/workflows/ci.yml/badge.svg)](https://github.com/404Avinash/Netra_cli/actions/workflows/ci.yml)
![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)
![Dependencies](https://img.shields.io/badge/dependencies-0%20external-brightgreen)
![Tests](https://img.shields.io/badge/tests-77%20passed-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

**NETRA_CLI** is a lightweight, zero-dependency **Local Laptop Network & Threat Guardian** and **Remote Perimeter Security Auditor**. Inspired by **Trivy** (high-contrast vulnerability severity grading) and **btop** (live interactive terminal monitoring).

Built entirely with Python's standard library—**no `pip install` required to run**.

---

## What is NETRA_CLI?

NETRA operates with dual capability depending on how you invoke it:

1. **Local Laptop Network & Threat Guardian (Default: `netra`)**  
   Audits your local machine in sub-seconds. Detects publicly bound listening ports (`0.0.0.0` or `*` exposing databases, debuggers, or dev servers), samples real-time interface bandwidth via `/proc/net/dev`, tracks active outbound process connections, scans for malicious C2/cryptominer ports, and audits SSH key and workspace `.env` secret hygiene.
2. **Remote Perimeter Security Auditor (`netra <domain>`)**  
   Inspects external web endpoints for plaintext HTTP downgrade vulnerabilities, TLS certificate expiration dates, and RFC-compliant HTTP security headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`).
3. **btop-Style Live Interactive Radar (`netra top`)**  
   Full-screen live curses terminal dashboard displaying interface bandwidth meters, active socket exposure matrix, process telemetry, and hotkey actions (`[r]` refresh, `[s]` lock baseline, `[q]` exit).
4. **Governed Baseline Drift & Swytchcode Issue Dispatch (`netra notify`)**  
   Lock security benchmarks into versioned snapshots (`.netra/baselines/`), automatically detect regressions or unexpected exposed ports, and dispatch GitHub issues via the Swytchcode Execution Authority Kernel without hardcoding API secrets.

---

## Visual Highlights

### 1. Local Laptop Threat Audit (`netra` / `netra check`)
Running bare `netra` instantly audits your local laptop's network posture, open listeners, and workspace hygiene:

```text
  _   _ _____ _____ ____      _       ____ _     ___ 
 | \ | | ____|_   _|  _ \    / \     / ___| |   |_ _|
 |  \| |  _|   | | | |_) |  / _ \   | |   | |    | | 
 | |\  | |___  | | |  _ <  / ___ \  | |___| |___ | | 
 |_| \_|_____| |_| |_| \_\/_/   \_\  \____|_____|___|
      Network & Endpoint Threat & Resilience Assessor

 Target: Local Host (developer-laptop | 192.168.1.105)  |  Interface: wlp4s0 (▼ 3.45 GB RX / ▲ 2.24 GB TX)
 Security Score: [██████░░░░░░░░░░░░░░] 30/100  (GRADE: F)

┌─────────────────────────────┬────────────────┬────────────┬────────────────────────────────────────────────┐
│ CATEGORY / CHECK            │ STATUS         │ SEVERITY   │ DETAILS / PROCESS                              │
├─────────────────────────────┼────────────────┼────────────┼────────────────────────────────────────────────┤
│ Exposed Port *:3000         │ [ EXPOSED  ]   │   MEDIUM   │ Dev Server (Node/React/Rails) bound to 0.0.0.0 │
│ Exposed Port *:4000         │ [ EXPOSED  ]   │   MEDIUM   │ Dev Server bound to all interfaces             │
│ Exposed Port 0.0.0.0:5678   │ [ EXPOSED  ]   │    HIGH    │ Debugger bound to all interfaces               │
│ Exposed Port 0.0.0.0:6379   │ [ EXPOSED  ]   │    HIGH    │ Redis Database bound to all interfaces         │
│ Localhost Ports (12 active) │ [   SAFE   ]   │    INFO    │ 127.0.0.1 (:53 DNS Resolv, :631 CUPS, ...)     │
│ Outbound Conns (11)         │ [  NORMAL  ]   │    INFO    │ All 11 ESTABLISHED conns over TLS (chrome, ...) │
│ Malicious / Backdoor Radar  │ [  CLEAN   ]   │    INFO    │ 0 C2/miner ports, 0 SYN floods, 0 plaintext    │
│ Workspace & SSH Hygiene     │ [   PASS   ]   │    INFO    │ SSH keys 0600, no untracked .env leaks         │
└─────────────────────────────┴────────────────┴────────────┴────────────────────────────────────────────────┘
 Summary: 4 Passed, 0 Warnings, 4 Exposed / Risks
```

### 2. Live Interactive Laptop Radar (`netra top`)
Real-time, interactive curses dashboard with bandwidth rates, socket tables, and instant hotkey baseline locking:

```text
┌─────────────────────────── NETRA LIVE MONITOR  ──  [Target: localhost] ───────────────────────────┐
│ Security Score: [██████░░░░░░░░░░░░░░] 30/100   GRADE: F      Host: laptop (192.168.1.105)  Audit: 18:30:15 │
├─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ NETWORK INTERFACE & BANDWIDTH (wlp4s0)                                                                      │
│ Rate: ▼ 42.5 KB/s RX  |  ▲ 18.2 KB/s TX       Total: ▼ 3.45 GB RX  |  ▲ 2.24 GB TX                          │
├─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ LISTENING PORTS & EXPOSURE RADAR                                                                            │
│   [ EXPOSED  ]  0.0.0.0:6379 (TCP)  Redis Database (redis-server:1204)                                      │
│   [ EXPOSED  ]  0.0.0.0:5678 (TCP)  Debugger / Service (python3:4812)                                       │
│   [ EXPOSED  ]  *:3000 (TCP)        Dev Server (Node/React/Rails) (node:9821)                               │
│   [   SAFE   ]  127.0.0.1:5432 (TCP) PostgreSQL Database (postgres:892)                                     │
├─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ ACTIVE ESTABLISHED CONNECTIONS (TOP 5)                                                                      │
│   chrome (pid 3140)    192.168.1.105:48920 -> 142.250.190.46:443 (HTTPS)                                   │
│   code (pid 4102)      192.168.1.105:51204 -> 20.201.28.151:443 (HTTPS)                                    │
├─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ BASELINE DRIFT CONTRACT                                                                                     │
│     ✔ BASELINE MATCH: Healthy contract (saved 2026-11-03T18:22:54)                                          │
├─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ HOTKEYS: [r] Refresh Now   [s] Save Baseline Snapshot   [q] Quit                                            │
│ Live monitoring active (interval: 2.0s) | Press 'q' to quit                                                 │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3. Remote Perimeter Security Audit (`netra github.com`)
Target any external domain or web service for instant perimeter inspection:

```text
  _   _ _____ _____ ____      _       ____ _     ___ 
 | \ | | ____|_   _|  _ \    / \     / ___| |   |_ _|
 |  \| |  _|   | | | |_) |  / _ \   | |   | |    | | 
 | |\  | |___  | | |  _ <  / ___ \  | |___| |___ | | 
 |_| \_|_____| |_| |_| \_\/_/   \_\  \____|_____|___|
      Network & Endpoint Threat & Resilience Assessor

 Target: https://github.com  |  Timestamp: 2026-11-03T18:23:07Z
 Security Score: [████████████████████] 100/100  (GRADE: A+)

┌─────────────────────────────┬────────────────┬────────────┬────────────────────────────────────────────────┐
│ CONTROL                     │ STATUS         │ SEVERITY   │ DETAILS / VALUE                                │
├─────────────────────────────┼────────────────┼────────────┼────────────────────────────────────────────────┤
│ HTTP -> HTTPS Redirect      │ [   PASS   ]   │    INFO    │ HTTP 301 redirects to HTTPS: https://github... │
│ TLS Certificate Validity    │ [   PASS   ]   │    INFO    │ Valid certificate (85 days left, expires 20... │
│ Strict-Transport-Security   │ [ PRESENT  ]   │    INFO    │ max-age=31536000; includeSubdomains; preload   │
│ Content-Security-Policy     │ [ PRESENT  ]   │    INFO    │ default-src 'none'; base-uri 'self'; child-... │
│ X-Content-Type-Options      │ [ PRESENT  ]   │    INFO    │ nosniff                                        │
│ Referrer-Policy             │ [ PRESENT  ]   │    INFO    │ origin-when-cross-origin, strict-origin-whe... │
└─────────────────────────────┴────────────────┴────────────┴────────────────────────────────────────────────┘
 Summary: 6 Passed, 0 Inconclusive, 0 Failed
```

---

## Tooling Comparison Matrix

| Capability | Wireshark / Netstat | Uptime Monitors (Pingdom) | Host Security Scanners (Trivy/Nessus) | **NETRA_CLI** |
|---|:---:|:---:|:---:|:---:|
| **Zero External Dependencies** | ❌ Requires drivers/root | N/A (SaaS only) | ❌ Heavy binary / containers | ✅ **Pure Python stdlib (0 deps)** |
| **Default Laptop Network Audit** | Raw packet dump | ❌ Remote only | ⚠️ Heavy agent or Docker required | ✅ **Instant sub-second audit (`netra`)** |
| **Exposed Dev Server / DB Alerts** | Manual inspection | ❌ Not covered | ⚠️ Complex configuration | ✅ **Automatic `[ EXPOSED ]` flagging** |
| **Workspace & SSH Secret Hygiene** | ❌ No | ❌ No | ⚠️ Clunky setup | ✅ **Checks SSH key permissions & `.env`** |
| **Live Interactive Terminal TUI** | ❌ No TUI | ❌ No TUI | ❌ No TUI | ✅ **btop-style dashboard (`netra top`)** |
| **External Perimeter Auditing** | ❌ No | ⚠️ Basic ping | ⚠️ Buried in 50-page PDF | ✅ **Direct RFC header & TLS validation** |
| **Alerting Pipeline Safety** | ❌ No | Webhook spam | Email alert flood | ✅ **Swytchcode Execution Authority** |

---

## Operational Workflow

### Security Baseline Lifecycle

NETRA treats both laptop network hygiene and external web posture as version-controlled baselines:

```text
*   d4e7f9a (HEAD -> main) Dispatched Issue via Swytchcode Kernel
|\  
| * c8b2a10 (drift-analysis) netra notify --repo OWNER/REPO --confirm (github.issue.create)
| * a7f3c21 netra compare (New exposed listener or security regression detected)
| * 5e2d19b Started unexpected service / changed configuration
|/  
* 2b8f410 netra baseline save --yes (locked baseline snapshot)
* 1a9c042 netra (initial laptop threat & network audit)
```

### End-to-End Pipeline

```text
   ┌──────────────────────────────────────────────┐
   │ 1. Invocation (Laptop or Remote Target)      │
   │    netra                 netra github.com    │
   └──────────────────────┬───────────────────────┘
                          │
                          ▼
   ┌──────────────────────────────────────────────┐
   │ 2. Audit: netra check / netra top            │ ──▶ Trivy table & btop live dashboard
   └──────────────────────┬───────────────────────┘
                          │
                          ▼
   ┌──────────────────────────────────────────────┐
   │ 3. Lock: netra baseline save                 │ ──▶ Snapshot in .netra/baselines/
   └──────────────────────┬───────────────────────┘
                          │
                          ▼
   ┌──────────────────────────────────────────────┐
   │ [Port opened / Secrets changed / Deploy]     │ ──▶ Operational state changes
   └──────────────────────┬───────────────────────┘
                          │
                          ▼
   ┌──────────────────────────────────────────────┐
   │ 4. Verify: netra compare                     │
   └──────────────────────┬───────────────────────┘
                          ├─────────────────────────────────────────────┐
                [No Drift Detected]                             [Regressions Found]
                          │                                             │
                          ▼                                             ▼
   ┌──────────────────────────────────────────────┐         ┌───────────────────────────────────┐
   │ ✔ Exit 0 (Contract Intact)                   │         │ ▲ Exit 1: netra notify            │
   └──────────────────────────────────────────────┘         └─────────────────┬─────────────────┘
                                                                              │
                                                                              ▼
                                                            ┌───────────────────────────────────┐
                                                            │ 5. Safe Markdown Preview Mode     │ (Zero external calls)
                                                            └─────────────────┬─────────────────┘
                                                                              │
                                                                              ▼
                                                            ┌───────────────────────────────────┐
                                                            │ 6. Swytchcode Execution Kernel    │ (--confirm passed)
                                                            │    (github.issue.create)          │
                                                            └─────────────────┬─────────────────┘
                                                                              │
                                                                              ▼
                                                            ┌───────────────────────────────────┐
                                                            │ 🚀 Live GitHub Issue Created      │ (No hardcoded secrets)
                                                            └───────────────────────────────────┘
```

---

## Architecture: Why Swytchcode?

Traditional alerting scripts require generating personal access tokens (PATs), hardcoding credentials into environment files, and writing custom retry logic.

NETRA uses **Swytchcode** as an *Execution Authority Kernel*:

```text
Developer / CI               NETRA_CLI (netra.py)          Swytchcode Kernel (swy exec)        GitHub REST API
     │                               │                                     │                          │
     │ 1. netra notify --confirm     │                                     │                          │
     ├──────────────────────────────▶│                                     │                          │
     │                               │ 2. Pipe JSON payload via stdin      │                          │
     │                               ├────────────────────────────────────▶│                          │
     │                               │                                     │ 3. Validate Wrekenfile   │
     │                               │                                     │    & inject OAuth token  │
     │                               │                                     ├──────────┐               │
     │                               │                                     │          │               │
     │                               │                                     │◀─────────┘               │
     │                               │                                     │ 4. POST /repos/issues    │
     │                               │                                     ├─────────────────────────▶│
     │                               │                                     │ 5. 201 Created (Issue URL│
     │                               │                                     │◀─────────────────────────┤
     │                               │ 6. Structured JSON Result           │                          │
     │                               │◀────────────────────────────────────┤                          │
     │ 7. ✔ Live Issue #1 Published  │                                     │                          │
     │◀──────────────────────────────┤                                     │                          │
```

### The 5 Architectural Advantages:

1. **Zero Secret Sprawl:** `netra.py` contains no API keys or tokens. Swytchcode manages OAuth credentials out-of-band and injects them in flight.
2. **Contract-Governed APIs (Wrekenfiles):** The request schema is validated against declarative Wrekenfile contracts before touching the network.
3. **Principle of Least Privilege:** Only explicitly whitelisted operations in `.swytchcode/tooling.json` (`github.issue.create`) can be triggered.
4. **Built-in Resilience:** Automatic 3-attempt exponential backoff retries on rate limits (429) or transient errors (503).
5. **Local Auditability:** Every outbound dispatch is logged locally (`swytchcode audit stats`).

---

## Installation & Quickstart

### Method A: One-Line Installer (Recommended)

Install `netra` directly to `~/.local/bin/netra` without requiring sudo or root permissions:

```bash
curl -sSL https://raw.githubusercontent.com/404Avinash/Netra_cli/main/install.sh | bash
```

Once installed, invoke `netra` globally from anywhere in your terminal:
```bash
# Instant local laptop audit
netra

# Or scan an external perimeter
netra github.com
```

### Method B: Install via Pip / Pipx

```bash
git clone https://github.com/404Avinash/Netra_cli.git
cd Netra_cli

# Editable pip install into your current environment
pip install -e .

# Or isolated global installation with pipx
pipx install .

# Run netra from anywhere
netra
```

### Method C: Standalone Portable Mode (Zero Installation)

NETRA runs out-of-the-box anywhere Python 3.10+ is installed:

```bash
git clone https://github.com/404Avinash/Netra_cli.git
cd Netra_cli
python3 netra.py
```

---

## Usage Guide

### 1. Instant Local Laptop Threat Audit (`netra`)

Run `netra` without arguments to audit your local laptop:

```bash
# Bare invocation: instant local audit
netra

# Equivalent explicit command
netra check

# Raw JSON output for automation, scripts, and SIEM pipelines
netra --json
```

### 2. Live Interactive Laptop Radar (`netra top`)

Launch an interactive, btop-style monitoring dashboard:

```bash
# Live dashboard for local laptop
netra top

# Custom refresh interval (in seconds):
netra top --interval 1.0

# Alias
netra monitor
```

**Interactive Hotkeys:**
- `[r]`: Force an immediate fresh network audit
- `[s]`: Save current security posture as baseline snapshot
- `[q]`: Exit dashboard cleanly

### 3. Save a Baseline Benchmark (`netra baseline save`)

Lock the current posture as the authoritative benchmark:

```bash
# Save local host baseline (stored in .netra/baselines/localhost.json)
netra baseline save --yes

# Or save external domain baseline
netra baseline save example.com --yes
```

### 4. Detect Drift & Regressions (`netra compare`)

Compare live security posture against your saved baseline:

```bash
# Compare local host against baseline
netra compare

# Or compare external domain
netra compare example.com
```

**Output when regressions or newly exposed ports are detected (exits with code `1`):**
```text
┌─────────────────────────────┬────────────────┬────────────────┬────────────┬──────────┐
│ CONTROL / PORT              │ BASELINE       │ CURRENT        │ STATUS     │ SEVERITY │
├─────────────────────────────┼────────────────┼────────────────┼────────────┼──────────┤
│ Exposed Port 0.0.0.0:6379   │ closed/local   │ EXPOSED        │ DRIFT      │ HIGH     │
│ Exposed Port *:3000         │ closed/local   │ EXPOSED        │ DRIFT      │ MEDIUM   │
│ SSH Key Permissions         │ 0600 (PASS)    │ wider (FAIL)   │ DRIFT      │ HIGH     │
└─────────────────────────────┴────────────────┴────────────────┴────────────┴──────────┘

▲ DRIFT DETECTED: 3 host security regression(s) identified!

Recommended Actions:
  1. [HIGH] Exposed Port 0.0.0.0:6379: Bind Redis Database to 127.0.0.1 or firewall port 6379.
  2. [MEDIUM] Exposed Port *:3000: Bind Dev Server to 127.0.0.1.
  3. [HIGH] SSH Key Permissions: Run 'chmod 600 ~/.ssh/id_*' to secure private keys.
```

### 5. Safe Alert Dispatch via Swytchcode (`netra notify`)

When regressions occur, file a GitHub issue directly in your tracking repository without hardcoding API secrets.

#### Safe Preview Mode (Default)
Running without `--confirm` displays a full markdown preview with **zero external network calls**:

```bash
# Preview local laptop regression issue
netra notify --repo 404Avinash/Netra_cli

# Preview external endpoint regression issue
netra notify example.com --repo 404Avinash/Netra_cli
```

#### Confirmed Dispatch
Pass `--confirm` to route the dispatch through Swytchcode's kernel:

```bash
netra notify --repo 404Avinash/Netra_cli --confirm
# ✔ Issue created successfully via Swytchcode!
# Issue URL: https://github.com/404Avinash/Netra_cli/issues/1
```

> [!NOTE]
> **Live Demonstration:** Inspect a real issue created live by NETRA_CLI via Swytchcode at [GitHub Issue #1](https://github.com/404Avinash/Netra_cli/issues/1).

---

### 6. External Perimeter Security Auditing (`netra <domain>`)

All commands seamlessly accept external domains or URLs:

```bash
# Nmap-style bare invocation for remote perimeter
netra github.com

# Explicit check
netra check github.com

# Live remote certificate and header monitor
netra top github.com

# Remote JSON observation
netra github.com --json
```

---

## Monitored Security Controls

### Local Laptop & Host Guardian Controls

| Control / Check | Inspection Method | Criteria | Severity on Regression | Weight |
|---|---|---|---|---|
| **Exposed Databases & Debuggers** | Sockets via `ss` / `/proc/net/tcp` | Bound to `0.0.0.0`, `*`, or `::` (e.g. Redis `6379`, Postgres `5432`, Debugger `5678`/`9229`) | **HIGH / CRITICAL** | 20-40 pts |
| **Exposed Dev Servers** | Sockets via `ss` / `/proc/net/tcp` | Dev servers bound to all interfaces (`3000`, `4000`, `5000`, `5173`, `8080`, `8000`) | **MEDIUM** | 10-20 pts |
| **Outbound Plaintext Leak** | Process connections (`ESTAB`) | Active outbound plaintext HTTP (`80`), Telnet (`23`), or FTP (`21`) | **MEDIUM** | 10 pts |
| **Backdoor / C2 / Miner Ports** | Sockets & active conns | Known suspicious ports (`4444`, `1337`, `3333`, `6667`, etc.) | **CRITICAL** | 30 pts |
| **SSH Private Key Hygiene** | `stat` on `~/.ssh/id_*` | Permissions wider than `0600` (e.g., world/group readable) | **HIGH** | 25 pts |
| **Workspace Secrets Hygiene** | Git tracking & file scan | `.env` files unignored in git repositories | **MEDIUM** | 15 pts |

### Remote Perimeter Controls

| Control | Verification Method | Status Values | Severity on Regression | Weight |
|---|---|---|---|---|
| **HTTP → HTTPS Redirect** | Plaintext HTTP (port 80) connection testing for permanent 301/308 redirect | `pass`, `fail`, `inconclusive` | **MEDIUM** | 25 pts |
| **TLS Certificate Validity** | Direct `ssl` handshake extracting `notAfter` timestamp and calculating remaining validity | `pass`, `fail`, `inconclusive` | **HIGH** (if expired) | 25 pts |
| **Strict-Transport-Security (HSTS)** | Inspects header and validates directives according to RFC 6797 (`max-age=0` fails) | `present`, `missing`, `inconclusive` | **MEDIUM** | 20 pts |
| **Content-Security-Policy (CSP)** | Checks header presence and asserts non-empty configuration | `present`, `missing`, `inconclusive` | **MEDIUM** | 15 pts |
| **X-Content-Type-Options** | Enforces the strict `nosniff` header value | `present`, `missing`, `inconclusive` | **LOW** | 10 pts |
| **Referrer-Policy** | Checks header presence and policy definition | `present`, `missing`, `inconclusive` | **LOW** | 5 pts |

---

## Test Suite

NETRA includes a comprehensive zero-dependency test suite mocking all network layers (`socket`, `ssl`, HTTP, `ss`, and `/proc/net`):

```bash
python3 -m unittest discover -s tests -v
```

```text
Ran 77 tests in 0.312s

OK
```

---

## Continuous Integration

Every commit and pull request is automatically tested across Python 3.10, 3.11, and 3.12 via GitHub Actions.

See live build results in [GitHub Actions](https://github.com/404Avinash/Netra_cli/actions).

---

## License

This project is licensed under the [MIT License](LICENSE).
