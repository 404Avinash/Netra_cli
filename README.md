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
![Tests](https://img.shields.io/badge/tests-50%20passed-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

**NETRA_CLI** is a lightweight, zero-dependency developer and DevOps utility to monitor external web security configurations, prevent silent perimeter drift, and safely dispatch regression issues. Inspired by **Trivy** (high-contrast vulnerability severity grading) and **btop** (live interactive terminal monitoring).

Built entirely with Python's standard library—no `pip install` required to run.

---

## Visual Highlights

### 1. Trivy-Style Security Audit (`netra check`)
Instant endpoint inspection with objective security scoring, letter grades, and severity pills:

```text
  _   _ _____ _____ ____      _       ____ _     ___ 
 | \ | | ____|_   _|  _ \    / \     / ___| |   |_ _|
 |  \| |  _|   | | | |_) |  / _ \   | |   | |    | | 
 | |\  | |___  | | |  _ <  / ___ \  | |___| |___ | | 
 |_| \_|_____| |_| |_| \_\/_/   \_\  \____|_____|___|
      Network & Endpoint Threat & Resilience Assessor

 Target: https://github.com  |  Timestamp: 2026-11-02T18:21:30Z
 Security Score: [████████████████████] 100/100  (GRADE: A+)

┌─────────────────────────────┬────────────────┬────────────┬────────────────────────────────────────────────┐
│ CONTROL                     │ STATUS         │ SEVERITY   │ DETAILS / VALUE                                │
├─────────────────────────────┼────────────────┼────────────┼────────────────────────────────────────────────┤
│ HTTP -> HTTPS Redirect      │ [   PASS   ]   │    INFO    │ HTTP 301 redirects to HTTPS: https://github... │
│ TLS Certificate Validity    │ [   PASS   ]   │    INFO    │ Valid certificate (86 days left, expires 20... │
│ Strict-Transport-Security   │ [ PRESENT  ]   │    INFO    │ max-age=31536000; includeSubdomains; preload   │
│ Content-Security-Policy     │ [ PRESENT  ]   │    INFO    │ default-src 'none'; base-uri 'self'; child-... │
│ X-Content-Type-Options      │ [ PRESENT  ]   │    INFO    │ nosniff                                        │
│ Referrer-Policy             │ [ PRESENT  ]   │    INFO    │ origin-when-cross-origin, strict-origin-whe... │
└─────────────────────────────┴────────────────┴────────────┴────────────────────────────────────────────────┘
 Summary: 6 Passed, 0 Inconclusive, 0 Failed
```

### 2. btop-Style Interactive Dashboard (`netra top`)
Real-time, interactive curses dashboard with dynamic countdown gauges, matrix health, and hotkey actions (`[r]` refresh, `[s]` lock baseline, `[q]` exit):

```text
┌─────────────────────────── NETRA LIVE MONITOR  ──  [Target: https://github.com] ───────────────────────────┐
│ Security Score: [████████████████████] 100/100   GRADE: A+     Latency: 142ms          Audit: 18:21:30 UTC │
├─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ TLS CERTIFICATE EXPIRATION GAUGE                                                                            │
│ [████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 86 Days Remaining                                                   │
│ Expires: 2027-01-27T23:59:59Z  |  Issuer: Sectigo Public Server CA                                          │
├─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ PERIMETER CONTROLS MATRIX                                                                                   │
│     HTTP -> HTTPS Redirect:   [  PASS  ]  HTTP 301 redirects to HTTPS: https://github.com/                  │
│     HSTS Protection:          [PRESENT ]  max-age=31536000; includeSubdomains; preload                      │
│     CSP Hardening:            [PRESENT ]  default-src 'none'; base-uri 'self'; style-src 'unsafe-inline'    │
│     nosniff Guard:            [PRESENT ]  nosniff                                                           │
│     Referrer Policy:          [PRESENT ]  origin-when-cross-origin, strict-origin-when-cross-origin         │
├─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ BASELINE DRIFT CONTRACT                                                                                     │
│     ✔ BASELINE MATCH: Healthy contract (saved 2026-11-02T15:38:13)                                          │
├─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ HOTKEYS: [r] Refresh Now   [s] Save Baseline Snapshot   [q] Quit                                            │
│ Live monitoring active (interval: 5.0s) | Press 'q' to quit                                                 │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## The Problem: Silent Security Degradation

In modern development and deployment workflows, web security settings frequently degrade unnoticed:
- A reverse proxy reload drops the `Strict-Transport-Security` (HSTS) header or weakens the `Content-Security-Policy` (CSP).
- An ingress controller restart causes port 80 to stop redirecting HTTP traffic to HTTPS, exposing users to plaintext downgrade attacks.
- A TLS certificate draws close to expiry or is renewed with unexpected attributes.

### Tooling Comparison Matrix

| Capability | Uptime Monitors (e.g. Pingdom) | Vulnerability Scanners (e.g. Nessus) | **NETRA_CLI** |
|---|:---:|:---:|:---:|
| **HTTP → HTTPS Redirect Validation** | ❌ Blindly follows redirect | ⚠️ Buried in 50-page PDF | ✅ **Explicit check & validation** |
| **Header Drift (HSTS, CSP, nosniff)** | ❌ Ignores headers | ⚠️ High false-positive noise | ✅ **Direct presence & RFC validation** |
| **TLS Expiry Monitoring** | ⚠️ Basic ping | ⚠️ Heavy scheduled agent | ✅ **Calculates days & ignores renewals** |
| **Execution Speed & Portability** | N/A (SaaS only) | Heavy binary / agents | ✅ **Sub-second, 0 external deps** |
| **Interactive Terminal TUI** | ❌ No TUI | ❌ No TUI | ✅ **btop-style curses dashboard (`netra top`)** |
| **Alerting Pipeline Safety** | Webhook spam | Email alert flood | ✅ **Swytchcode Execution Authority** |

---

## Operational Workflow

### Security Baseline Lifecycle (Git Graph)

NETRA treats web security posture like version-controlled source code. You lock in a known good baseline (`baseline save`), verify deployments against it (`compare`), and catch regressions before your users do:

```text
*   d4e7f9a (HEAD -> main) Dispatched Issue #1 via Swytchcode Kernel
|\  
| * c8b2a10 (drift-analysis) netra notify --confirm (github.issue.create)
| * a7f3c21 netra compare --target https://example.com (5 regressions detected)
| * 5e2d19b Server deploy / reverse proxy configuration reload
|/  
* 2b8f410 netra baseline save --target https://example.com (locked contract)
* 1a9c042 netra check --target https://example.com (initial security audit)
```

### End-to-End Pipeline

```text
  ┌───────────────────────────────────┐
  │ 1. Target Website                 │
  │    (https://example.com)          │
  └─────────────────┬─────────────────┘
                    │
                    ▼
  ┌───────────────────────────────────┐
  │ 2. Audit: netra check / netra top │ ──▶ Trivy table & btop-style live dashboard
  └─────────────────┬─────────────────┘
                    │
                    ▼
  ┌───────────────────────────────────┐
  │ 3. Lock: netra baseline save      │ ──▶ Snapshot persisted to .netra/baselines/
  └─────────────────┬─────────────────┘
                    │
                    ▼
  ┌───────────────────────────────────┐
  │ [Server Deploy / Proxy Reload]    │ ──▶ Operational changes occur
  └─────────────────┬─────────────────┘
                    │
                    ▼
  ┌───────────────────────────────────┐
  │ 4. Verify: netra compare          │
  └─────────────────┬─────────────────┘
                    ├─────────────────────────────────────────────┐
          [No Drift Detected]                             [Regressions Found]
                    │                                             │
                    ▼                                             ▼
  ┌───────────────────────────────────┐         ┌───────────────────────────────────┐
  │ ✔ Exit 0 (Contract Intact)        │         │ ▲ Exit 1: netra notify            │
  └───────────────────────────────────┘         └─────────────────┬─────────────────┘
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
netra --help
```

### Method C: Standalone Portable Mode (Zero Installation)

NETRA runs out-of-the-box anywhere Python 3.10+ is installed:

```bash
git clone https://github.com/404Avinash/Netra_cli.git
cd Netra_cli
python3 netra.py example.com
```

---

## Usage Guide

### Nmap-Style Bare Domain Invocation (Zero Ceremony)

Just like `nmap` or `curl`, pass any bare domain or URL directly. NETRA automatically normalizes the target (prepending `https://` if no scheme is specified) and executes an instant security audit:

```bash
# Nmap-style bare invocation (automatically performs security audit)
netra github.com

# Raw JSON output for automation and jq processing
netra github.com --json

# Launch live interactive dashboard directly
netra top github.com
```

> [!NOTE]
> **100% Backward Compatible:** All subcommands support both positional targets (`netra check example.com`, `netra top example.com`) and standard flag syntax (`--target https://example.com`).

---

### 1. Instant Security Audit (`netra check`)

Inspect an endpoint with formatted Trivy-style table output:

```bash
# Nmap-style bare domain
netra github.com

# Positional target
netra check github.com

# Classic flag syntax
netra check --target https://github.com
```

For scripts and CI pipelines, use `--json`:
```bash
netra github.com --json
# or
netra check --target https://github.com --json
```

---

### 2. Live Terminal Monitoring Dashboard (`netra top`)

Launch an interactive, btop-style monitoring dashboard:

```bash
# Positional syntax
netra top github.com

# Or with custom interval and flags:
netra top --target https://github.com --interval 3.0
# or alias:
netra monitor github.com
```

**Interactive Hotkeys:**
- `[r]`: Force an immediate fresh network audit
- `[s]`: Save current security posture as baseline snapshot
- `[q]`: Exit dashboard cleanly

---

### 3. Save a Reviewed Baseline (`netra baseline save`)

Lock the current posture as the authoritative benchmark:

```bash
# Positional syntax
netra baseline save example.com --yes

# Or flag syntax:
netra baseline save --target https://example.com --yes
# ✔ Baseline saved successfully to baselines/example.com.json
```

---

### 4. Detect Drift & Regressions (`netra compare`)

Compare live security posture against your saved baseline:

```bash
# Positional syntax
netra compare example.com

# Or flag syntax:
netra compare --target https://example.com
```

**Output when regressions are detected (exits with code `1`):**
```text
┌─────────────────────────────┬────────────┬────────────┬────────────┬──────────┐
│ CONTROL                     │ BASELINE   │ CURRENT    │ STATUS     │ SEVERITY │
├─────────────────────────────┼────────────┼────────────┼────────────┼──────────┤
│ HTTP->HTTPS Redirect        │ pass       │ fail       │ DRIFT      │ MEDIUM   │
│ TLS Certificate Validity    │ pass       │ pass       │ MATCH      │ -        │
│ Strict-Transport-Security   │ present    │ missing    │ DRIFT      │ MEDIUM   │
│ Content-Security-Policy     │ present    │ missing    │ DRIFT      │ MEDIUM   │
│ X-Content-Type-Options      │ present    │ missing    │ DRIFT      │ LOW      │
│ Referrer-Policy             │ present    │ missing    │ DRIFT      │ LOW      │
└─────────────────────────────┴────────────┴────────────┴────────────┴──────────┘

▲ DRIFT DETECTED: 5 security regression(s) identified!

Recommended Actions:
  1. [MEDIUM] HTTP->HTTPS Redirect: Enforce permanent 301/308 redirect from HTTP to HTTPS on port 80.
  2. [MEDIUM] Strict-Transport-Security: Restore Strict-Transport-Security header (recommended: max-age=31536000; includeSubDomains).
  3. [MEDIUM] Content-Security-Policy: Restore Content-Security-Policy header to protect against XSS and content injection.
  4. [LOW] X-Content-Type-Options: Restore 'X-Content-Type-Options: nosniff' header to prevent MIME sniffing.
  5. [LOW] Referrer-Policy: Restore 'Referrer-Policy: strict-origin-when-cross-origin' header to prevent referrer leakage.
```

---

### 5. Safe Alert Dispatch via Swytchcode (`netra notify`)

When regressions occur, file a GitHub issue directly in your tracking repository without hardcoding API secrets.

#### Safe Preview Mode (Default)
Running without `--confirm` displays a full markdown preview with **zero external network calls**:

```bash
# Positional target
netra notify example.com --repo 404Avinash/Netra_cli

# Flag syntax
netra notify --target https://example.com --repo 404Avinash/Netra_cli
```

#### Confirmed Dispatch
Pass `--confirm` to route the dispatch through Swytchcode's kernel:

```bash
netra notify example.com --repo 404Avinash/Netra_cli --confirm
# or:
netra notify --target https://example.com --repo 404Avinash/Netra_cli --confirm
# ✔ Issue created successfully via Swytchcode!
# Issue URL: https://github.com/404Avinash/Netra_cli/issues/1
```

> [!NOTE]
> **Live Demonstration:** Inspect a real issue created live by NETRA_CLI via Swytchcode at [GitHub Issue #1](https://github.com/404Avinash/Netra_cli/issues/1).

---

## Monitored Security Controls

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

NETRA includes a comprehensive zero-dependency test suite mocking all network layers (`socket`, `ssl`, and HTTP):

```bash
python3 -m unittest discover -s tests -v
```

```text
Ran 50 tests in 0.191s

OK
```

---

## Continuous Integration

Every commit and pull request is automatically tested across Python 3.10, 3.11, and 3.12 via GitHub Actions.

See live build results in [GitHub Actions](https://github.com/404Avinash/Netra_cli/actions).

---

## License

This project is licensed under the [MIT License](LICENSE).
