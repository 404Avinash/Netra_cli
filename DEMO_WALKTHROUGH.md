# NETRA_CLI & Swytchcode: End-to-End Local Walkthrough & Demo Guide

> **Author:** Avinash  
> **Project:** NETRA_CLI (Network & Endpoint Threat and Resilience Assessor)  
> **Repository:** https://github.com/404Avinash/Netra_cli  
> **Live Demonstrated Issue:** https://github.com/404Avinash/Netra_cli/issues/1  

---

## 1. What is this project and why are we making it?

### The Core Problem: Silent Security Drift
When developers and DevOps engineers push updates, deploy new containers, or restart reverse proxies (Nginx, Caddy, Cloudflare, Traefik), basic web security settings frequently break **without anyone noticing**:
- An ingress restart causes port 80 to stop redirecting to HTTPS.
- A modified proxy configuration accidentally drops the `Strict-Transport-Security` (HSTS) header or removes the `Content-Security-Policy` (CSP).
- A TLS certificate draws close to expiry or is renewed with misconfigured intermediate chains.

### Why Existing Tools Fail Small Teams
1. **Uptime Monitors (e.g. Pingdom, UptimeRobot):** They only answer *"is the server responding with 200 OK?"*. If a site loads over plain HTTP without HSTS, uptime monitors report green.
2. **Heavy Vulnerability Scanners (e.g. Nessus, Qualys, OWASP ZAP):** They take hours to run, produce 80-page noisy PDF reports, and require heavy infrastructure.

### The Solution: NETRA_CLI
**NETRA_CLI** is a fast, zero-dependency Python command-line utility. It inspects a website's critical perimeter controls in under 1 second, lets an engineer save an authoritative **baseline**, and immediately flags **drift** (regressions) when subsequent checks run.

---

## 2. How Swytchcode Works (The Most Important Part)

The heart of this project is demonstrating **Swytchcode as an Execution Authority**.

### The Traditional Risk (Without Swytchcode)
In traditional Python scripts or AI agent pipelines, creating a GitHub issue requires:
1. Creating a personal access token (PAT) with broad repository write permissions.
2. Hardcoding that secret into code, `.env`, or CI secrets.
3. If an engineer makes a mistake or an AI agent hallucinates an endpoint, the token can leak or execute destructive mutations (e.g. deleting a repository).
4. Writing custom retry loops and rate-limit handlers in Python.

### The Swytchcode Architecture (With Swytchcode)
NETRA_CLI delegates the external API execution entirely to Swytchcode's local kernel:

```text
[ NETRA_CLI ] ──(JSON Stdin)──> [ Swytchcode Kernel ] ──(OAuth)──> [ GitHub REST API ]
                                       │
                         ├── 1. Wrekenfile Schema Check (wrekenfile.yaml)
                         ├── 2. Tool Whitelist Check (tooling.json)
                         ├── 3. In-Flight OAuth Credential Injection
                         └── 4. Automatic Retries on 429/503/504
```

### The 5 Ways Swytchcode Shines:
1. **Zero Secret Sprawl:** `netra.py` contains **zero API tokens, zero passwords, and zero secrets**. Swytchcode manages OAuth out-of-band and injects the authorization header in flight.
2. **Contract-Governed Validation (Wrekenfiles):** External APIs are defined in declarative `wrekenfile.yaml` specifications. The Swytchcode kernel locally validates parameter schemas (path vs. body) *before* touching the network.
3. **Principle of Least Privilege:** Only explicitly whitelisted tools in `.swytchcode/tooling.json` (`github.issue.create`) can be executed. Even if compromised, NETRA cannot delete repositories or modify code.
4. **Built-in Resilience:** Automatic 3-attempt backoff retries on rate limits (429) or transient errors (503) without writing custom retry loops in Python.
5. **Local Auditability:** Every outbound dispatch is recorded locally (`swytchcode audit stats`).

---

## 3. "What is What": Repository File Map

Understanding every file in the repository:

| File / Folder | Purpose |
|---|---|
| [`netra.py`](./netra.py) | **The entire CLI application.** Contains pure check functions (`check_redirect`, `check_tls`, `check_headers`), baseline comparison logic, ANSI table formatting, and the Swytchcode subprocess dispatcher. Zero external pip dependencies. |
| [`tests/test_netra.py`](./tests/test_netra.py) | **The unit test suite.** 39 comprehensive tests mocking socket, SSL, and HTTP responses. Executes 100% offline in ~0.11s. |
| [`.swytchcode/tooling.json`](./.swytchcode/tooling.json) | **Tool whitelist.** Declares which methods are authorized to run (`github.issue.create`). |
| [`.swytchcode/integrations/`](./.swytchcode/integrations/) | **Provider bundles.** Contains `wrekenfile.yaml` and `methods.json` for GitHub and Stripe, defining the API schemas. |
| [`baseline.example.json`](./baseline.example.json) | **Example baseline.** Demonstrates the reviewed baseline format for `https://example.com`. |
| [`baselines/`](./baselines/) | **Local baseline storage.** Stores target-specific baselines (e.g. `github.com.json`). Ignored by git so user target data remains private. |
| [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) | **Automated CI/CD pipeline.** Tests all 39 unit tests and CLI commands across Python 3.10, 3.11, and 3.12 on every push. |
| [`README.md`](./README.md) | **Official project documentation.** Open-source documentation with CI badges, architecture diagrams, and control tables. |

---

## 4. Step-by-Step Terminal Demonstration

Here is the exact series of commands to type in your terminal to demonstrate the entire project from scratch.

### Step 1: Verify Swytchcode & Project Health
Check that Swytchcode is installed, authenticated, and that the bundles parse cleanly:

```bash
# 1. Check CLI version
swytchcode --version

# 2. Check connected accounts (Shows github oauth2 connected)
swytchcode auth status

# 3. Run doctor diagnostics
swytchcode doctor
```
*Expected Output:* `All checks passed (no errors).`

---

### Step 2: Live Security Check (`netra check`)
Inspect a live target website to view all 6 security controls:

```bash
# Formatted table view
python3 netra.py check --target https://github.com

# Machine-readable JSON output (for CI/CD)
python3 netra.py check --target https://github.com --json
```
*What to observe:* HTTP 301 redirect is verified, TLS certificate validity and days left are extracted, and 4 security headers (HSTS, CSP, nosniff, Referrer-Policy) are audited.

---

### Step 3: Save an Authoritative Baseline (`netra baseline save`)
Establish the verified controls as your baseline:

```bash
python3 netra.py baseline save --target https://github.com --yes
```
*What to observe:* Writes `baselines/github.com.json` marked with `"reviewed": true` and a timestamp.

---

### Step 4: Verify Zero Drift on Unchanged Endpoint (`netra compare`)
Run a comparison against the baseline you just saved:

```bash
python3 netra.py compare --target https://github.com
```
*What to observe:* Output reports `MATCH` across all controls and exits with code `0`. Notice that if the certificate is renewed in the future, NETRA smartly ignores the day count change because routine renewals are not regressions.

---

### Step 5: Simulate a Security Regression & Detect Drift
Now compare against a site that lacks headers (or an older baseline) to demonstrate drift detection:

```bash
# Copy example baseline (which expects HSTS, CSP, and redirect)
cp baseline.example.json baselines/example.com.json

# Run compare against live example.com (which lacks those headers)
python3 netra.py compare --target https://example.com
```
*What to observe:* NETRA immediately catches the regression, flags 5 security regressions (`DRIFT`), assigns severity levels (`MEDIUM` for redirect/HSTS/CSP, `LOW` for nosniff/referrer), outputs remediation steps, and exits with code `1`.

---

### Step 6: Safe Preview Mode (`netra notify` without confirm)
Demonstrate the built-in safeguard that prevents accidental or rogue dispatches:

```bash
python3 netra.py notify --target https://example.com --repo 404Avinash/Netra_cli
```
*What to observe:* Prints a formatted Markdown issue preview to the terminal and exits with code `0`. **Zero network calls** were made.

---

### Step 7: Live Issue Creation via Swytchcode Kernel (`netra notify --confirm`)
Now dispatch the regression alert through the Swytchcode execution authority:

```bash
python3 netra.py notify --target https://example.com --repo 404Avinash/Netra_cli --confirm
```
*What to observe:* 
```text
✔ Issue created successfully via Swytchcode!
```
*What happens under the hood:*
1. `netra.py` pipes the JSON payload to `swytchcode exec`.
2. Swytchcode checks `.swytchcode/tooling.json` to ensure `github.issue.create` is authorized.
3. Swytchcode validates the arguments against `wrekenfile.yaml`.
4. Swytchcode retrieves your OAuth token from its session vault and injects it into the HTTP header.
5. Swytchcode dispatches to GitHub's REST API and returns the result.

Check the live issue created on GitHub:
👉 **https://github.com/404Avinash/Netra_cli/issues/1**

---

### Step 8: View the Swytchcode Audit Log
Show that Swytchcode maintains an immutable local audit log of all executions:

```bash
swytchcode audit stats
```
*What to observe:* Shows total execution runs, success rate, and confirms that `github.issue.create` was executed successfully.

---

### Step 9: Run the Offline Test Suite
Demonstrate engineering rigor with the zero-dependency test suite:

```bash
python3 -m unittest discover -s tests -v
```
*What to observe:* All 39 unit tests run and pass in ~0.11s with zero network dependencies.

---

## 5. Talking Points for Your Demo Video or Interview

When explaining this project to an interviewer or recording your 2-minute video:

1. **The Hook (15s):**  
   *"Web security configurations degrade silently. A quick server reload can drop HSTS or disable HTTPS redirects, and uptime monitors won't notice. That's why I built NETRA_CLI."*
2. **The Product (30s):**  
   *"NETRA inspects 6 critical perimeter controls with zero dependencies. It lets you establish a human-reviewed baseline and compare against it to detect true regressions while ignoring routine certificate renewals."*
3. **The Swytchcode Differentiator (45s):**  
   *"For alerting, traditional scripts require hardcoding personal access tokens with dangerous repo-wide permissions. Instead, NETRA uses Swytchcode as an Execution Authority. Swytchcode validates the request against declarative Wrekenfile contracts, enforces least privilege through `tooling.json`, injects OAuth tokens in flight, and maintains a local audit trail. Here is Issue #1 on GitHub created live through Swytchcode without a single secret in my code."*
4. **DevOps & Testing (15s):**  
   *"The project has 39 offline unit tests and a live GitHub Actions CI/CD pipeline passing across Python 3.10, 3.11, and 3.12."*
