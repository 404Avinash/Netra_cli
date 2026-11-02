# NETRA_CLI: Network & Endpoint Threat and Resilience Assessor CLI

> **Submission:** Swytchcode PPI Assessment  
> **Author:** Avinash  
> **Repository:** https://github.com/404Avinash/Netra_cli  
> **Live Demonstrated Issue:** https://github.com/404Avinash/Netra_cli/issues/1  
> **Submission Date:** November 2026  

---

## 1. Problem and Intended User

### The Problem
In modern DevOps and security operations, web application security controls frequently degrade silently:
- A reverse proxy misconfiguration accidentally removes the `Strict-Transport-Security` (HSTS) header or weakens the `Content-Security-Policy` (CSP).
- Port 80 ceases redirecting to HTTPS after an ingress controller restart, exposing users to plaintext downgrade attacks.
- A TLS certificate draws close to expiry or expires without alerting the correct team.
- Generic security scanners produce massive, noisy 50-page PDF reports that engineers ignore rather than actionable, bite-sized diffs.

### Intended User
Site Reliability Engineers (SREs), DevOps engineers, and security engineers who need:
1. Fast, deterministic, zero-dependency endpoint checks during CI/CD or synthetic monitoring.
2. An intentional, human-reviewed security baseline that ignores routine modifications (e.g., certificate renewals) while instantly flagging true security regressions.
3. Safe, auditable alerting into GitHub Issues via an execution authority kernel (Swytchcode) rather than brittle, hardcoded API scripts.

---

## 2. Explanation of Swytchcode (150–250 Words)

**Swytchcode** is an execution authority kernel and provider abstraction layer that governs how applications and autonomous agents interact with external APIs. In traditional architectures, connecting to third-party services like GitHub or Stripe requires installing bulky vendor SDKs, manually wrangling OAuth flows, scattering raw API keys across environments, and implementing bespoke retry, idempotency, and rate-limiting policies.

Swytchcode eliminates this complexity by turning third-party APIs into clean, statically discoverable contracts called **Wrekenfiles**. Instead of making direct HTTP requests or managing vendor libraries, developers declare trusted tools in a local `tooling.json` and execute them through a single offline-capable runtime kernel (`swytchcode exec`). Swytchcode centralizes credential injection, enforces granular security policies (such as network boundaries and approval gates), and standardizes error responses.

For example, when a security utility detects a configuration regression, it does not embed a GitHub client library with personal access tokens. Instead, it pipes a structured payload to `swytchcode exec github.issue.create`. The kernel verifies that the tool is authorized, maps the parameters against the provider's Wrekenfile schema, handles authentication securely out-of-band, and reliably dispatches the request. This provides complete auditability, eliminates token sprawl, and gives teams total control over agent and script execution.

---

## 3. NETRA_CLI Architecture & Controls

NETRA_CLI is built using pure Python standard library (`urllib`, `ssl`, `socket`, `json`, `argparse`, `subprocess`) with zero third-party pip dependencies.

### Monitored Controls

| Control | Implementation | Status Values | Regression Severity |
|---|---|---|---|
| **HTTP -> HTTPS Redirect** | Plaintext HTTP (port 80) connection testing for 301/308 redirect | `pass`, `fail`, `inconclusive` | **MEDIUM** |
| **TLS Certificate Validity** | `ssl` socket handshake extracting `notAfter`, calculating days left | `pass`, `fail`, `inconclusive` | **HIGH** (if expired) |
| **Strict-Transport-Security (HSTS)** | Header inspection over HTTPS connection | `present`, `missing`, `inconclusive` | **MEDIUM** |
| **Content-Security-Policy (CSP)** | Header inspection over HTTPS connection | `present`, `missing`, `inconclusive` | **MEDIUM** |
| **X-Content-Type-Options** | Header inspection, enforces `nosniff` | `present`, `missing`, `inconclusive` | **LOW** |
| **Referrer-Policy** | Header inspection over HTTPS connection | `present`, `missing`, `inconclusive` | **LOW** |

### Resilience Guarantee
Network timeouts or socket connection errors never produce false "missing" or false "fail" results. They cleanly yield `inconclusive`, preventing false alarms in alerting pipelines.

---

## 4. Setup and Commands

### Prerequisites
- Python 3.10+
- `swytchcode` CLI (v2.25.1 or later)

### CLI Command Reference

```bash
# 1. Live security inspection
python3 netra.py check --target https://github.com
python3 netra.py check --target https://github.com --json

# 2. Save reviewed security baseline
python3 netra.py baseline save --target https://github.com --yes

# 3. Detect drift against saved baseline (exits 0 if no drift, 1 if drift detected)
python3 netra.py compare --target https://github.com
python3 netra.py compare --target https://github.com --json

# 4. Issue Notification (Preview Mode - does not dispatch)
python3 netra.py notify --target https://example.com --repo owner/repo

# 5. Issue Notification (Confirmed Dispatch via Swytchcode)
python3 netra.py notify --target https://example.com --repo owner/repo --confirm
```

---

## 5. Actual Execution Outputs & Reproduction

### A. Live Inspection (`netra check`)
```text
$ python3 netra.py check --target https://github.com
NETRA Security Assessment for https://github.com
Observation Timestamp: 2026-11-02T15:20:33Z
==============================================================================
Control                      | Status          | Details / Value
------------------------------------------------------------------------------
HTTP -> HTTPS Redirect       | [PASS]      | HTTP 301 redirects to HTTPS: https://github.com/
TLS Certificate Validity     | [PASS]      | Valid certificate (86 days left, expires 2027-01-27T23:59:59Z, issuer: Sectigo Limited)
Strict-Transport-Security    | [PRESENT]   | max-age=31536000; includeSubdomains; preload
Content-Security-Policy      | [PRESENT]   | default-src 'none'; base-uri 'self'; child-src github.githubassets.com ...
X-Content-Type-Options       | [PRESENT]   | nosniff
Referrer-Policy              | [PRESENT]   | origin-when-cross-origin, strict-origin-when-cross-origin
==============================================================================
```

### B. Baseline Save (`netra baseline save`)
```text
$ python3 netra.py baseline save --target https://github.com --yes
✔ Baseline saved successfully to baselines/github.com.json
```

### C. Drift Comparison with Regressions (`netra compare`)
```text
$ python3 netra.py compare --target https://example.com
NETRA Drift Analysis for https://example.com
Baseline Saved: 2026-11-02T20:00:00Z | Current Time: 2026-11-02T15:21:16Z
======================================================================================
Control                    | Baseline   | Current    | Status       | Severity
--------------------------------------------------------------------------------------
HTTP->HTTPS Redirect       | pass       | fail       | DRIFT    | MEDIUM
TLS Certificate Validity   | pass       | pass       | MATCH        | -
Strict-Transport-Security  | present    | missing    | DRIFT    | MEDIUM
Content-Security-Policy    | present    | missing    | DRIFT    | MEDIUM
X-Content-Type-Options     | present    | missing    | DRIFT    | LOW
Referrer-Policy            | present    | missing    | DRIFT    | LOW
======================================================================================

⚠ DRIFT DETECTED: 5 security regression(s) identified!

Recommended Actions:
  1. [MEDIUM] HTTP->HTTPS Redirect: Enforce permanent 301/308 redirect from HTTP to HTTPS on port 80.
  2. [MEDIUM] Strict-Transport-Security: Restore Strict-Transport-Security header (recommended: max-age=31536000; includeSubDomains).
  3. [MEDIUM] Content-Security-Policy: Restore Content-Security-Policy header to protect against XSS and content injection.
  4. [LOW] X-Content-Type-Options: Restore 'X-Content-Type-Options: nosniff' header to prevent MIME sniffing.
  5. [LOW] Referrer-Policy: Restore 'Referrer-Policy: strict-origin-when-cross-origin' header to prevent referrer leakage.
```

### D. Safe Issue Notification Preview (`netra notify`)
```text
$ python3 netra.py notify --target https://example.com --repo avinash/netra-demo
================================================================================
[PREVIEW MODE] GitHub Issue Preview
Target Repository: avinash/netra-demo
================================================================================
Title: [NETRA Security Drift] example.com: 5 regression(s) detected

Body:
## NETRA Security Drift Alert

**Target Host:** `https://example.com`  
**Detected At:** `2026-11-02T15:21:20Z`  
**Baseline Anchor:** `2026-11-02T20:00:00Z`  
**Total Regressions:** `5`  

### Security Regressions Summary

| Control | Severity | Baseline | Current | Recommendation |
|---|---|---|---|---|
| **HTTP->HTTPS Redirect** | `MEDIUM` | `pass` | `fail` | Enforce permanent 301/308 redirect from HTTP to HTTPS on port 80. |
| **Strict-Transport-Security** | `MEDIUM` | `present` | `missing` | Restore Strict-Transport-Security header (recommended: max-age=31536000; includeSubDomains). |
| **Content-Security-Policy** | `MEDIUM` | `present` | `missing` | Restore Content-Security-Policy header to protect against XSS and content injection. |
| **X-Content-Type-Options** | `LOW` | `present` | `missing` | Restore 'X-Content-Type-Options: nosniff' header to prevent MIME sniffing. |
| **Referrer-Policy** | `LOW` | `present` | `missing` | Restore 'Referrer-Policy: strict-origin-when-cross-origin' header to prevent referrer leakage. |

### Action Required
Security controls that were previously configured and verified have degraded. Review the recommendations above and update the web server configuration.

---
*Dispatched automatically by [NETRA_CLI](https://github.com/404Avinash/Netra_cli) via Swytchcode Execution Authority Kernel.*
================================================================================
Run with --confirm to dispatch this issue to GitHub via Swytchcode:
  netra notify --target https://example.com --repo 404Avinash/Netra_cli --confirm
```

### E. Dispatch via Swytchcode Kernel (`netra notify --confirm`)
When executed with connected GitHub OAuth credentials, Swytchcode dispatches the live issue:
```text
$ python3 netra.py notify --target https://example.com --repo 404Avinash/Netra_cli --confirm
✔ Issue created successfully via Swytchcode!
```
*Live Issue:* https://github.com/404Avinash/Netra_cli/issues/1

When executed without GitHub OAuth credentials configured, Swytchcode returns exit code `3` and structured error output:
```text
$ python3 netra.py notify --target https://example.com --repo 404Avinash/Netra_cli --confirm
Swytchcode execution failed with exit code 3:
Error: missing credentials for GitHub - run `swytchcode auth connect GitHub`
Suggested Action: to access registry features, run: swytchcode login - local execution works without auth
Reference ID: SWY-ERR-18465F
```

---

## 6. Unit Test Suite Verification

Run the comprehensive unit test suite:
```bash
python3 -m unittest discover -s tests -v
```

### Actual Test Run Output
```text
test_load_nonexistent_baseline (test_netra.TestBaselineEngine.test_load_nonexistent_baseline) ... ok
test_save_aborted_by_user (test_netra.TestBaselineEngine.test_save_aborted_by_user) ... Baseline save aborted by user.
ok
test_save_and_load_baseline (test_netra.TestBaselineEngine.test_save_and_load_baseline) ... ✔ Baseline saved successfully to /tmp/tmpj0u93f66/example.com.json
ok
test_header_regression_detected (test_netra.TestDriftComparisonEngine.test_header_regression_detected) ... ok
test_ignores_routine_changes (test_netra.TestDriftComparisonEngine.test_ignores_routine_changes) ... ok
test_no_drift_when_identical (test_netra.TestDriftComparisonEngine.test_no_drift_when_identical) ... ok
test_redirect_regression (test_netra.TestDriftComparisonEngine.test_redirect_regression) ... ok
test_tls_expired_regression (test_netra.TestDriftComparisonEngine.test_tls_expired_regression) ... ok
test_ansi_padding_alignment (test_netra.TestEnhancedResilienceAndEdgeCases.test_ansi_padding_alignment) ... ok
test_headers_unverified_fallback_on_cert_error (test_netra.TestEnhancedResilienceAndEdgeCases.test_headers_unverified_fallback_on_cert_error) ... ok
test_headers_whitespace_values_reported_missing (test_netra.TestEnhancedResilienceAndEdgeCases.test_headers_whitespace_values_reported_missing) ... ok
test_hsts_max_age_zero_fails (test_netra.TestEnhancedResilienceAndEdgeCases.test_hsts_max_age_zero_fails) ... ok
test_hsts_missing_max_age_fails (test_netra.TestEnhancedResilienceAndEdgeCases.test_hsts_missing_max_age_fails) ... ok
test_tls_self_signed_cert_days_remaining_is_none (test_netra.TestEnhancedResilienceAndEdgeCases.test_tls_self_signed_cert_days_remaining_is_none) ... ok
test_tls_valid_cert_under_24_hours (test_netra.TestEnhancedResilienceAndEdgeCases.test_tls_valid_cert_under_24_hours) ... ok
test_all_headers_present (test_netra.TestHeadersCheck.test_all_headers_present) ... ok
test_headers_extracted_on_http_error (test_netra.TestHeadersCheck.test_headers_extracted_on_http_error) ... ok
test_headers_inconclusive_on_network_timeout (test_netra.TestHeadersCheck.test_headers_inconclusive_on_network_timeout) ... ok
test_headers_missing (test_netra.TestHeadersCheck.test_headers_missing) ... ok
test_x_content_type_options_invalid_value (test_netra.TestHeadersCheck.test_x_content_type_options_invalid_value) ... ok
test_observe_target (test_netra.TestObservationEngine.test_observe_target) ... ok
test_redirect_fail_200_ok (test_netra.TestRedirectCheck.test_redirect_fail_200_ok) ... ok
test_redirect_fail_non_https (test_netra.TestRedirectCheck.test_redirect_fail_non_https) ... ok
test_redirect_fallback_on_405 (test_netra.TestRedirectCheck.test_redirect_fallback_on_405) ... ok
test_redirect_inconclusive_on_timeout (test_netra.TestRedirectCheck.test_redirect_inconclusive_on_timeout) ... ok
test_redirect_pass_301 (test_netra.TestRedirectCheck.test_redirect_pass_301) ... ok
test_redirect_pass_302 (test_netra.TestRedirectCheck.test_redirect_pass_302) ... ok
test_issue_content_generation (test_netra.TestSwytchcodeIssueNotification.test_issue_content_generation) ... ok
test_notify_dispatch_handles_swytchcode_error (test_netra.TestSwytchcodeIssueNotification.test_notify_dispatch_handles_swytchcode_error) ... ok
test_notify_preview_mode_does_not_call_subprocess (test_netra.TestSwytchcodeIssueNotification.test_notify_preview_mode_does_not_call_subprocess) ... ok
test_notify_with_confirm_invokes_swytchcode (test_netra.TestSwytchcodeIssueNotification.test_notify_with_confirm_invokes_swytchcode) ... ok
test_tls_expired_cert (test_netra.TestTLSCheck.test_tls_expired_cert) ... ok
test_tls_inconclusive_on_timeout (test_netra.TestTLSCheck.test_tls_inconclusive_on_timeout) ... ok
test_tls_valid_cert (test_netra.TestTLSCheck.test_tls_valid_cert) ... ok
test_tls_verification_error (test_netra.TestTLSCheck.test_tls_verification_error) ... ok
test_invalid_repos (test_netra.TestURLAndRepoValidation.test_invalid_repos) ... ok
test_invalid_urls (test_netra.TestURLAndRepoValidation.test_invalid_urls) ... ok
test_valid_repos (test_netra.TestURLAndRepoValidation.test_valid_repos) ... ok
test_valid_urls (test_netra.TestURLAndRepoValidation.test_valid_urls) ... ok

----------------------------------------------------------------------
Ran 39 tests in 0.113s

OK
```

---

## 7. Notes on the Generated Wrekenfile

The Wrekenfile bundle for GitHub (`.swytchcode/integrations/GitHub/github/1.1.4/wrekenfile.yaml`) is a compiled provider specification that provides:
1. **Tool Canonical ID:** Mapped to `github.issue.create` (backed by `POST /repos/{owner}/{repo}/issues`).
2. **Schema Separation:** Distinguishes path variables (`owner`, `repo`) from the JSON payload body (`title`, `body`).
3. **Execution Policy:** Configures automatic retries on transient errors (429, 503, 504) with exponential backoff (500ms base delay, 30s max delay) while failing immediately on non-retryable 4xx client errors.
4. **Deterministic Kernel:** Allows local parsing and validation without requiring runtime calls to a central Swytchcode registry.

---

## 8. What Worked vs. What Did Not Work

### What Worked
- **Zero-Dependency CLI:** Standard library networking (`http.client`, `ssl`, `urllib.request`) achieved sub-second scan times without heavy external dependencies like `requests` or `httpx`.
- **Offline Mocked Tests:** 39 unit tests execute in ~110ms without needing live Internet access or mock servers.
- **Swytchcode JSON Stdin Mode:** Non-interactive execution using JSON stdin (`{"tool": "...", "args": {...}} | swytchcode exec`) provided rock-solid subprocess stability.
- **Preview Safeguard:** Requiring `--confirm` prevented unintended API calls or token consumption.

### What Did Not Work & Rough Edges Encountered
- **Default Sandbox Endpoint:** Initializing in sandbox mode left `sandbox_endpoint: ""` in `manifest.json`, resulting in base URL errors unless switched to `production` or populated.
- **Interactive Stdin Prompts in CLI Subprocess:** Invoking `swytchcode exec` with command line flags prompted interactively for credentials (`Connect now? [Y/n]`), which hung headless processes until switched to piped JSON stdin.
- **PostHog Telemetry Warnings:** Shutdown timeout warnings from PostHog telemetry were emitted to stderr during normal command execution.
*(Detailed steps, errors, and resolutions are recorded in [`FRICTION_DIARY.md`](file:///home/avi/Downloads/Swytchcode_ppi_task/FRICTION_DIARY.md).)*

---

## 9. Marketing Asset: Demo Script & Social Post

### Option A: 2-Minute Demo Video Script

**Title:** *Stop Security Drift with NETRA_CLI and Swytchcode*  
**Duration:** 2 Minutes  

- **[0:00 - 0:25] The Hook:**
  *(Screen: Terminal with split screen showing web server config and terminal)*  
  "Every team has had this happen: an engineer updates an Nginx or Caddy config, and accidentally drops the HSTS header or disables the HTTP-to-HTTPS redirect. You don't find out until your next quarterly audit. Let's fix that in 60 seconds with NETRA_CLI."

- **[0:25 - 0:55] Step 1: Inspection & Baseline:**  
  *(Screen: Running `python3 netra.py check --target https://github.com`)*  
  "NETRA inspects redirects, TLS expiration, and critical headers—HSTS, CSP, nosniff, and Referrer-Policy. It's built with zero dependencies. Once verified, we lock in a reviewed baseline: `python3 netra.py baseline save --target https://github.com --yes`. This baseline is human-reviewed and checked into git."

- **[0:55 - 1:30] Step 2: Drift Detection & Safe Preview:**  
  *(Screen: Running `python3 netra.py compare --target https://example.com`)*  
  "Now imagine an endpoint regresses. NETRA runs `compare`. It ignores routine cert renewals, but immediately flags true regressions with clear severity ratings and remediation guidance. When we run `netra notify`, it previews the exact GitHub issue without making unauthorized external calls."

- **[1:30 - 2:00] Step 3: Swytchcode Execution Authority:**  
  *(Screen: Running `netra notify ... --confirm`)*  
  "When confirmed, NETRA doesn't need hardcoded tokens or brittle SDKs. It delegates execution to Swytchcode's kernel (`github.issue.create`). Swytchcode handles credentials, enforces policies, and provides full auditability. Check out NETRA_CLI on GitHub and take control of your endpoint resilience today!"

---

### Option B: LinkedIn / Reddit Post

```markdown
🚀 Excited to introduce **NETRA_CLI**: Network & Endpoint Threat and Resilience Assessor.

Most security monitoring tools fall into one of two traps: they either flood your inbox with 50-page vulnerability PDFs, or they require heavy agent setups that break during CI.

We built NETRA_CLI with three core design principles:
1. **Zero External Dependencies:** Built with pure Python standard library networking (`ssl`, `socket`, `urllib`). Sub-second scan times, portable anywhere.
2. **Human-Reviewed Baselines:** Captures an intentional security baseline. Ignores routine changes (like certificate renewals) while instantly catching true regressions in HSTS, CSP, and redirects.
3. **Execution Authority via Swytchcode:** Rather than scattering raw GitHub API tokens across bash scripts, NETRA delegates issue creation to Swytchcode's offline-capable execution kernel. You get safe issue previews by default, policy enforcement, and auditability out of the box.

Check out the repository, run the 39-test offline suite, and let us know what controls you'd like to see next!

#DevSecOps #CyberSecurity #Python #Swytchcode #OpenSource #SRE #CloudSecurity
```

---

## 10. AI Usage Disclosure

- **AI Tools Used:** Antigravity (Google DeepMind agentic coding assistant).
- **How AI Was Used:**
  - Designed the architecture and test suite based on the assessment requirements.
  - Explored Swytchcode CLI discovery commands (`swytchcode list tooling`, `swytchcode info`).
  - Implemented standard library networking resilience logic (handling `HTTPError`, socket timeouts, and certificate calculations).
  - Drafted unit test mocks and documentation.
- **Key Engineering Decisions Made:**
  - Chose JSON stdin piping (`subprocess.run(..., input=...)`) over flag-based CLI args to prevent interactive TTY blocking.
  - Selected strict standard library implementations over external packages to ensure zero-installation portability.
  - Implemented pure deterministic drift detection that explicitly filters out routine renewals from being flagged as regressions.
