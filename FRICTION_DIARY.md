# Swytchcode Onboarding & Friction Diary

> **Project:** Swytchcode PPI Assessment  
> **Author:** Avinash  
> **Environment:** Linux (x86_64), `swytchcode` CLI v2.25.1, Bun runtime  
> **Submission Date:** November 2026  

---

## Overview & Purpose
This friction diary documents all steps, unexpected behaviors, rough edges, documentation gaps, and resolutions encountered while installing, exploring, and building with Swytchcode.

---

## Friction Log

### Entry 1: Doctor Diagnostics on Fresh Directory
* **Step Attempting:** Verify installation health and diagnostic status using `swytchcode doctor` before initialization.
* **Command / Action:** `swytchcode doctor`
* **What I Expected:** A diagnostic message reporting CLI version, system dependencies, auth status, and an informative note indicating that the current directory is not yet a Swytchcode project.
* **What Actually Happened:** 
  ```text
  no .swytchcode/tooling.json found in "/home/avi/Downloads/Swytchcode_ppi_task" or any parent directory - run 'swytchcode init' to initialize
  ```
  Exit code returned was `1` (failure).
* **Friction / Rough Edge:** While the recommendation (`run 'swytchcode init'`) is clear, failing with exit code 1 on `doctor` prior to `init` can be confusing for a first-time user who expects `doctor` to check system requirements and prerequisites regardless of project state.
* **Next Step / AI Action:** Checked `swytchcode init --help` to inspect initialization options (`--mode`, `--editor`, `--non-interactive`).
* **Status / Resolution:** Resolved by proceeding to initialize a project using `swytchcode init`.

---

### Entry 2: PostHog Telemetry Shutdown Warning on Standard Commands
* **Step Attempting:** Verifying authentication session using `swytchcode whoami` or executing commands.
* **Command / Action:** `swytchcode whoami`, `swytchcode list`, `swytchcode add method`
* **What I Expected:** Clean output displaying account details, session validity, or execution results.
* **What Actually Happened:** The account or execution output was printed, but followed by PostHog telemetry timeout warnings printed directly to stderr/stdout:
  ```text
  posthog 2026/11/02 18:59:06 WARN: shutdown timeout exceeded, some messages may be lost
  posthog 2026/11/02 18:59:06 WARN: sending request - Post "https://us.i.posthog.com/batch/": context canceled
  posthog 2026/11/02 18:59:06 ERROR: 1 messages dropped: shutdown timeout
  ```
* **Friction / Rough Edge:** Raw telemetry network timeouts leak into the terminal UX during normal CLI usage, creating visual noise and making users suspect their network or command failed.
* **Status / Resolution:** Harmless warning, but recommended to mute or decouple telemetry from CLI foreground exit.

---

### Entry 3: Mental Model Gap: Init vs. Wrekenfile Generation
* **Step Attempting:** Inspect the `Wrekenfile` right after running `swytchcode init`, as described in onboarding documentation ("Inspect the Wrekenfile generated during project initialization").
* **Command / Action:** `swytchcode init --mode sandbox` followed by `find . -iname "*wreken*"`
* **What I Expected:** A starter `wrekenfile.yaml` or template to be created in the project root or `.swytchcode/` directory.
* **What Actually Happened:** `swytchcode init` only created `.swytchcode/tooling.json` and empty integration folders. No `wrekenfile.yaml` existed anywhere in the workspace.
* **Next Step / AI Action:** Read `swytchcode get --help` which revealed: `"Fetch Wrekenfile bundles for a provider"`. Wrekenfiles are only fetched/generated when running `swytchcode get <provider>` or executing a provider tool (e.g. `swytchcode demo stripe`).
* **Status / Resolution:** Identified that Wrekenfiles are provider bundle artifacts stored under `.swytchcode/integrations/<Provider>/<library>/<version>/wrekenfile.yaml`. Documentation phrasing ("Inspect the Wrekenfile generated during project initialization") should be updated to clarify that initializing does not produce a Wrekenfile until a provider is fetched.

---

### Entry 4: Conflicting CLI Recommendation for Demo Method
* **Step Attempting:** Following the CLI's own recommended next step after running `swytchcode demo stripe`.
* **Command / Action:** 
  The CLI displayed:
  ```text
  running in demo mode (stripe.create_payment not added yet)
     run: swytchcode add method stripe.create_payment
  ```
  Ran: `swytchcode add method stripe.create_payment`
* **What I Expected:** The method `stripe.create_payment` would be added to `.swytchcode/tooling.json`.
* **What Actually Happened:** 
  ```text
  error: canonical ID "stripe.create_payment" not found in any fetched providers.
  Run: swytchcode get <provider>
  ```
* **Investigation:** Searched `.swytchcode/integrations/Stripe/stripe/2026-06-24.dahlia/methods.json` for payment methods. Discovered that the actual canonical ID in the Stripe Wrekenfile is `stripe.payment_intent.create`. `stripe.create_payment` is an internal virtual alias used only by the demo runner.
* **Status / Resolution:** The CLI prompts the user to add an ID that does not exist in the official provider schema. Resolved by adding the canonical method: `swytchcode add method stripe.payment_intent.create`. Recommended fix: Have the CLI advise running `swytchcode add method stripe.payment_intent.create`.

---

### Entry 5: Demo Mode Extensibility Limitation
* **Step Attempting:** Running another Stripe method (`stripe.customer.create`) using the `--demo` flag to test sandbox execution.
* **Command / Action:** `swytchcode exec stripe.customer.create --demo --dry-run`
* **What I Expected:** A simulated execution or mock response similar to `stripe.create_payment`.
* **What Actually Happened:** 
  ```text
  Demo unavailable for stripe.customer.create: no demo available for stripe.customer.create — supported: stripe.create_payment
  To use real providers:
    swytchcode init
  ```
  Exited with code 4.
* **Friction / Rough Edge:** The suggestion says "To use real providers: swytchcode init", even though the project is already initialized. The message should advise `swytchcode auth connect <provider>` or setting live API credentials instead.
* **Status / Resolution:** Understood that `--demo` is currently hardcoded for a tiny set of showcase methods (`stripe.create_payment`).

---

### Entry 6: Empty Default `sandbox_endpoint` in Provider Manifest
* **Step Attempting:** Executing or dry-running a method while in `sandbox` mode (`"mode": "sandbox"` in `tooling.json`).
* **Command / Action:** `swytchcode exec github.zen.list --dry-run`
* **What I Expected:** Swytchcode to execute or dry-run against the public sandbox/staging endpoint or fallback to the provider's API.
* **What Actually Happened:** 
  ```text
  ⚠ base URL for GitHub.github@1.1.4 (sandbox) is not set: "" (it is empty) - previewing with https://base-url-not-set.invalid; this provider runs on your own instance - set sandbox_endpoint for "GitHub.github@1.1.4" in .swytchcode/integrations/manifest.json, or set SWYTCHCODE_BASE_URL_GITHUB_GITHUB_SANDBOX
  Missing credentials for GitHub. Connect now? [Y/n]
  ```
* **Friction / Rough Edge:** When `swytchcode init --mode sandbox` is chosen, the fetched `manifest.json` populates `production_endpoint` with `https://api.github.com` but leaves `sandbox_endpoint` blank (`""`). This causes immediate warnings or dead URLs unless the user manually edits `manifest.json` or switches mode to `production`.
* **Status / Resolution:** Documented workarounds: configure `manifest.json` with a mock server or set `mode: "production"` in `tooling.json`.

---

### Entry 7: Locating the Canonical Method ID for GitHub Issue Creation
* **Step Attempting:** Identifying and enabling the exact Swytchcode method ID for creating GitHub issues from NETRA_CLI.
* **Command / Action:** `swytchcode list methods | grep -i issue`
* **What I Expected:** A single intuitive canonical ID such as `github.issues.create` or `github.create_issue`.
* **What Actually Happened:** The GitHub provider bundle includes over 40 issue-related methods (`github.issue.create`, `github.issue_comment.create`, `github.issue_event.list`, `github.issue_label.add`, etc.). Searching the full methods list without filtering by HTTP endpoint or inspecting the Wrekenfile requires parsing a large bundle.
* **Next Step / AI Action:** Inspected `.swytchcode/integrations/GitHub/github/1.1.4/methods.json` and matched endpoint `POST /repos/{owner}/{repo}/issues` to canonical ID `github.issue.create`.
* **Status / Resolution:** Confirmed `github.issue.create` is enabled in `tooling.json` with `swytchcode list tooling`.

---

### Entry 8: Parameter Schema Structure for Path vs Body Arguments in `swytchcode exec`
* **Step Attempting:** Formulating the input payload for `github.issue.create` execution.
* **Command / Action:** `swytchcode info github.issue.create`
* **What I Expected:** Flat arguments (e.g., `--owner OWNER --repo REPO --title "..." --body "..."`).
* **What Actually Happened:** `swytchcode info` reveals that `owner` and `repo` are path parameters (strings), whereas `body` is an object containing `title` (required) and `body` (optional string, markdown). Passing flat arguments or mismatched nesting produces a schema validation error before execution.
* **Next Step / AI Action:** Structured the JSON payload with proper nesting:
  ```json
  {
    "tool": "github.issue.create",
    "args": {
      "owner": "OWNER",
      "repo": "REPO",
      "body": {
        "title": "Issue title",
        "body": "Markdown body content"
      }
    }
  }
  ```
* **Status / Resolution:** Implemented nested structure in `netra.py` and validated schema acceptance.

---

### Entry 9: Interactive Stdin Blocking in Unattended CLI & Subprocess Execution
* **Step Attempting:** Invoking `swytchcode exec` programmatically from Python `subprocess.run()`.
* **Command / Action:** `swytchcode exec github.issue.create --dry-run --input owner=... --input repo=... --body '{"title":"..."}'`
* **What I Expected:** The CLI to run deterministically and non-interactively in automated subshells.
* **What Actually Happened:** When credentials are missing, the command prompts interactively on standard input:
  `Missing credentials for GitHub. Connect now? [Y/n] `
  This hangs automated pipelines and parent processes indefinitely waiting for TTY response.
* **Next Step / AI Action:** Consulted `skills.md` for headless invocation syntax. Piping JSON directly over standard input:
  `echo '{"tool":"github.issue.create","args":{...}}' | swytchcode exec`
  runs purely non-interactively and does not hang on terminal prompts.
* **Status / Resolution:** Implemented JSON stdin piping in `netra.py` via `subprocess.run(["swytchcode", "exec"], input=json.dumps(payload), text=True, capture_output=True)`.

---

### Entry 10: Structured Auth Failure Contract and Exit Code 3
* **Step Attempting:** Handling the failure path when dispatching an issue without configured GitHub credentials.
* **Command / Action:** Executed `swytchcode exec` with a valid JSON payload when GitHub OAuth/token is not connected.
* **What I Expected:** A generic exit code 1 or unparsed error.
* **What Actually Happened:** Swytchcode cleanly returned exit code `3` and emitted structured JSON to stderr:
  ```json
  {"error":"missing credentials for GitHub - run `swytchcode auth connect GitHub`","category":"auth","suggested_action":"to access registry features, run: swytchcode login - local execution works without auth","reference_id":"SWY-ERR-CB7193"}
  ```
* **Next Step / AI Action:** Verified that exit code 3 is Swytchcode's designated auth failure code. Configured `netra.py` to propagate this exit code and display the exact troubleshooting command (`swytchcode auth connect GitHub`).
* **Status / Resolution:** Clear, deterministic failure handling without masking errors or crashing.

---

### Entry 11: Telemetry Noise Leakage in Subprocess Stderr Output
* **Step Attempting:** Capturing and presenting failure diagnostics from `swytchcode exec` when invoked as a subprocess from Python.
* **Command / Action:** `subprocess.run(["swytchcode", "exec"], input=json.dumps(payload), text=True, capture_output=True)`
* **What I Expected:** `proc.stderr` to contain either clean human-readable diagnostic messages or the exact JSON failure object.
* **What Actually Happened:** In addition to the JSON error payload, `stderr` contained mixed timestamped runner logs and unsuppressed PostHog telemetry shutdown warnings:
  ```text
  2026/11/02 20:58:02 [swytchcode exec] request tool=github.issue.create ...
  {"error":"missing credentials for GitHub - run `swytchcode auth connect GitHub`", ...}
  posthog 2026/11/02 20:58:03 WARN: shutdown timeout: 1 batches still in flight
  posthog 2026/11/02 20:58:03 WARN: shutdown timeout exceeded, some messages may be lost
  ```
  Dumping `stderr` directly into user terminal output exposed confusing telemetry messages to end-users.
* **Next Step / AI Action:** Inspected the output stream format. Identified that Swytchcode outputs structured JSON error objects as discrete lines within stderr.
* **Status / Resolution:** Implemented structured JSON line parsing in `netra.py` (`dispatch_swytchcode_issue`). When an execution failure occurs, NETRA parses the structured JSON payload to extract `error`, `suggested_action`, and `reference_id`, suppressing raw internal telemetry logs while preserving crisp diagnostic messages.

