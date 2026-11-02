# Swytchcode PPI Assessment

> **Author:** Avinash  
> **Submission Deadline:** 5th November 2026 (11:59 PM)  
> **Repository:** Swytchcode PPI Exploration & Practical Demo  
> **Environment:** Linux (x86_64), Python 3, `swytchcode` CLI v2.25.1  

---

## 1. Problem and Intended User

### The Problem
As autonomous AI agents, LLM pipelines, and automated developer scripts increasingly interact with production APIs, traditional integration patterns break down:
1. **Unbounded Agent Authority:** AI agents given raw API credentials or generic HTTP tools can make unintended, destructive, or hallucinated mutations (e.g. creating duplicate orders, wiping tables, or calling unexpected endpoints).
2. **Brittle Integration Code:** Hardcoding vendor-specific SDKs across different services creates high maintenance overhead, inconsistent retry policies, and scattered credential handling.
3. **Lack of Centralized Execution Governance:** Most agentic architectures lack an isolated, deterministic execution firewall that strictly verifies schemas, enforces rate limits and idempotency, and logs every invocation to an immutable audit trail.

### Intended User
* **AI & Agentic Systems Engineers:** Developers building autonomous AI agents (LangGraph, AutoGen, CrewAI, custom LLM loops) who need a deterministic runtime sandbox and policy enforcement layer for tool execution.
* **Backend & Platform Engineers:** Teams seeking a unified, contract-driven standard to discover, permission, and audit external API operations across their microservices.

---

## 2. API / Integration Explored

During this evaluation, two primary integrations were inspected and exercised:
1. **Stripe (`Stripe.stripe@2026-06-24.dahlia`):**
   * Explored payment intent creation, customer provisioning, and financial transaction schemas.
   * Executed operations via Swytchcode's local deterministic kernel using both demo simulation and canonical method definitions.
2. **GitHub (`GitHub.github@1.1.4`):**
   * Analyzed repository schemas, authentication configurations, and public endpoint behavior (such as `github.zen.list` and repository events).

---

## 3. Setup and Commands

### Prerequisites
* Bun runtime or Node.js
* Swytchcode CLI installed (`curl -fsSL https://get.swytchcode.com | sh` or via Bun)
* Python 3.8+ (for running the practical demo application)

### Installation & Account Setup
```bash
# Verify installation
swytchcode --version
# Output: swytchcode version 2.25.1

# Authenticate session
swytchcode whoami
```

### Initializing the Project
```bash
# Initialize Swytchcode project configuration
swytchcode init --mode sandbox

# Fetch provider bundles (downloads Wrekenfiles)
swytchcode get stripe
swytchcode get github --non-interactive

# Inspect locally available methods
swytchcode list methods stripe
swytchcode list methods github

# Whitelist approved methods in tooling.json
swytchcode add method stripe.payment_intent.create
swytchcode add method github.zen.list

# Inspect tool schema and input requirements
swytchcode info stripe.payment_intent.create
```

---

## 4. What Worked

1. **CLI Installation & Auth:** Swytchcode CLI (`v2.25.1`) was installed and authenticated seamlessly via Bun.
2. **Bundle Fetching & Caching:** Successfully pulled full Wrekenfile bundles for both Stripe (584+ methods) and GitHub (1,200+ methods).
3. **Execution Kernel (Demo Execution):** Executed `stripe.create_payment` through the Swytchcode kernel (`swytchcode exec`) in demo mode, returning structured JSON containing simulated payment intent IDs and authorized amounts.
4. **Tool Whitelisting (`tooling.json`):** Registered canonical methods (`stripe.payment_intent.create` and `github.zen.list`) into `tooling.json`, verifying that only declared tools can be targeted.
5. **Programmatic Python Integration:** Built a practical Python CLI checkout script (`checkout_demo.py`) that successfully executes payment intents through the Swytchcode kernel with structured JSON parsing.
6. **Local Execution Auditing:** Verified Swytchcode’s auditing subsystem via `swytchcode audit stats`, recording an 87%+ success rate across execution runs with provider breakdowns and timestamps.

---

## 5. What Did Not Work & Errors Encountered

All friction points and unexpected behaviors have been systematically logged in [`FRICTION_DIARY.md`](./FRICTION_DIARY.md). Key findings include:

1. **`swytchcode doctor` on Fresh Directory:** Running `swytchcode doctor` prior to `swytchcode init` failed with exit code 1 (`no .swytchcode/tooling.json found`) instead of reporting system-level prerequisites.
2. **Conflicting CLI Recommendation for Demo Method:** After running `swytchcode demo stripe`, the CLI output advised running:
   ```text
   swytchcode add method stripe.create_payment
   ```
   Executing that command failed with:
   ```text
   error: canonical ID "stripe.create_payment" not found in any fetched providers.
   ```
   *Root Cause:* `stripe.create_payment` is a demo-runner alias; the canonical Wrekenfile ID is `stripe.payment_intent.create`.
3. **Telemetry Network Timeout Noise:** Normal CLI commands (`whoami`, `add method`, `doctor`) frequently printed raw PostHog shutdown timeout warnings to stderr/stdout.
4. **Empty Sandbox Endpoint Default:** When initialized in `sandbox` mode, fetched providers populate `production_endpoint` but leave `sandbox_endpoint` blank (`""`), leading to warnings when executing without a custom mock URL.

---

## 6. How to Reproduce

Follow these simple steps to reproduce the entire working pipeline:

```bash
# 1. Clone this repository and navigate into it
cd Swytchcode_ppi_task

# 2. Verify Swytchcode project health
swytchcode doctor

# 3. View enabled tools
swytchcode list tooling

# 4. Run the practical checkout example
python3 checkout_demo.py --amount 49.99 --item "AI Agent License" --customer "developer@example.com"

# 5. Check the audit history
swytchcode audit stats
```

---

## 7. Notes on the Generated Wrekenfile

The Wrekenfile (`wrekenfile.yaml`) is Swytchcode's core abstraction for API contracts. Located under `.swytchcode/integrations/<Provider>/<library>/<version>/wrekenfile.yaml`, it contains:

* **Top-Level Defaults:** Base URLs, default auth schemes (`basic_auth`, `bearer_token`).
* **Granular Method Specifications:** Each API method defines:
  * `HTTP`: Verb (`GET`, `POST`), endpoint paths, content-type, accepted response headers.
  * `INPUTS`: Strongly typed parameter schemas (type, location: query/body/path, required flags).
  * `SECURITY`: Declared authentication schemes (e.g. `bearerAuth`, `basicAuth`, `oauth2`).
  * `EXECUTION`: Execution paradigm (e.g. `KIND: http`, `MODE: sync`).
  * `RETURNS` & `ERRORS`: Typed response structures and status code mappings.
* **Execution Policies (in `manifest.json`):** Configurable retry limits (`max_retries: 3`), backoff delays, timeouts (30s HTTP, 90s total), non-retryable status codes (`[400, 401, 403, 404, 422]`), and idempotency headers (`Idempotency-Key`).

This declarative format eliminates runtime guesswork for AI agents by converting complex third-party APIs into strongly typed, inspectable interfaces.

---

## 8. Explain Swytchcode (150–250 Words)

> **Swytchcode** is an execution authority and runtime security gateway for agentic and developer-driven API integrations. When AI agents or autonomous workflows interact with external services, they frequently hallucinate API schemas, leak credentials, or trigger unintended destructive mutations. Swytchcode solves this by introducing a deterministic, offline-capable kernel governed by explicit declarations.
> 
> Instead of writing raw HTTP calls or hardcoding brittle SDKs, developers use Swytchcode to discover and bundle third-party APIs into declarative schema files called Wrekenfiles. The developer registers approved methods in a central `tooling.json`, configures guard policies (such as retry limits, budget caps, or human-in-the-loop approvals), and invokes operations through the Swytchcode CLI (`swy exec`) or runtime SDK. Swytchcode acts as an authoritative proxy that validates incoming arguments against the Wrekenfile contract, applies credential management, enforces security boundaries, and maintains an immutable audit log.
> 
> For example, in an autonomous customer onboarding workflow, an AI agent needs to provision a Stripe customer account and dispatch a welcome email. Rather than giving the agent raw Stripe API keys and unrestricted network access, the developer declares `stripe.customer.create` in `tooling.json` with an idempotency policy and a maximum spend constraint. Swytchcode executes the payment intent securely, intercepts any rogue parameter mutations, and records the full audit trail.
*(Word count: 218 words)*

---

## 9. Marketing Asset Reference

Full marketing copy (Reddit post, LinkedIn post, and a 2–3 minute video demo recording script) is provided in [`MARKETING_ASSET.md`](./MARKETING_ASSET.md).

---

## 10. Link to Demo Video

* **Demo Video Link:** `[YOUR_LOOM_OR_YOUTUBE_LINK_HERE]` *(Record using the provided script in `MARKETING_ASSET.md` and insert your link here prior to final submission).*

---

## 11. AI Usage Disclosure

In compliance with the assignment guidelines:
* **AI Assistants Consulted:** Antigravity (powered by Gemini).
* **How AI Was Used:**
  * Diagnosing CLI flag behaviors and environment compatibility.
  * Inspecting Wrekenfile schemas and debugging canonical ID mismatches.
  * Structuring the Python practical demo (`checkout_demo.py`) with subprocess JSON parsing.
  * Formulating and refining the structured Friction Diary and documentation.
* **Verification:** All commands, scripts, and executions were directly run and verified locally within the terminal environment.
