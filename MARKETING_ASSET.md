# Swytchcode Marketing Assets

This document contains ready-to-use marketing assets for Swytchcode, satisfying **Task 6** of the PPI assessment:
1. **Option A:** Reddit Post (Community-focused, technical, for r/LocalLLaMA, r/devops, or r/programming)
2. **Option B:** LinkedIn Post (Professional engineering & AI safety perspective)
3. **Option C:** 2–3 Minute Video Demo Script (Complete script with timestamps and screen actions for Loom / YouTube)

---

## Option A: Reddit Post

**Target Subreddits:** `r/devops`, `r/LocalLLaMA`, `r/webdev`, `r/programming`  
**Title:** Tired of giving AI agents unrestricted API keys? Here's how Swytchcode provides a deterministic execution firewall.

**Post Body:**

```markdown
If you’ve ever built autonomous agents with LangChain, LangGraph, or AutoGen, you know the quiet panic of giving an LLM direct API keys or HTTP tools. One prompt injection or hallucinated JSON payload, and your agent might double-charge a customer or wipe a table.

I recently tested **Swytchcode** (https://swytchcode.com), a developer tool built specifically to act as an *Execution Authority* for agentic API calls.

### What it actually does:
Instead of baking vendor SDKs and live bearer tokens into your agent's context window:
1. **Declarative Contracts (Wrekenfiles):** APIs are compiled into strict schemas (`wrekenfile.yaml`) specifying exact endpoints, parameter types, idempotency rules, and HTTP policies.
2. **Project Tooling Manifest:** You selectively whitelist approved methods inside `.swytchcode/tooling.json`. If a method isn't enabled, the kernel refuses to run it.
3. **Local Kernel Isolation:** Calls run through a local, deterministic kernel (`swytchcode exec`) that intercepts calls, enforces rate limits, manages credentials, and logs every execution to a local audit trail (`swytchcode audit`).
4. **Built-in Demo Sandbox:** You can test tools like Stripe payments instantly without needing live test keys or configuring mock servers.

### Quick Workflow:
```bash
# Initialize and fetch a bundle
swytchcode init --mode sandbox
swytchcode get stripe

# Whitelist allowed tool
swytchcode add method stripe.payment_intent.create

# Execute deterministically with automatic policy validation
swytchcode exec stripe.create_payment --demo --body '{"amount":2000,"currency":"usd"}'
```

In Python or Node, you invoke it via subprocess or their runtime wrapper, ensuring your LLM output is strictly validated against the Wrekenfile before touching network sockets.

Curious what guardrails others are using to stop autonomous agents from going rogue on third-party APIs? Have you tried contract-driven execution?
```

---

## Option B: LinkedIn Post

**Audience:** Software Engineers, Tech Leads, AI/ML Engineers  

**Post Content:**

```markdown
Giving autonomous AI agents direct access to external APIs is one of the biggest vulnerabilities in modern agentic architectures. 

When an LLM generates HTTP requests directly, traditional safeguards break down:
❌ Hallucinated endpoint paths and invalid request payloads
❌ Accidental credential leakage across context prompts
❌ Lack of granular execution policies and human-in-the-loop gates

Over the past few days, I explored **Swytchcode**—an execution authority and runtime governance layer for developer and agentic integrations.

Here is why their approach stands out:
🔹 **Contract-Driven Execution:** External APIs are governed by "Wrekenfiles"—declarative YAML specifications defining exact parameter constraints, security headers, retry policies, and idempotency guarantees.
🔹 **Principle of Least Privilege for Agents:** Agents don't get arbitrary API credentials. They interact through a localized kernel that enforces tool-level permissions defined in your project's `tooling.json`.
🔹 **Native Auditing:** Every outbound call, policy violation, and network hop is tracked locally with instant diagnostics via `swytchcode audit`.

I built a lightweight e-commerce checkout script wrapping Swytchcode's Stripe execution kernel. The separation of concerns between agent reasoning and API execution authority makes autonomous workflows substantially more resilient.

If you are deploying AI agents into production environments with sensitive API access, contract-governed execution is a pattern to watch.

Check them out: https://swytchcode.com / https://docs.swytchcode.com

#SoftwareEngineering #AIAgents #DevOps #API #AgenticAI #Swytchcode #CyberSecurity
```

---

## Option C: 2–3 Minute Video Demo Script

> **Format:** Screen recording using Loom, OBS, or Google Meet (unlisted YouTube / Drive link).  
> **Target Length:** ~2 minutes 30 seconds.  
> **Visual Setup:** VS Code / Terminal side-by-side with your project files.

### [0:00 – 0:30] Introduction & Problem Statement
* **On Screen:** Terminal showing `swytchcode --version` and project folder.
* **Voiceover:**  
  *"Hi everyone! In this demo, I’m exploring Swytchcode—an execution authority tool designed to make external API integrations safe, deterministic, and contract-governed for developers and autonomous AI agents.*  
  *The core problem Swytchcode tackles is API safety in agentic workflows: rather than letting agents or scripts make untracked, arbitrary HTTP calls with exposed API keys, Swytchcode interposes an execution kernel governed by declarative API contracts called Wrekenfiles."*

### [0:30 – 1:00] Initializing & Inspecting the Wrekenfile
* **On Screen:** Open `.swytchcode/integrations/Stripe/stripe/2026-06-24.dahlia/wrekenfile.yaml` in your code editor.
* **Voiceover:**  
  *"After installing the CLI and running `swytchcode init`, we fetch provider bundles using `swytchcode get stripe`.*  
  *Let's look at the generated `wrekenfile.yaml`. This file defines the full API schema—methods, security requirements, parameter locations, response schemas, and execution policies like automatic retries and idempotency keys. In this Stripe bundle alone, over 580 methods are formally mapped, turning a messy external API into a strictly validated interface."*

### [1:00 – 1:40] Executing an API Operation & Reviewing Tooling
* **On Screen:** Terminal executing CLI commands:
  ```bash
  swytchcode list tooling
  python3 checkout_demo.py --amount 49.99 --item "Pro Subscription"
  ```
* **Voiceover:**  
  *"To enable an API operation, we register it in `.swytchcode/tooling.json` using `swytchcode add method`. This ensures only explicit, whitelisted operations can ever be triggered.*  
  *Here, I’ve built a small Python application, `checkout_demo.py`, which simulates an e-commerce checkout. When we run it with a \$49.99 order, it dispatches the payload to the Swytchcode kernel. Swytchcode validates the request against the Wrekenfile, executes the Stripe payment intent in demo mode, and returns a structured JSON payload with our Payment Intent ID and confirmation status—all without exposing live API secrets."*

### [1:40 – 2:10] Auditing & Policy Governance
* **On Screen:** Run `swytchcode audit stats` in terminal.
* **Voiceover:**  
  *"Another great feature is the built-in observability. Running `swytchcode audit stats` gives us a real-time summary of our execution history, success rates, and active providers. Swytchcode also logs policy evaluations and outbound network hops, giving developers complete visibility into what tools were triggered."*

### [2:10 – 2:40] Key Takeaway & Conclusion
* **On Screen:** Show `FRICTION_DIARY.md` briefly.
* **Voiceover:**  
  *"One key thing I learned during onboarding is the importance of contract-first tooling for AI. Rather than relying on LLMs to guess API payloads, binding them to a deterministic schema prevents hallucinated endpoints and security flaws.*  
  *I also documented several onboarding friction points in my Friction Diary—such as CLI suggestions for demo aliases versus canonical IDs—which I’ve shared in the project repository.*  
  *Thanks for watching!"*
