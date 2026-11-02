# Swytchcode integration skill

Use this file when writing or changing code that calls an external API through
Swytchcode. The editor's always-read config contains the essential trust and policy
rules. This file holds the detailed workflow and runtime guidance shared by all agents.

Use Swytchcode's CLI or MCP tools to inspect installed providers and tool contracts.
Do not infer a provider's inputs, endpoint, or authentication model from its name.

The MCP server exposes Swytchcode discovery and execution tools. Setup and policy
editing tools depend on its profile, so use the CLI when an MCP operation is unavailable.
`swytchcode login`, `whoami`, `logout`, `sync`, and `auth connect` are CLI commands.

## Adding a provider

Follow these steps in order:
1. Run `swytchcode search <keyword>` to find a provider.
2. Run `swytchcode get <provider>` to fetch its bundle.
3. Use `swytchcode list methods` or `swytchcode list workflows` to find the canonical ID.
4. Enable the method with `swytchcode add method <canonical_id>`, or install the
   workflow with `swytchcode add workflow <canonical_id>`. To enable every method
   for a provider, use `swytchcode add method --all <provider>`.
5. Inspect the contract with `swytchcode info <canonical_id>`, then use the runtime
   library or `swytchcode exec` as described below.

### Useful commands

| Command | Purpose |
|---|---|
| `swytchcode list` | List locally installed providers |
| `swytchcode info <canonical_id>` | Show a tool's I/O by canonical ID (workflow step order matters) |
| `swytchcode --version` | Check the Swytchcode version |
| `swytchcode discover "<intent>" [--library <name>]` | Find API capabilities from a natural-language description (MCP: `swytchcode_discover`) |
| `swytchcode plan <canonical_id>` | Show a workflow's steps before executing (MCP: `swytchcode_plan`) |
| `swytchcode doctor` | Diagnose project setup (MCP: `swytchcode_doctor`) |
| `swytchcode sync [provider_name]` | Pull new/updated workflows and methods from backend without touching tooling.json |

### Debugging execution

If an execution returns 404 from a `localhost` base URL, inspect the method and
endpoint with `swytchcode info <canonical_id>`, then preview the resolved request
with `swytchcode exec <canonical_id> --dry-run`. The mode in `tooling.json` selects
the sandbox or production endpoint from `manifest.json`. Use `swytchcode doctor`
to check project setup before changing application code.

| Flag | Effect |
|---|---|
| `--dry-run` | Preview the exact HTTP request (method, URL, headers, body) without calling it. MCP: `dry_run: true` |
| `--verbose` | Log full request + response JSON to stderr (`Authorization` redacted); redirect with `2>debug.log`. MCP: `verbose: true` |
| `--output <file>` | Write binary response body to a file; stdout gets a JSON summary with `saved_to`/`bytes` |

Errors from `swytchcode exec` are written to stderr as structured JSON:
```json
{ "error": "message", "category": "network", "retryable": true }
```
`category` values: `auth` | `permission_denied` | `policy_denied` | `policy_error` | `validation` | `not_found` | `network` | `rate_limit` | `internal` | `base_url_not_set` | `tenant_not_connected` | `plan_limit` | `setup_required`.
`retryable: true` means the error is transient - retry is safe. Non-retryable errors require user action.
`tenant_not_connected`: a call made with a tenant id for an end user who has not connected the provider. Do not retry - the app must show that end user its Connect button.
`plan_limit` / `setup_required`: the developer's plan does not allow this, or the developer must set the provider up first (`swytchcode auth connect <provider>`). Do not retry - report `suggested_action` to the developer.
`base_url_not_set`: the provider runs on the user's own instance (Jira, Salesforce, ...) and its URL is not set. Do not retry - ask the user for their instance URL and point them to the fix in `suggested_action`.
In MCP context, parse the stderr JSON `category` field before deciding how to respond to an `swytchcode_exec` error.

## Golden Path (MANDATORY, STEP-BY-STEP)

When a task involves Swytchcode, providers, methods, or workflows:

### Step 1 - Check local state
- Discover which providers, methods, and workflows exist locally using Swytchcode discovery.
- Treat the result as authoritative.

If nothing relevant exists:
- DO NOT proceed.
- Ask the user what provider should be added.

### Step 2 - Ensure provider is present
If the required provider is not present locally:

- STOP.
- Ask the user for permission to fetch the provider.
- Do NOT assume it exists.
- Do NOT generate code.

Only continue after the provider has been explicitly added.

### Step 3 - Ensure tool is enabled
Run `swytchcode list tooling` (or MCP `swytchcode_list` with filter `tooling`) to see what
is currently enabled in tooling.json.

- If the canonical_id IS already listed: proceed directly to Step 4. Do NOT call `swytchcode add` again.
- If the canonical_id is NOT listed:
  - STOP.
  - Ask the user for permission to add it to Swytchcode configuration.
  - Do NOT invent or placeholder canonical IDs.
  - Do NOT generate code.
  - For methods: run `swytchcode add method <canonical_id>`, then confirm it appears in `swytchcode list tooling`.
  - For workflows: run `swytchcode add workflow <canonical_id>` (CLI) or MCP `swytchcode_add_workflow`, then confirm it appears in `swytchcode list tooling`.

Never skip this check. Never assume a tool is in tooling.json without verifying via `swytchcode list tooling`.

### Step 4 - Inspect the contract
For any method or workflow you intend to use:

- Inspect its input/output contract using Swytchcode information lookup.
- Use the discovered schema as the sole source of truth.

If contract information is unavailable:
- STOP.
- Ask the user.
- Do NOT guess.

### Step 5 - Generate code
Only after Steps 1-4 are complete:

**Pre-generation gate:** Run `swytchcode list tooling` and confirm the canonical_id appears
in the output. If it is missing, do NOT generate code - go back to Step 3.

Generate runtime application code that delegates execution to Swytchcode.

**Golden rule: the generated code must run as-is. No edits required beyond supplying
real values for required fields.**

Use the output of `swytchcode info <canonical_id>` to determine which fields are
required vs optional and what the auth header looks like.

1. **Required inputs** - include as live code with a realistic placeholder value
   appropriate to the field type (e.g. a real-looking string, not `""`).
2. **Auth** - follow the Authentication & Environment Variables rules below, which
   branch on whether `swytchcode info` shows an `Auth` section. Do not add `.env`
   loading or credential handling here for managed providers.
3. **Optional inputs** - do NOT include as live code. Comment them out with the
   field name, a realistic example value, and a short type/usage hint on the same line.
   Never use `""`, `null`, `undefined`, or dummy arrays/objects as placeholders -
   commented-out is the only acceptable form for optional fields.
4. **No dummy data** - do not invent attachment content, fake IDs, or stub arrays.
   If an optional field needs non-trivial setup (e.g. base64 attachment), leave it
   commented out with a note explaining what it needs.
5. **Output** - add a `// Returns: { ... }` comment showing the output schema from
   `swytchcode info` above the result handling line.

## Absolute Prohibitions (NON-NEGOTIABLE)

You MUST NOT:

- Invent or placeholder canonical IDs
- Use fake values like `your_method_id`
- Generate example or speculative code
- Generate runtime code before configuration is complete
- Assume providers or tools exist
- Infer APIs from training data
- Read or reason about `.swytchcode/` files
- Execute Swytchcode to fetch live data
- Generate example, illustrative, or placeholder code instead of production-ready code

If progress cannot be made with certainty:
- STOP.
- Ask the user.

## Code Generation Rules

When generating code:

- Always delegate execution to Swytchcode
- Use an official Swytchcode runtime library if available (see Runtime Usage below). Otherwise invoke Swytchcode via subprocess.
- Pass a single structured input object
- Handle stdout, stderr, and exit codes

Generated code MUST be immediately executable without placeholders.

### Runtime Usage

Use EXACTLY the following patterns - do NOT invent class names, module paths, or method signatures:

**JavaScript/Node.js:**
```js
const { exec } = require("@swytchcode/runtime");

const result = await exec("canonical.id", { /* args */ });
```

**Python:**
```python
from swytchcode_runtime import exec

result = exec("canonical.id", { /* args */ })
```

**Go:**
```go
import runtime "github.com/swytchcode/go-runtime"

result, err := runtime.Exec("canonical.id", map[string]interface{}{ /* args */ })
```

### Authentication & Environment Variables

Check the `Auth` section in `swytchcode info` first - it tells you which of two
completely different auth models this provider uses. Do not assume; do not apply the
same pattern to every provider.

**`Auth.type` is present (`oauth2`, `api_key`, `basic_auth`, or `api_key_header`) - MANAGED:**
- The developer connects this once via `swytchcode auth connect <provider>` (a CLI-only
  command you cannot run for them - ask them to run it if the exec call fails with an
  auth-category error). Credentials are stored locally and encrypted.
- `swytchcode exec` / `swytchcode_exec` injects the correct Authorization header (or, for
  `api_key_header`, the custom header named in `Auth.header_name`) automatically on every
  call - this happens inside the CLI/runtime, after your code has already called exec.
- Generated code MUST NOT read a credential from an env var, load `.env` for it, or
  set/override an Authorization or credential header for this method. The CLI only
  injects the real credential when that header is absent - if you set it yourself (even
  to a placeholder), the CLI trusts your value and skips injection entirely, so the call
  goes out with a wrong or missing credential instead of the real one. This is also the
  only correct choice for `basic_auth`/`api_key_header`: there is no single Bearer-token
  env var that could represent either credential shape anyway.

**No `Auth` section, or `Auth.type` is `bearer_token` (legacy/unmanaged provider):**
- NEVER hardcode credentials.
- ALWAYS read from environment variables.
- ALWAYS add `.env` loading at the top of the generated file - Go has no stdlib .env
  loader, so use a small dependency the same way Node/Python do:
  - Node.js: `require('dotenv').config();`
  - Python: `from dotenv import load_dotenv; load_dotenv()`
  - Go: `github.com/joho/godotenv` - `godotenv.Load()`
- Name the env var after the service (e.g. `<SERVICE>_API_KEY`).
- Pass the auth header as an arg to override the static placeholder:
  - Node.js: `Authorization: \`Bearer \${process.env.<SERVICE>_API_KEY}\``
  - Python: `f"Bearer {os.environ['<SERVICE>_API_KEY']}"`
  - Go: `"Bearer " + os.Getenv("<SERVICE>_API_KEY")`

## Multi-tenant apps (calls for your app's end users)

When the app you are building calls a provider for one of ITS users (each user
connects their own Gmail, Slack, ...), every such call is for one end user, named
by a tenant id:

- Pass the tenant id on EVERY call made for an end user:
  - Node.js: `exec("canonical.id", args, { tenantId })`
  - Python: `exec("canonical.id", args, tenant_id=tenant_id)`
  - CLI: `swytchcode exec <canonical_id> --tenant <id>`
- If the app's policies ask for human approval, also pass how the approver should see that
  end user (e.g. their name and email): `tenantLabel` / `tenant_label` / `--tenant-label`.
- Take the tenant id from the app's own logged-in session on the server. NEVER take it
  from the browser, a request body, a query string or a header the client controls.
- NEVER fall back to the developer's own account when a tenant id is missing or the end
  user is not connected. A call made without a tenant id uses the developer's account.
- OAuth providers: a server route calls `connect({ provider, tenantId })` (Python:
  `connect(provider, tenant_id)`) and returns the `url` to the browser. The browser
  opens it in a popup straight from the user's click; the link works once and expires
  after 10 minutes, so fetch a new one per click.
- API-key providers: collect the end user's key in the app's own form, send it to the
  server, and save it with `saveKey({ provider, tenantId, key })` (Python:
  `save_key(provider, tenant_id, key)`). Never log it or send it anywhere else.
- When an end user disconnects or is deleted: `disconnect({ provider, tenantId })`.
- When an AI agent picks the tools for an end user, bind the client instead: `new Swytchcode(provider, { tenantId })` (Python: `Swytchcode(provider, tenant_id=tenant_id)`), one client per request. Every tool the agent runs then uses that user's accounts.
- Choosing Default Swytchcode or the developer's own OAuth app is the developer's
  decision, made once with `swytchcode auth connect <provider>`. Never offer that
  choice to end users.
- Error `tenant_not_connected` (exit 3) means "show this end user the Connect button",
  not "retry". `plan_limit` and `setup_required` need the developer: report
  `suggested_action` to them.

## Methods and Workflows

- Methods and workflows are both executable tools.
- Workflows may reference multiple methods internally.
- Workflows are opaque and must be executed as-is.

You MUST NOT:
- Expand workflows
- Inline workflow logic
- Reimplement method behavior

## Discovering workflow steps and their I/O

When you need to use a workflow:

1. **List workflows** - `swytchcode list workflows` (or MCP `swytchcode_list` with filter `workflows`) shows workflow canonical IDs and their provider (`provider.library@version`).
2. **Inspect the workflow** - `swytchcode info <workflow_canonical_id>` returns the workflow’s own input schema (`Inputs`) and its **steps** (each step has a `canonical_id`). Build the exec call’s args from this top-level `Inputs` schema.
3. **Understand a step (optional, for comments/explanation only)** - run `swytchcode info <step_canonical_id>` on any step canonical ID to see that method’s input/output schema. Use this only to write an accurate `// Returns: { ... }` comment or explain behavior to the user - never to generate a separate exec call for that step.

Do not guess step IDs or I/O from workflow names. Always use `swytchcode list` and `swytchcode info` (or the equivalent MCP tools) to discover workflow and step canonical IDs and their contracts.

Execute the workflow as ONE call - `exec(workflow_canonical_id, args)` (or MCP `swytchcode_exec`) - using the workflow’s own `Inputs` schema from step 2. The CLI runs every step internally; per the Methods and Workflows rule above, never expand a workflow into separate per-step exec calls in generated code.

## Advanced: Agentic / Dynamic Tool Selection

SKIP THIS SECTION unless the task explicitly requires a model to choose which tool(s)
to call at runtime (e.g. "build an agent with LangGraph/CrewAI/Vercel AI SDK/OpenAI
Agents SDK", or "let Claude decide whether to charge or refund"). The static `exec`
pattern under Runtime Usage above is what the Golden Path assumes and covers nearly
every task - read no further if that's what you're building.

Use EXACTLY the following - do NOT invent class names, module/import paths, or method
signatures:

**JavaScript/Node.js (Anthropic-style manual loop):**
```js
import { Swytchcode, TOOL_USE_INSTRUCTIONS } from "@swytchcode/runtime";
import { AnthropicProvider } from "@swytchcode/runtime/providers/anthropic";

const swx = new Swytchcode(new AnthropicProvider());
const tools = await swx.tools.get({ toolkits: ["stripe"] }); // or { tools: [...] } or { search: "..." }

// pass `tools` into anthropic.messages.create({ tools, ... }); after a response with
// stop_reason === "tool_use":
const toolResults = await swx.handleToolCalls(response);
```

**Python (Anthropic-style manual loop):**
```python
from swytchcode_runtime import Swytchcode, TOOL_USE_INSTRUCTIONS
from swytchcode_runtime.providers.anthropic import AnthropicProvider

swx = Swytchcode(provider=AnthropicProvider())
tools = swx.tools.get(toolkits=["stripe"])  # or tools=[...] or search="..."

# pass `tools` into client.messages.create(tools=tools, ...); after a response with
# stop_reason == "tool_use":
tool_results = swx.handle_tool_calls(response)
```

`tools.get(...)` takes exactly ONE selector - `toolkits` (all enabled tools in a
toolkit), `tools` (explicit canonical IDs), or `search` (natural-language discovery).
Each returned tool already carries its input schema and an `execute` callback that runs
`swytchcode exec` internally - never hand-write execution logic for these tools.
Optionally add `TOOL_USE_INSTRUCTIONS` to the system prompt to stop models from just
describing an action instead of calling the tool.

Non-Anthropic frameworks run their own tool loop - pass `tools.get(...)`'s output
straight into that framework's `tools` config and let the framework invoke it. Do NOT
call `handleToolCalls`/`handle_tool_calls` yourself in that case.

| Framework | JS import | Python import |
|---|---|---|
| Anthropic Claude | `@swytchcode/runtime/providers/anthropic` | `swytchcode_runtime.providers.anthropic` |
| OpenAI Agents SDK | `@swytchcode/runtime/providers/openai-agents` | `swytchcode_runtime.providers.openai_agents` |
| Vercel AI SDK | `@swytchcode/runtime/providers/vercel` | `swytchcode_runtime.providers.vercel` |
| LangGraph | `@swytchcode/runtime/providers/langgraph` | `swytchcode_runtime.providers.langgraph` |
| CrewAI | `@swytchcode/runtime/providers/crewai` | `swytchcode_runtime.providers.crewai` |

Note: `tools.get()`/`handleToolCalls()` are async in JS; `tools.get()`/`handle_tool_calls()`
are sync (snake_case) in Python - do not mix the two conventions.

**Go:** No agentic surface is confirmed for `github.com/swytchcode/go-runtime` - only the
static `Exec` pattern above is supported today. Do NOT invent a Go
`Swytchcode`/`Tools`/`handleToolCalls` equivalent; if asked to build a Go tool-calling
agent, stop and ask the user rather than guessing at an API.

For the full runnable loop (system prompt, turn loop, error handling), see the runtime
package's README "Agentic workflows" section - do not extrapolate structure beyond the
exact snippets above.

## When a contract is unavailable

If a tool or its schema cannot be confirmed through Swytchcode, stop and explain
which piece of configuration is missing. Do not generate a speculative call.
