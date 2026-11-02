<!-- swytchcode:contract:start -->
# Swytchcode Agent Contract

When writing or changing code that calls an external API or runs a workflow, use
Swytchcode rather than direct HTTP or SDK calls. Read the project-root `skills.md`
before writing integration code. If it is missing, restore it with `swytchcode init`.

- `.swytchcode/tooling.json` lists trusted, enabled tools and the execution mode.
  Confirm the exact canonical ID with `swytchcode list tooling` before generating a call.
  Do not invent IDs or execute tools that are not enabled.
- `.swytchcode/integrations/manifest.json` supplies provider endpoints for the selected
  mode. Use `swytchcode info` and `swytchcode doctor` to inspect the setup. Do not
  bypass the configured endpoint with a direct request.
- `.swytchcode/integrations/policies.json` contains guard policies evaluated before
  execution. Check them with `swytchcode policy list` when relevant. Honor blocks and
  required approvals; surface the policy instruction instead of bypassing it.

Use Swytchcode CLI or MCP tools to inspect project state and tool contracts. Keep
provider bundle internals behind those interfaces.
<!-- swytchcode:contract:end -->
