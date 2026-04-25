# MCP / A2A Bridge

## Status

Draft.

## Purpose

Project Model Context Protocol (MCP) tool catalogues and Agent-to-Agent
(A2A) capability advertisements into TrustForge agent contracts. AI
agents that already speak MCP or A2A can be wrapped by TrustForge
without rewriting their tool definitions.

The reference implementations live at:

- TS: `tools/tf-types-ts/src/core/bridge-mcp.ts` and `bridge-a2a.ts`.
- Rust: `crates/tf-types/src/bridge_mcp.rs` and `bridge_a2a.rs`.

## Source identity / catalogue object

### MCP

An MCP tool list — the response to `tools/list`:

```jsonc
{
  "tools": [
    {
      "name": "filesystem.read",
      "description": "Read a file",
      "inputSchema": { /* JSON Schema */ }
    }
  ]
}
```

MCP tool lists carry no actor identity of their own; the connecting
agent is identified separately (typically by the spawning process or
session cookie). The bridge therefore projects MCP into a *capability
surface*, not an actor.

### A2A

An A2A AgentCard — the discovery payload another agent publishes:

```jsonc
{
  "agent_id": "code-helper",
  "display_name": "Code Helper",
  "public_key_b64": "<base64 ed25519 key>",
  "public_key_algorithm": "ed25519",
  "capabilities": [
    { "name": "fs.read", "risk": "R1" },
    { "name": "shell.exec", "risk": "R3" }
  ],
  "trust_domain": "example.com"
}
```

A2A AgentCards DO carry actor identity. The bridge derives an actor URI
and a capability set in one step.

## Actor mapping

| Bridge | Actor URI form                                      |
| ------ | --------------------------------------------------- |
| MCP    | inherited from session — no projection              |
| A2A    | `tf:actor:agent:<trust_domain>/<agent_id>`          |

A2A AgentCards without `public_key_b64` are projected with a
`external-attestation` pseudo-key (`agent-card:<agent_id>`); the daemon
treats them at trust level T1 and refuses high-risk capabilities.

## Capability mapping

Both bridges normalize tool / capability names:

1. lowercase
2. non-alphanumeric runs collapse to `_`
3. trim leading / trailing `_`
4. if the result has no `.`, prepend the bridge namespace (`mcp.` or
   `a2a.`)

Examples:

| Input              | MCP output            | A2A output            |
| ------------------ | --------------------- | --------------------- |
| `Read File!`       | `mcp.read_file`       | `a2a.read_file`       |
| `filesystem.read`  | `mcp.filesystem_read` | `a2a.filesystem_read` |
| `system-info`      | `mcp.system_info`     | `a2a.system_info`     |

`.` collapses to `_` so the projection is unambiguous; callers wanting
the original dotted name can pass `prefix` to override the namespace
(e.g. `prefix: "tools"` → `tools.system_info`).

## Trust level mapping

| Source                                | Trust level |
| ------------------------------------- | ----------- |
| MCP local stdio transport             | T1          |
| MCP HTTP w/ TLS pinned                | T2          |
| A2A AgentCard w/ ed25519 key          | T2          |
| A2A AgentCard w/o key (pseudo-attest) | T1          |

## Proof events

- `bridge.mcp.tools_imported` — an MCP catalogue projected, lists tool
  count and capability digest.
- `bridge.a2a.agent_card_accepted` — a remote agent's AgentCard
  projected to a TrustForge actor.
- `bridge.mcp.tools_rejected` / `bridge.a2a.agent_card_rejected` —
  with reason.

## Revocation behavior

MCP catalogues are re-imported on every connection; revocation happens
at the host process layer (the agent simply stops advertising the
tool). A2A actors revoke through the standard TrustForge
`RevocationIndex` at the daemon — the bridge consults it on every
AgentCard projection.

## Conformance tests

`conformance/bridge-vectors.yaml` covers:

- `mcp.normalize.tool-name-with-dot`
- `mcp.normalize.tool-name-with-special-chars`
- `mcp.normalize.tool-name-with-prefix`
- `a2a.accept.minimal-agent-card`
- `a2a.reject.empty-agent-id`
