# MCP Integration

IntentGuard is MCP-first.

Canonical protected path:

IDE/AI Agent
→ MCP Client
→ IntentGuard MCP Gateway
→ Protected MCP Server/Tool
→ Resource

## V0.1

This directory establishes the MCP integration boundary and fixtures location. No downstream MCP forwarding is enabled yet.

## V0.2

Implement:
- MCP gateway request handling
- server/tool registration
- tool manifests
- session binding
- hard ALLOW/DENY forwarding
- protected demo MCP tools
- DENY-before-execution security proof

Do not bypass the gateway with direct downstream credentials.

## V0.3 Capability Enforcement

V0.3 introduces cryptographic, task-scoped capability tokens enforced fail-closed at the MCP Gateway.

Endpoint: `POST http://localhost:8080/mcp`

### Required Headers

| Header | Description | Required |
|---|---|---|
| `Mcp-Session-Id` | Active agent session ID bound to an active task | Required for `tools/call` |
| `X-IntentGuard-Capability` | Cryptographic capability token authorized for task, tool, and resource scope | Required for `tools/call` |
| `Mcp-Protocol-Version` | MCP protocol version negotiation header (e.g., `2024-11-05`) | Optional |

### Request Lifecycle
1. **Capability Validation**: Evaluates the `X-IntentGuard-Capability` header against active, unexpired, unrevoked capability records matching `task_id`, `tool_name`, and `resource_scope`.
   - Missing, invalid, expired, revoked, or out-of-scope capabilities are immediately denied with zero tool lookup and zero downstream execution.
2. **Tool Manifest Resolution**: Verifies tool registration in `mcp_tool_manifests`.
3. **Policy Evaluation**: Evaluates deterministic task policies against task constraints.
4. **Execution**: If and only if all gates pass, dispatches execution to the protected tool handler.

### MCP Client Configuration

See [`mcp-client-config.example.json`](./mcp-client-config.example.json) for standard MCP client configuration.

### Control-Plane API (Capability Issuance & Rotation)

Capability lifecycle operations are exposed via the authenticated control plane at `/api/v1/control-plane/capabilities`:
- Authentication: requires `X-IntentGuard-Operator-Key` and `X-Operator-Id` headers.
- Issuance: `POST /api/v1/control-plane/capabilities` validates task, tool, scope, and TTL server-side before minting a random capability token.
- Rotation: `POST /api/v1/control-plane/capabilities/{id}/rotate` immediately revokes the old capability in the database and returns a replacement token.
- Revocation: `POST /api/v1/control-plane/capabilities/{id}/revoke` invalidates capabilities to prevent further tool access.
- Security Invariant: The raw capability token is returned only once at creation/rotation time and is never stored in plaintext (only SHA-256 hashes are persisted).

See [`docs/V0.3_CAPABILITIES.md`](../docs/V0.3_CAPABILITIES.md) for full endpoint specifications.

