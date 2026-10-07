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

### Control-Plane Requirement (Capability Issuance)

In accordance with security principles, the gateway does **not** expose an unauthenticated or insecure capability-issuance API. Capabilities are issued via the internal `CapabilityService`. Exposing an external issuance API requires an authenticated and authorized control plane (e.g., operator console / IAM-authenticated control-plane service) in the next iteration.

