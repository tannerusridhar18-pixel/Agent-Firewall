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
