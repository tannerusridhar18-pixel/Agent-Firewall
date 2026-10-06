# Security Test Structure

Mandatory MCP security tests are introduced incrementally.

The first hard architectural gate is V0.2:

> If a denied MCP call can reach the protected tool, the gateway is not secure enough to proceed.

Planned suites include:
- unknown/unregistered tool denial
- out-of-task denial
- invalid destination/path denial
- capability expiry/replay/revocation
- quarantine enforcement
- direct downstream bypass rejection
- fail-closed policy/gateway failure
- audit failure cannot convert DENY to ALLOW
