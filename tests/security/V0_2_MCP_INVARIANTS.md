# V0.2 Security Invariants

1. Missing MCP session -> no protected execution.
2. Unknown/unregistered tool -> protocol error and zero execution.
3. Tool outside task scope -> tool error and zero execution.
4. Resource outside task scope -> tool error and zero execution.
5. In-scope registered tool -> exactly one protected execution.
6. Gateway failures must fail closed rather than execute downstream.

The primary proof is DENY-before-execution: the protected handler must not be invoked on a denied request.