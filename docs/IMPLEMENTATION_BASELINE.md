# IntentGuard Implementation Baseline — v2.2

This repository follows the official MCP-first document set v2.2.

## V0.1

V0.1 establishes the runnable core, data model, dashboard shell, deterministic simulator, policy skeleton and audit foundation.

Implemented:
- Java 21 + Spring Boot modular-monolith base
- MySQL 8.x + Flyway
- Task/session/activity schema
- deterministic policy interface and safe default behavior
- simulator endpoint for reproducible activity decisions
- audit/activity domain records
- Next.js + React + Tailwind shell
- Docker Compose local MySQL
- CI baseline

Not implemented yet:
- MCP request forwarding
- protected MCP server/tool execution
- task-scoped capability issuance
- provenance enforcement
- risk/approval/quarantine enforcement
- attack evaluation metrics
- real IDE/agent integration

## V0.2

The next gate is the MCP Gateway:
- MCP server/tool registration
- Tool Manifest
- authenticated session binding
- protected demo tools
- hard ALLOW/DENY forwarding
- DENY-before-execution proof
- direct downstream bypass rejection

## V0.3+

Follow the canonical roadmap for capability, provenance, alignment, risk, approval, quarantine, attack evaluation, real MCP-agent integration, dashboard expansion and hardening.

## Security invariant

The gateway remains authoritative. Dashboard controls never authorize tools directly. Protected downstream credentials must remain gateway/server-side in the supported deployment.

## Honesty rule

No universal prompt-injection detection, universal agent compatibility, hidden-reasoning visibility, or whole-system monitoring claim is allowed. Metrics are reported only from actual reproducible tests.
