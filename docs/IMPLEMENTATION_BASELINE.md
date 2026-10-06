# IntentGuard V0.1 Implementation Baseline

Source of truth: IntentGuard_Official_Document_Set_MCP_v2.2.zip.

## Required V0.1 scope

V0.1 must provide:
- Spring Boot + Java 21 modular-monolith foundation
- MySQL 8.x with deterministic Flyway migrations
- task/session/activity data model
- deterministic policy engine skeleton
- deterministic simulator and mock tool execution
- basic dashboard that can create/view a task and session and display activity
- health/readiness endpoints
- reproducible backend/frontend test baseline
- CI

## Explicitly deferred

Real protected MCP forwarding is V0.2.
Real MCP-capable IDE/agent integration is after the gateway is stable.
Task-scoped capability enforcement, provenance, risk, approval and quarantine are later roadmap stages.

## Security invariants

The simulator may execute only its own mock tool. It must never be described as downstream MCP enforcement.
The dashboard is not an enforcement boundary.
No external LLM is required for V0.1.
No universal visibility or prompt-injection-detection claim is permitted.
