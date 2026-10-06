# IntentGuard / AgentFirewall

IntentGuard is a runtime security enforcement gateway for AI agents.

It sits between an AI agent and protected tools/APIs and makes the final authorization decision for consequential tool calls. The enforcement path is deterministic: task scope, tool capability, provenance, policy and runtime security context are evaluated before execution.

## Core security invariants

- The gateway is the enforcement boundary.
- The LLM is advisory only and can only make a decision stricter.
- Capabilities are narrow, task-scoped and time-limited.
- Sensitive arguments require acceptable provenance.
- Unknown/lost provenance fails closed.
- DENY means the protected tool is not executed.
- Dashboard/observability components cannot bypass gateway authorization.
- Security decisions are auditable without logging raw secrets.

## Technology baseline

- Backend / gateway: Java 21 + Spring Boot
- Database: MySQL 8.x
- Frontend: Next.js + React + Tailwind CSS
- API: REST/JSON
- Build: Maven Wrapper
- Testing: JUnit/Spring tests + frontend tests + security/evaluation fixtures

## Repository layout

```text
backend/       Spring Boot enforcement service
frontend/      Next.js dashboard
contracts/     machine-readable security contracts
docs/          implementation and architecture notes
infra/         local infrastructure configuration
tests/         cross-component security/evaluation fixtures
```

## Development rule

Implementation follows the finalized IntentGuard documentation baseline. Security invariants are not weakened for convenience. Each major capability is implemented incrementally, tested, security-verified, and only then advanced.

## Status

Repository foundation initialized. V0.1 implementation starts from this baseline.
