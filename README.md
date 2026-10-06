# IntentGuard / AgentFirewall

**MCP-first, provenance-aware, capability-based authorization gateway for autonomous AI agents.**

This repository follows the **IntentGuard / AgentFirewall Official Document Set v2.2**. The documents are the source of truth for architecture, security invariants, technology, version order, and release gates.

## Canonical architecture

```
IDE / AI Agent
      |
   MCP Client
      |
IntentGuard MCP Gateway
      |
Protected MCP Server / Tool
      |
   Resource
```

The dashboard communicates with IntentGuard Core through REST. It is never an enforcement point.

## Technology baseline

- Java 21 + Spring Boot
- Maven Wrapper
- MySQL 8.x + Flyway
- Next.js + React + Tailwind CSS
- MCP-first integration
- Deterministic Java policy engine
- JUnit/Spring Boot tests
- Docker Compose

## V0.1 foundation

V0.1 is intentionally limited to a runnable core:
- Spring Boot application
- MySQL/Flyway schema foundation
- task/session/activity data model
- deterministic policy skeleton
- replayable deterministic simulator
- audit model
- Next.js dashboard shell
- CI baseline

**MCP enforcement is V0.2.** V0.1 must not pretend to provide protected downstream execution.

## Security rule

The agent is not the final security authority. The gateway is. Any advisory model can only make a deterministic result stricter; it can never turn a deterministic DENY into ALLOW.

Never claim protection that has not been implemented and measured.
