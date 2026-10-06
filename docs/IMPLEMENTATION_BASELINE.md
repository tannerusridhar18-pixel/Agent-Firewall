# IntentGuard Implementation Baseline

## Authoritative scope

The repository follows the finalized IntentGuard / AgentFirewall documentation baseline:
- Project Charter & Requirements
- Architecture & Security Design
- Threat Model, API & Data Contract
- Stable Version Roadmap
- Testing, Evaluation & Release Gates
- Agent Security & Activity Monitoring Technical Specification

## V0.1 target

V0.1 is the runnable foundation:
- Java 21 + Spring Boot gateway skeleton
- Next.js + React + Tailwind dashboard shell
- MySQL 8.x local infrastructure
- Flyway migration baseline
- health/readiness endpoints
- initial task/session/activity data model
- application smoke-test baseline
- no fake authorization or security claims

## Security boundaries

The dashboard is not an enforcement point. Future protected tool execution must pass through the gateway. The backend owns authorization decisions. A frontend control must never be treated as security enforcement.

## Deliberately deferred

V0.2 introduces the protected gateway, request normalization, tool manifest registry, adapter authorization context and deterministic ALLOW/DENY.

V0.3 introduces Task Contracts and deterministic policy rules.

V0.4 introduces provenance and sensitivity propagation.

V0.5 introduces risk, approval lifecycle and quarantine.

V0.6 introduces attack evaluation and metrics.

V0.7 introduces the full operator dashboard.

V0.8 hardens authentication/authorization, rate limits, secret handling, failure modes and deployment packaging.

V1.0 is released only after the documented gates pass.

## Honesty rule

The repository must never describe an unimplemented control as active protection. No universal agent compatibility, universal prompt-injection detection or whole-system monitoring claim is permitted.
