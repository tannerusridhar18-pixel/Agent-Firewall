package io.intentguard.gateway.model;
import java.time.Instant;
public record AgentSession(String sessionId,String agentId,String agentVersion,String taskId,String status,String policyVersion,Instant startedAt,Instant endedAt,Instant lastActivityAt) {}