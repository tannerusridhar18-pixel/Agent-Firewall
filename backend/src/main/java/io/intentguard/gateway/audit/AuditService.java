package io.intentguard.gateway.audit;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class AuditService {
    private final SecurityDecisionRepository decisions;
    private final SecurityEventRepository events;

    public AuditService(SecurityDecisionRepository decisions, SecurityEventRepository events) {
        this.decisions = decisions;
        this.events = events;
    }

    public SecurityDecision recordDecision(SecurityDecision decision) {
        // Fail-closed invariant: repository exceptions propagate and abort downstream tool execution
        decisions.insert(decision);
        return decision;
    }

    public Optional<SecurityDecision> findDecisionByRequestId(String requestId) {
        return decisions.findByRequestId(requestId);
    }

    public List<SecurityDecision> listRecentDecisions(int limit) {
        return decisions.listRecent(limit);
    }

    public void recordSecurityEvent(String sessionId, String taskId, String severity, String eventType,
                                    String requestId, String message, String metadata) {
        SecurityEvent event = new SecurityEvent(
                "EVT-" + UUID.randomUUID(),
                sessionId,
                taskId,
                severity,
                eventType,
                requestId,
                message,
                metadata,
                Instant.now()
        );
        events.insert(event);
    }

    public List<SecurityEvent> listSecurityEvents(int limit) {
        return events.listRecent(limit);
    }

    public List<SecurityEvent> findEventsBySessionId(String sessionId) {
        return events.findBySessionId(sessionId);
    }

    public int countRecentHardDenials(String sessionId, int limit) {
        return decisions.countRecentHardDenials(sessionId, limit);
    }
}
