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

    public record SecuritySummary(
            long totalAnalyzed,
            long allowedRequests,
            long flaggedRequests,
            long blockedRequests,
            java.util.Map<String, Long> threatCategories,
            java.util.Map<String, Long> riskLevels,
            List<SecurityEvent> recentEvents
    ) {}

    public SecuritySummary getSecuritySummary() {
        List<SecurityDecision> recent = decisions.listRecent(500);
        long total = recent.size();
        long allowed = recent.stream().filter(d -> "ALLOW".equalsIgnoreCase(d.decision())).count();
        long flagged = recent.stream().filter(d -> "REQUIRE_APPROVAL".equalsIgnoreCase(d.decision())).count();
        long blocked = recent.stream().filter(d -> "DENY".equalsIgnoreCase(d.decision())).count();

        java.util.Map<String, Long> threatCategories = new java.util.LinkedHashMap<>();
        java.util.Map<String, Long> riskLevels = new java.util.LinkedHashMap<>();

        for (SecurityDecision d : recent) {
            String level = d.riskLevel() != null ? d.riskLevel() : "LOW";
            riskLevels.put(level, riskLevels.getOrDefault(level, 0L) + 1);

            List<String> factors = d.riskFactors();
            if (factors != null) {
                for (String f : factors) {
                    if (!f.equals("SECURITY_AGENT_FLAG") && !f.equals("THREAT_DETECTED") && !f.equals("HIGH_RISK_TOOL") && !f.equals("SIDE_EFFECT")) {
                        threatCategories.put(f, threatCategories.getOrDefault(f, 0L) + 1);
                    }
                }
            }
        }

        List<SecurityEvent> recentEvts = events.listRecent(20);
        return new SecuritySummary(total, allowed, flagged, blocked, threatCategories, riskLevels, recentEvts);
    }
}
