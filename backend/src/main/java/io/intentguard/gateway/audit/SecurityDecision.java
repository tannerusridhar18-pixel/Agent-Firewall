package io.intentguard.gateway.audit;

import java.time.Instant;
import java.util.List;

public record SecurityDecision(
        String decisionId,
        String requestId,
        String sessionId,
        String taskId,
        String toolName,
        String argumentsHash,
        List<String> provenanceRefs,
        String decision,
        List<String> reasonCodes,
        String riskLevel,
        List<String> riskFactors,
        String policyVersion,
        String approvalId,
        boolean executed,
        Instant createdAt
) {}
