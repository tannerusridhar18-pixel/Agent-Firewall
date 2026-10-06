package io.intentguard.gateway.audit;

import java.time.Instant;
import io.intentguard.gateway.common.Decision;

public record AuditRecord(
        String requestId,
        String sessionId,
        String taskId,
        String activityType,
        String target,
        Decision decision,
        String reason,
        Instant timestamp
) {}