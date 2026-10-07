package io.intentguard.gateway.audit;

import java.time.Instant;

public record SecurityEvent(
        String eventId,
        String sessionId,
        String taskId,
        String severity,
        String eventType,
        String requestId,
        String message,
        String metadata,
        Instant createdAt
) {}
