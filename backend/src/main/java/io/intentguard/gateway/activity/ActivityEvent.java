package io.intentguard.gateway.activity;

import java.time.Instant;

public record ActivityEvent(
        String eventId,
        String sessionId,
        String taskId,
        String activityType,
        String source,
        String target,
        Instant timestamp
) {}
