package io.intentguard.gateway.approval;

import java.time.Instant;

public record Approval(
        String approvalId,
        String requestId,
        String sessionId,
        String taskId,
        String toolName,
        String argumentsHash,
        String status,
        String approverId,
        Instant createdAt,
        Instant expiresAt,
        Instant consumedAt
) {}
