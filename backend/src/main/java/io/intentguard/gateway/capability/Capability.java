package io.intentguard.gateway.capability;

import java.time.Instant;

public record Capability(
        String id,
        String taskId,
        String toolName,
        String resourceScope,
        String tokenHash,
        String status,
        Instant issuedAt,
        Instant expiresAt,
        Instant revokedAt) {
}
