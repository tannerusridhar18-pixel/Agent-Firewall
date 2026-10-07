package io.intentguard.gateway.quarantine;

import java.time.Instant;

public record QuarantineRecord(
        String quarantineId,
        String sessionId,
        String reason,
        String restrictions,
        String quarantinedBy,
        boolean active,
        Instant quarantinedAt,
        Instant releasedAt
) {}
