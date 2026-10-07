package io.intentguard.gateway.provenance;

import java.time.Instant;
import java.util.List;

public record ProvenanceRecord(
        String id,
        String sourceType,
        String trustLevel,
        List<String> parentRefs,
        String sensitivity,
        Instant createdAt
) {}
