package io.intentguard.gateway.provenance;

import java.util.List;

public record ProvenanceResolution(
        boolean valid,
        String trustLevel,
        String sensitivity,
        String failureReason,
        List<ProvenanceRecord> resolvedRecords
) {
    public static ProvenanceResolution allow(String trustLevel, String sensitivity, List<ProvenanceRecord> records) {
        return new ProvenanceResolution(true, trustLevel, sensitivity, null, records);
    }

    public static ProvenanceResolution deny(String failureReason) {
        return new ProvenanceResolution(false, "UNTRUSTED", "PUBLIC", failureReason, List.of());
    }
}
