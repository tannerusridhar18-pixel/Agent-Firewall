package io.intentguard.gateway.provenance;

import io.intentguard.gateway.mcp.ToolManifest;
import io.intentguard.gateway.model.Task;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class ProvenanceService {
    private final ProvenanceRepository repository;

    public ProvenanceService(ProvenanceRepository repository) {
        this.repository = repository;
    }

    public ProvenanceRecord record(String id, String sourceType, String trustLevel, List<String> parentRefs, String sensitivity) {
        if (id == null || id.isBlank()) throw new IllegalArgumentException("id is required");
        if (sourceType == null || sourceType.isBlank()) throw new IllegalArgumentException("sourceType is required");
        if (trustLevel == null || trustLevel.isBlank()) trustLevel = "UNTRUSTED";
        if (sensitivity == null || sensitivity.isBlank()) sensitivity = "PUBLIC";

        ProvenanceRecord record = new ProvenanceRecord(id, sourceType, trustLevel, parentRefs, sensitivity, Instant.now());
        repository.insert(record);
        return record;
    }

    public Optional<ProvenanceRecord> findById(String id) {
        return repository.findById(id);
    }

    public ProvenanceResolution resolve(List<String> provenanceRefs, String toolName, String target, ToolManifest manifest, Task task) {
        if (provenanceRefs == null || provenanceRefs.isEmpty()) {
            return ProvenanceResolution.allow("TRUSTED", "PUBLIC", List.of());
        }

        List<ProvenanceRecord> records = new ArrayList<>();
        boolean hasUntrusted = false;
        String highestSensitivity = "PUBLIC";

        for (String ref : provenanceRefs) {
            Optional<ProvenanceRecord> recOpt = repository.findById(ref);
            if (recOpt.isEmpty()) {
                return ProvenanceResolution.deny("INVALID_PROVENANCE_REF");
            }
            ProvenanceRecord rec = recOpt.get();
            records.add(rec);

            if ("UNTRUSTED".equalsIgnoreCase(rec.trustLevel())) {
                hasUntrusted = true;
            }
            highestSensitivity = maxSensitivity(highestSensitivity, rec.sensitivity());
        }

        String aggregateTrust = hasUntrusted ? "UNTRUSTED" : "TRUSTED";

        // Restricted destination check: untrusted content must never flow into side-effecting or egress operations
        if ("UNTRUSTED".equals(aggregateTrust)) {
            if (manifest != null && manifest.sideEffect()) {
                return ProvenanceResolution.deny("UNTRUSTED_PROVENANCE");
            }
            if (toolName != null && (toolName.contains("send") || toolName.contains("post") || toolName.contains("upload") || toolName.contains("email"))) {
                return ProvenanceResolution.deny("UNTRUSTED_PROVENANCE");
            }
        }

        return ProvenanceResolution.allow(aggregateTrust, highestSensitivity, records);
    }

    private String maxSensitivity(String s1, String s2) {
        int rank1 = rank(s1);
        int rank2 = rank(s2);
        return rank1 >= rank2 ? s1 : s2;
    }

    private int rank(String s) {
        if (s == null) return 0;
        return switch (s.toUpperCase()) {
            case "RESTRICTED" -> 3;
            case "CONFIDENTIAL" -> 2;
            case "INTERNAL" -> 1;
            default -> 0;
        };
    }
}
