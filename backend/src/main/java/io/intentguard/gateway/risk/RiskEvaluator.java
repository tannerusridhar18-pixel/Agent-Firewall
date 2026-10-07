package io.intentguard.gateway.risk;

import io.intentguard.gateway.mcp.ToolManifest;
import io.intentguard.gateway.model.Task;
import io.intentguard.gateway.provenance.ProvenanceResolution;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class RiskEvaluator {

    public RiskSnapshot evaluate(Task task, ToolManifest manifest, String target, ProvenanceResolution provenance, int recentHardDenials) {
        List<String> factors = new ArrayList<>();

        if (manifest != null) {
            if ("HIGH".equalsIgnoreCase(manifest.riskLevel())) {
                factors.add("HIGH_RISK_TOOL");
            } else if ("MEDIUM".equalsIgnoreCase(manifest.riskLevel())) {
                factors.add("MEDIUM_RISK_TOOL");
            }
            if (manifest.sideEffect()) {
                factors.add("SIDE_EFFECT");
            }
        }

        if (provenance != null) {
            if ("UNTRUSTED".equalsIgnoreCase(provenance.trustLevel())) {
                factors.add("UNTRUSTED_INPUT_PROVENANCE");
            }
            if ("CONFIDENTIAL".equalsIgnoreCase(provenance.sensitivity()) || "RESTRICTED".equalsIgnoreCase(provenance.sensitivity())) {
                factors.add("HIGH_SENSITIVITY_DATA");
            }
        }

        if (recentHardDenials >= 2) {
            factors.add("ELEVATED_SESSION_DENIALS");
        }

        RiskLevel level;
        if (factors.contains("UNTRUSTED_INPUT_PROVENANCE") && factors.contains("SIDE_EFFECT")) {
            level = RiskLevel.CRITICAL;
        } else if (factors.contains("HIGH_RISK_TOOL") && factors.contains("ELEVATED_SESSION_DENIALS")) {
            level = RiskLevel.CRITICAL;
        } else if (factors.contains("HIGH_RISK_TOOL") || (factors.contains("SIDE_EFFECT") && factors.contains("HIGH_SENSITIVITY_DATA")) || factors.contains("ELEVATED_SESSION_DENIALS")) {
            level = RiskLevel.HIGH;
        } else if (factors.contains("SIDE_EFFECT") || factors.contains("MEDIUM_RISK_TOOL")) {
            level = RiskLevel.MEDIUM;
        } else {
            level = RiskLevel.LOW;
        }

        return new RiskSnapshot(level, factors);
    }
}
