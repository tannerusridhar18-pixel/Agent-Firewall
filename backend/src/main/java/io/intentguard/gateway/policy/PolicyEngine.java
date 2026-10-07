package io.intentguard.gateway.policy;

import io.intentguard.gateway.common.Decision;
import io.intentguard.gateway.mcp.ToolManifest;
import io.intentguard.gateway.model.Task;
import io.intentguard.gateway.provenance.ProvenanceResolution;
import io.intentguard.gateway.risk.RiskSnapshot;

public interface PolicyEngine {
    Decision evaluate(Task task, String tool, String target);

    PolicyEvaluationResult evaluate(Task task, ToolManifest manifest, String target,
                                    ProvenanceResolution provenance, RiskSnapshot risk);
}