package io.intentguard.gateway.policy;

import io.intentguard.gateway.common.Decision;
import io.intentguard.gateway.mcp.ToolManifest;
import io.intentguard.gateway.model.Task;
import io.intentguard.gateway.provenance.ProvenanceResolution;
import io.intentguard.gateway.risk.RiskLevel;
import io.intentguard.gateway.risk.RiskSnapshot;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Service
public class DefaultPolicyEngine implements PolicyEngine {

    @Override
    public Decision evaluate(Task task, String tool, String target) {
        if (task == null) return Decision.DENY;
        if (!"ACTIVE".equals(task.status())) return Decision.DENY;
        if (task.expiresAt() != null && !task.expiresAt().isAfter(Instant.now())) return Decision.DENY;
        if (tool == null || !task.allowedTools().contains(tool)) return Decision.DENY;
        if (task.forbiddenActions().stream().anyMatch(a -> a.equalsIgnoreCase(tool))) return Decision.DENY;
        if (!resourceAllowed(task, target)) return Decision.DENY;
        return Decision.ALLOW;
    }

    @Override
    public PolicyEvaluationResult evaluate(Task task, ToolManifest manifest, String target,
                                           ProvenanceResolution provenance, RiskSnapshot risk) {
        if (task == null) return PolicyEvaluationResult.deny("TASK_NOT_FOUND");
        if (!"ACTIVE".equals(task.status())) return PolicyEvaluationResult.deny("INACTIVE_TASK");
        if (task.expiresAt() != null && !task.expiresAt().isAfter(Instant.now())) {
            return PolicyEvaluationResult.deny("EXPIRED_TASK");
        }
        if (manifest == null) return PolicyEvaluationResult.deny("UNREGISTERED_TOOL");

        String tool = manifest.toolName();
        if (tool == null || !task.allowedTools().contains(tool)) {
            return PolicyEvaluationResult.deny("TOOL_OUTSIDE_TASK_SCOPE");
        }
        if (task.forbiddenActions().stream().anyMatch(a -> a.equalsIgnoreCase(tool))) {
            return PolicyEvaluationResult.deny("FORBIDDEN_ACTION");
        }
        if (!resourceAllowed(task, target)) {
            return PolicyEvaluationResult.deny("RESOURCE_OUTSIDE_TASK_SCOPE");
        }

        if (provenance != null && !provenance.valid()) {
            return PolicyEvaluationResult.deny(provenance.failureReason() != null ? provenance.failureReason() : "UNTRUSTED_PROVENANCE");
        }

        if (risk != null && (risk.level() == RiskLevel.HIGH || risk.level() == RiskLevel.CRITICAL)) {
            return PolicyEvaluationResult.requireApproval(List.of("HIGH_RISK_ACTION_REQUIRES_APPROVAL"));
        }

        return PolicyEvaluationResult.allow();
    }

    private boolean resourceAllowed(Task task, String target) {
        if (target == null || task.allowedResources().isEmpty()) return false;
        return task.allowedResources().stream().anyMatch(scope ->
                scope.endsWith("*")
                        ? target.startsWith(scope.substring(0, scope.length() - 1))
                        : target.equals(scope));
    }
}