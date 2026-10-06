package io.intentguard.gateway.policy;

import io.intentguard.gateway.common.Decision;
import io.intentguard.gateway.model.Task;
import org.springframework.stereotype.Service;

import java.time.Instant;

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

    private boolean resourceAllowed(Task task, String target) {
        if (target == null || task.allowedResources().isEmpty()) return false;
        return task.allowedResources().stream().anyMatch(scope ->
                scope.endsWith("*")
                        ? target.startsWith(scope.substring(0, scope.length() - 1))
                        : target.equals(scope));
    }
}