package io.intentguard.gateway.capability;

import io.intentguard.gateway.mcp.McpToolRegistry;
import io.intentguard.gateway.model.Task;
import io.intentguard.gateway.repository.TaskRepository;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class CapabilityService {
    private static final Duration MAX_TTL = Duration.ofHours(24);
    private final SecureRandom random = new SecureRandom();
    private final CapabilityRepository repository;
    private final TaskRepository tasks;
    private final McpToolRegistry registry;

    @org.springframework.beans.factory.annotation.Autowired
    public CapabilityService(CapabilityRepository repository, TaskRepository tasks, McpToolRegistry registry) {
        this.repository = repository;
        this.tasks = tasks;
        this.registry = registry;
    }

    public CapabilityService(CapabilityRepository repository) {
        this(repository, null, null);
    }

    public IssuedCapability issue(String operatorId, String taskId, String toolName, String resourceScope, Duration ttl) {
        if (operatorId == null || operatorId.isBlank()) {
            throw new IllegalArgumentException("operatorId is required");
        }
        if (taskId == null || taskId.isBlank()) {
            throw new IllegalArgumentException("taskId is required");
        }
        if (toolName == null || toolName.isBlank()) {
            throw new IllegalArgumentException("toolName is required");
        }
        if (resourceScope == null || resourceScope.isBlank()) {
            throw new IllegalArgumentException("resourceScope is required");
        }
        if (ttl == null || ttl.isZero() || ttl.isNegative() || ttl.compareTo(MAX_TTL) > 0) {
            throw new IllegalArgumentException("ttl must be between 1 second and 24 hours");
        }

        if (tasks != null) {
            Task task = tasks.find(taskId);
            if (task == null) {
                throw new IllegalArgumentException("Task not found: " + taskId);
            }
            if (!"ACTIVE".equals(task.status())) {
                throw new IllegalStateException("Task is not active: " + task.status());
            }
            if (task.expiresAt() != null && !task.expiresAt().isAfter(Instant.now())) {
                throw new IllegalStateException("Task has expired");
            }
            if (!operatorId.equals(task.actorId()) && !"system".equalsIgnoreCase(operatorId) && !"admin".equalsIgnoreCase(operatorId)) {
                throw new SecurityException("Operator " + operatorId + " is not authorized for task " + taskId);
            }
            if (task.allowedTools() == null || !task.allowedTools().contains(toolName)) {
                throw new IllegalArgumentException("Tool " + toolName + " is not permitted by task");
            }
            if (task.allowedResources() == null || !isScopePermitted(task.allowedResources(), resourceScope)) {
                throw new IllegalArgumentException("Resource scope " + resourceScope + " is not permitted by task");
            }
            if (task.expiresAt() != null && Instant.now().plus(ttl).isAfter(task.expiresAt())) {
                throw new IllegalArgumentException("Capability TTL cannot exceed task expiration");
            }
        }

        if (registry != null) {
            if (registry.findEnabled(toolName).isEmpty()) {
                throw new IllegalArgumentException("Tool " + toolName + " is not registered or enabled");
            }
        }

        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        Instant issuedAt = Instant.now();
        Capability capability = new Capability(
                "CAP-" + UUID.randomUUID(),
                taskId,
                toolName,
                resourceScope,
                hash(token),
                "ACTIVE",
                issuedAt,
                issuedAt.plus(ttl),
                null);
        repository.insert(capability);
        return new IssuedCapability(capability, token);
    }

    public IssuedCapability issue(String taskId, String toolName, String resourceScope, Duration ttl) {
        return issue("system", taskId, toolName, resourceScope, ttl);
    }

    public RotatedCapability rotate(String operatorId, String capabilityId, Duration ttl) {
        if (operatorId == null || operatorId.isBlank()) {
            throw new IllegalArgumentException("operatorId is required");
        }
        if (capabilityId == null || capabilityId.isBlank()) {
            throw new IllegalArgumentException("capabilityId is required");
        }

        Capability previous = repository.findById(capabilityId)
                .orElseThrow(() -> new IllegalArgumentException("Capability not found: " + capabilityId));

        if (!"ACTIVE".equals(previous.status())) {
            throw new IllegalStateException("Cannot rotate capability with status: " + previous.status());
        }
        if (!previous.expiresAt().isAfter(Instant.now())) {
            throw new IllegalStateException("Cannot rotate expired capability");
        }

        if (tasks != null) {
            Task task = tasks.find(previous.taskId());
            if (task != null && !operatorId.equals(task.actorId()) && !"system".equalsIgnoreCase(operatorId) && !"admin".equalsIgnoreCase(operatorId)) {
                throw new SecurityException("Operator " + operatorId + " is not authorized for task " + previous.taskId());
            }
        }

        Duration replacementTtl = ttl;
        if (replacementTtl == null) {
            replacementTtl = Duration.between(previous.issuedAt(), previous.expiresAt());
        }

        // Revoke previous capability immediately to prevent reuse
        repository.revoke(previous.id(), Instant.now());

        // Issue new replacement capability
        IssuedCapability replacement = issue(operatorId, previous.taskId(), previous.toolName(), previous.resourceScope(), replacementTtl);
        return new RotatedCapability(previous.id(), replacement.capability(), replacement.token());
    }

    public CapabilityDecision validate(String rawToken, String taskId, String toolName, String target) {
        if (rawToken == null || rawToken.isBlank()) return CapabilityDecision.deny("CAPABILITY_REQUIRED");

        var capability = repository.findByTokenHash(hash(rawToken));
        if (capability.isEmpty()) return CapabilityDecision.deny("INVALID_CAPABILITY");

        Capability c = capability.get();
        Instant now = Instant.now();

        if (!c.taskId().equals(taskId)) return CapabilityDecision.deny("CAPABILITY_TASK_MISMATCH");
        if (!c.toolName().equals(toolName)) return CapabilityDecision.deny("CAPABILITY_TOOL_MISMATCH");
        if (!"ACTIVE".equals(c.status())) return CapabilityDecision.deny("CAPABILITY_REVOKED");
        if (!c.expiresAt().isAfter(now)) return CapabilityDecision.deny("CAPABILITY_EXPIRED");
        if (target == null || !scopeAllows(c.resourceScope(), target)) {
            return CapabilityDecision.deny("CAPABILITY_SCOPE_DENIED");
        }

        return CapabilityDecision.allow();
    }

    public void revoke(String operatorId, String capabilityId) {
        if (operatorId == null || operatorId.isBlank()) {
            throw new IllegalArgumentException("operatorId is required");
        }
        if (capabilityId == null || capabilityId.isBlank()) {
            throw new IllegalArgumentException("capabilityId is required");
        }

        Capability cap = repository.findById(capabilityId)
                .orElseThrow(() -> new IllegalArgumentException("Capability not found: " + capabilityId));

        if (tasks != null) {
            Task task = tasks.find(cap.taskId());
            if (task != null && !operatorId.equals(task.actorId()) && !"system".equalsIgnoreCase(operatorId) && !"admin".equalsIgnoreCase(operatorId)) {
                throw new SecurityException("Operator " + operatorId + " is not authorized for task " + cap.taskId());
            }
        }

        repository.revoke(capabilityId, Instant.now());
    }

    public void revoke(String capabilityId) {
        repository.revoke(capabilityId, Instant.now());
    }

    public Optional<Capability> findById(String capabilityId) {
        return repository.findById(capabilityId);
    }

    public List<Capability> findByTaskId(String taskId) {
        return repository.findByTaskId(taskId);
    }

    private boolean isScopePermitted(List<String> allowedResources, String requestedScope) {
        if (allowedResources == null || allowedResources.isEmpty()) return false;
        return allowedResources.stream().anyMatch(allowed -> {
            if (allowed.endsWith("*")) {
                String prefix = allowed.substring(0, allowed.length() - 1);
                return requestedScope.startsWith(prefix);
            } else {
                return requestedScope.equals(allowed);
            }
        });
    }

    private boolean scopeAllows(String scope, String target) {
        return scope.endsWith("*")
                ? target.startsWith(scope.substring(0, scope.length() - 1))
                : target.equals(scope);
    }

    private String hash(String token) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256")
                            .digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("Unable to hash capability token", e);
        }
    }

    public record IssuedCapability(Capability capability, String token) {
    }

    public record RotatedCapability(String rotatedFromId, Capability capability, String token) {
    }
}
