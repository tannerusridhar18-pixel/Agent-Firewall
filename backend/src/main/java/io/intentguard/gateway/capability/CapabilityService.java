package io.intentguard.gateway.capability;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class CapabilityService {
    private static final Duration MAX_TTL = Duration.ofHours(24);
    private final SecureRandom random = new SecureRandom();
    private final CapabilityRepository repository;

    public CapabilityService(CapabilityRepository repository) {
        this.repository = repository;
    }

    public IssuedCapability issue(String taskId, String toolName, String resourceScope, Duration ttl) {
        if (taskId == null || taskId.isBlank()) throw new IllegalArgumentException("taskId is required");
        if (toolName == null || toolName.isBlank()) throw new IllegalArgumentException("toolName is required");
        if (resourceScope == null || resourceScope.isBlank()) throw new IllegalArgumentException("resourceScope is required");
        if (ttl == null || ttl.isZero() || ttl.isNegative() || ttl.compareTo(MAX_TTL) > 0) {
            throw new IllegalArgumentException("ttl must be between 1 second and 24 hours");
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

    public void revoke(String capabilityId) {
        repository.revoke(capabilityId, Instant.now());
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
}
