package io.intentguard.gateway.api;

import io.intentguard.gateway.capability.Capability;
import io.intentguard.gateway.capability.CapabilityService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

@RestController
@RequestMapping("/api/v1/control-plane/capabilities")
public class CapabilityControlPlaneController {

    private final CapabilityService capabilityService;
    private final String configuredOperatorKey;

    public CapabilityControlPlaneController(
            CapabilityService capabilityService,
            @Value("${intentguard.control-plane.api-key:intentguard-control-plane-secret-key}") String configuredOperatorKey) {
        this.capabilityService = capabilityService;
        this.configuredOperatorKey = configuredOperatorKey;
    }

    @PostMapping
    public ResponseEntity<IssueResponse> issue(
            @RequestHeader(value = "X-IntentGuard-Operator-Key", required = false) String operatorKey,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId,
            @Valid @RequestBody IssueRequest request) {
        authenticate(operatorKey, operatorId);

        Duration ttl = request.ttlSeconds() == null ? Duration.ofHours(1) : Duration.ofSeconds(request.ttlSeconds());
        try {
            var issued = capabilityService.issue(operatorId, request.taskId(), request.toolName(), request.resourceScope(), ttl);
            Capability c = issued.capability();
            return ResponseEntity.status(HttpStatus.CREATED).body(new IssueResponse(
                    c.id(), c.taskId(), c.toolName(), c.resourceScope(), c.status(),
                    c.issuedAt(), c.expiresAt(), issued.token()));
        } catch (SecurityException ex) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, ex.getMessage(), ex);
        } catch (IllegalArgumentException | IllegalStateException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage(), ex);
        }
    }

    @PostMapping("/{capabilityId}/rotate")
    public ResponseEntity<RotateResponse> rotate(
            @RequestHeader(value = "X-IntentGuard-Operator-Key", required = false) String operatorKey,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId,
            @PathVariable String capabilityId,
            @RequestBody(required = false) RotateRequest request) {
        authenticate(operatorKey, operatorId);

        Duration ttl = (request != null && request.ttlSeconds() != null) ? Duration.ofSeconds(request.ttlSeconds()) : null;
        try {
            var rotated = capabilityService.rotate(operatorId, capabilityId, ttl);
            Capability c = rotated.capability();
            return ResponseEntity.ok(new RotateResponse(
                    c.id(), rotated.rotatedFromId(), c.taskId(), c.toolName(),
                    c.resourceScope(), c.status(), c.issuedAt(), c.expiresAt(), rotated.token()));
        } catch (SecurityException ex) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, ex.getMessage(), ex);
        } catch (IllegalArgumentException ex) {
            if (ex.getMessage() != null && ex.getMessage().contains("not found")) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, ex.getMessage(), ex);
            }
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage(), ex);
        } catch (IllegalStateException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage(), ex);
        }
    }

    @PostMapping("/{capabilityId}/revoke")
    public ResponseEntity<RevokeResponse> revoke(
            @RequestHeader(value = "X-IntentGuard-Operator-Key", required = false) String operatorKey,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId,
            @PathVariable String capabilityId) {
        authenticate(operatorKey, operatorId);

        try {
            capabilityService.revoke(operatorId, capabilityId);
            return ResponseEntity.ok(new RevokeResponse(capabilityId, "REVOKED", Instant.now()));
        } catch (SecurityException ex) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, ex.getMessage(), ex);
        } catch (IllegalArgumentException ex) {
            if (ex.getMessage() != null && ex.getMessage().contains("not found")) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, ex.getMessage(), ex);
            }
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage(), ex);
        }
    }

    @GetMapping("/{capabilityId}")
    public ResponseEntity<CapabilityMetadata> get(
            @RequestHeader(value = "X-IntentGuard-Operator-Key", required = false) String operatorKey,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId,
            @PathVariable String capabilityId) {
        authenticate(operatorKey, operatorId);

        return capabilityService.findById(capabilityId)
                .map(c -> ResponseEntity.ok(new CapabilityMetadata(
                        c.id(), c.taskId(), c.toolName(), c.resourceScope(),
                        c.status(), c.issuedAt(), c.expiresAt(), c.revokedAt())))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Capability not found: " + capabilityId));
    }

    @GetMapping
    public ResponseEntity<List<CapabilityMetadata>> listByTask(
            @RequestHeader(value = "X-IntentGuard-Operator-Key", required = false) String operatorKey,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId,
            @RequestParam String taskId) {
        authenticate(operatorKey, operatorId);

        var list = capabilityService.findByTaskId(taskId).stream()
                .map(c -> new CapabilityMetadata(
                        c.id(), c.taskId(), c.toolName(), c.resourceScope(),
                        c.status(), c.issuedAt(), c.expiresAt(), c.revokedAt()))
                .toList();
        return ResponseEntity.ok(list);
    }

    private void authenticate(String operatorKey, String operatorId) {
        if (operatorKey == null || operatorKey.isBlank() ||
                !MessageDigest.isEqual(operatorKey.getBytes(StandardCharsets.UTF_8), configuredOperatorKey.getBytes(StandardCharsets.UTF_8))) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or missing operator key");
        }
        if (operatorId == null || operatorId.isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Operator identity is required");
        }
    }

    public record IssueRequest(
            @NotBlank String taskId,
            @NotBlank String toolName,
            @NotBlank String resourceScope,
            Long ttlSeconds) {
    }

    public record IssueResponse(
            String capabilityId,
            String taskId,
            String toolName,
            String resourceScope,
            String status,
            Instant issuedAt,
            Instant expiresAt,
            String token) {
    }

    public record RotateRequest(Long ttlSeconds) {
    }

    public record RotateResponse(
            String capabilityId,
            String rotatedFromId,
            String taskId,
            String toolName,
            String resourceScope,
            String status,
            Instant issuedAt,
            Instant expiresAt,
            String token) {
    }

    public record RevokeResponse(String capabilityId, String status, Instant revokedAt) {
    }

    public record CapabilityMetadata(
            String capabilityId,
            String taskId,
            String toolName,
            String resourceScope,
            String status,
            Instant issuedAt,
            Instant expiresAt,
            Instant revokedAt) {
    }
}
