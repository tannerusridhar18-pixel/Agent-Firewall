package io.intentguard.gateway.api;

import io.intentguard.gateway.audit.AuditService;
import io.intentguard.gateway.audit.SecurityDecision;
import io.intentguard.gateway.audit.SecurityEvent;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

@RestController
@RequestMapping("/api/v1")
public class AuditController {

    private final AuditService auditService;
    private final String configuredOperatorKey;

    public AuditController(
            AuditService auditService,
            @Value("${intentguard.control-plane.api-key:intentguard-control-plane-secret-key}") String configuredOperatorKey) {
        this.auditService = auditService;
        this.configuredOperatorKey = configuredOperatorKey;
    }

    @GetMapping("/audit/{requestId}")
    public ResponseEntity<SecurityDecision> getDecision(
            @RequestHeader(value = "X-IntentGuard-Operator-Key", required = false) String operatorKey,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId,
            @PathVariable String requestId) {
        authenticate(operatorKey, operatorId);
        return auditService.findDecisionByRequestId(requestId)
                .map(ResponseEntity::ok)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Security decision not found: " + requestId));
    }

    @GetMapping("/security-events")
    public ResponseEntity<List<SecurityEvent>> listEvents(
            @RequestHeader(value = "X-IntentGuard-Operator-Key", required = false) String operatorKey,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId,
            @RequestParam(defaultValue = "100") int limit) {
        authenticate(operatorKey, operatorId);
        return ResponseEntity.ok(auditService.listSecurityEvents(limit));
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
}
