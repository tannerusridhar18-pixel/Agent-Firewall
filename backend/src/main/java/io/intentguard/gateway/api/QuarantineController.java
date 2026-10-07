package io.intentguard.gateway.api;

import io.intentguard.gateway.quarantine.QuarantineRecord;
import io.intentguard.gateway.quarantine.QuarantineService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@RestController
@RequestMapping("/api/v1/sessions/{sessionId}")
public class QuarantineController {

    private final QuarantineService quarantineService;
    private final String configuredOperatorKey;

    public QuarantineController(
            QuarantineService quarantineService,
            @Value("${intentguard.control-plane.api-key:intentguard-control-plane-secret-key}") String configuredOperatorKey) {
        this.quarantineService = quarantineService;
        this.configuredOperatorKey = configuredOperatorKey;
    }

    @PostMapping("/quarantine")
    public ResponseEntity<QuarantineRecord> quarantine(
            @RequestHeader(value = "X-IntentGuard-Operator-Key", required = false) String operatorKey,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId,
            @PathVariable String sessionId,
            @RequestBody(required = false) QuarantineRequest body) {
        authenticate(operatorKey, operatorId);
        String reason = (body != null && body.reason() != null) ? body.reason() : "MANUAL_OPERATOR_QUARANTINE";
        String restrictions = (body != null && body.restrictions() != null) ? body.restrictions() : null;

        QuarantineRecord record = quarantineService.quarantine(sessionId, reason, operatorId, restrictions);
        return ResponseEntity.ok(record);
    }

    @PostMapping("/unquarantine")
    public ResponseEntity<Void> unquarantine(
            @RequestHeader(value = "X-IntentGuard-Operator-Key", required = false) String operatorKey,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId,
            @PathVariable String sessionId) {
        authenticate(operatorKey, operatorId);
        quarantineService.unquarantine(sessionId, operatorId);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/quarantine")
    public ResponseEntity<QuarantineRecord> getQuarantine(
            @RequestHeader(value = "X-IntentGuard-Operator-Key", required = false) String operatorKey,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId,
            @PathVariable String sessionId) {
        authenticate(operatorKey, operatorId);
        return quarantineService.getActiveQuarantine(sessionId)
                .map(ResponseEntity::ok)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Session is not actively quarantined"));
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

    public record QuarantineRequest(String reason, String restrictions) {}
}
