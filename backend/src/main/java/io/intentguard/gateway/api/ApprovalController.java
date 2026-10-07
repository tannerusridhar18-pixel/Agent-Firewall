package io.intentguard.gateway.api;

import io.intentguard.gateway.approval.Approval;
import io.intentguard.gateway.approval.ApprovalService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@RestController
@RequestMapping("/api/v1/approvals")
public class ApprovalController {

    private final ApprovalService approvalService;
    private final String configuredOperatorKey;

    public ApprovalController(
            ApprovalService approvalService,
            @Value("${intentguard.control-plane.api-key:intentguard-control-plane-secret-key}") String configuredOperatorKey) {
        this.approvalService = approvalService;
        this.configuredOperatorKey = configuredOperatorKey;
    }

    @PostMapping("/{requestId}/approve")
    public ResponseEntity<Approval> approve(
            @RequestHeader(value = "X-IntentGuard-Operator-Key", required = false) String operatorKey,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId,
            @PathVariable String requestId) {
        authenticate(operatorKey, operatorId);
        try {
            Approval approved = approvalService.approve(operatorId, requestId);
            return ResponseEntity.ok(approved);
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, ex.getMessage(), ex);
        } catch (IllegalStateException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage(), ex);
        }
    }

    @PostMapping("/{requestId}/deny")
    public ResponseEntity<Approval> deny(
            @RequestHeader(value = "X-IntentGuard-Operator-Key", required = false) String operatorKey,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId,
            @PathVariable String requestId) {
        authenticate(operatorKey, operatorId);
        try {
            Approval denied = approvalService.deny(operatorId, requestId);
            return ResponseEntity.ok(denied);
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, ex.getMessage(), ex);
        } catch (IllegalStateException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage(), ex);
        }
    }

    @GetMapping("/{requestId}")
    public ResponseEntity<Approval> get(
            @RequestHeader(value = "X-IntentGuard-Operator-Key", required = false) String operatorKey,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId,
            @PathVariable String requestId) {
        authenticate(operatorKey, operatorId);
        return approvalService.findByRequestId(requestId)
                .map(ResponseEntity::ok)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Approval not found: " + requestId));
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
