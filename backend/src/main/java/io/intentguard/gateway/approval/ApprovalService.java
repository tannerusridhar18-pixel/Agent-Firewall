package io.intentguard.gateway.approval;

import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class ApprovalService {
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(15);
    private final ApprovalRepository repository;

    public ApprovalService(ApprovalRepository repository) {
        this.repository = repository;
    }

    public Approval createPending(String sessionId, String taskId, String toolName, String argumentsHash, Duration ttl) {
        if (ttl == null || ttl.isZero() || ttl.isNegative()) {
            ttl = DEFAULT_TTL;
        }

        Instant now = Instant.now();
        Approval approval = new Approval(
                "APP-" + UUID.randomUUID(),
                "REQ-" + UUID.randomUUID(),
                sessionId,
                taskId,
                toolName,
                argumentsHash,
                "PENDING",
                null,
                now,
                now.plus(ttl),
                null
        );
        repository.insert(approval);
        return approval;
    }

    public Approval approve(String operatorId, String requestId) {
        if (operatorId == null || operatorId.isBlank()) {
            throw new IllegalArgumentException("operatorId is required");
        }
        Approval approval = repository.findByRequestId(requestId)
                .orElseThrow(() -> new IllegalArgumentException("Approval request not found: " + requestId));

        if (!"PENDING".equals(approval.status())) {
            throw new IllegalStateException("Approval is not pending: " + approval.status());
        }
        if (!approval.expiresAt().isAfter(Instant.now())) {
            throw new IllegalStateException("Approval request has expired");
        }

        boolean updated = repository.updateStatus(requestId, "APPROVED", operatorId);
        if (!updated) {
            throw new IllegalStateException("Failed to approve request: status may have changed");
        }
        return repository.findByRequestId(requestId).orElseThrow();
    }

    public Approval deny(String operatorId, String requestId) {
        if (operatorId == null || operatorId.isBlank()) {
            throw new IllegalArgumentException("operatorId is required");
        }
        Approval approval = repository.findByRequestId(requestId)
                .orElseThrow(() -> new IllegalArgumentException("Approval request not found: " + requestId));

        if (!"PENDING".equals(approval.status())) {
            throw new IllegalStateException("Approval is not pending: " + approval.status());
        }

        boolean updated = repository.updateStatus(requestId, "DENIED", operatorId);
        if (!updated) {
            throw new IllegalStateException("Failed to deny request: status may have changed");
        }
        return repository.findByRequestId(requestId).orElseThrow();
    }

    public Optional<Approval> findByRequestId(String requestId) {
        return repository.findByRequestId(requestId);
    }

    public ApprovalResult validateAndConsume(String requestId, String sessionId, String taskId, String toolName, String argumentsHash) {
        if (requestId == null || requestId.isBlank()) {
            return ApprovalResult.deny("APPROVAL_REQUIRED");
        }

        Optional<Approval> opt = repository.findByRequestId(requestId);
        if (opt.isEmpty()) {
            return ApprovalResult.deny("APPROVAL_NOT_FOUND");
        }

        Approval approval = opt.get();
        Instant now = Instant.now();

        if (!approval.sessionId().equals(sessionId)) {
            return ApprovalResult.deny("APPROVAL_SESSION_MISMATCH");
        }
        if (!approval.taskId().equals(taskId)) {
            return ApprovalResult.deny("APPROVAL_TASK_MISMATCH");
        }
        if (!approval.toolName().equals(toolName)) {
            return ApprovalResult.deny("APPROVAL_TOOL_MISMATCH");
        }
        if (!approval.argumentsHash().equals(argumentsHash)) {
            return ApprovalResult.deny("APPROVAL_ARGUMENT_MISMATCH");
        }
        if ("CONSUMED".equals(approval.status())) {
            return ApprovalResult.deny("APPROVAL_ALREADY_CONSUMED");
        }
        if ("DENIED".equals(approval.status())) {
            return ApprovalResult.deny("APPROVAL_DENIED");
        }
        if (!approval.expiresAt().isAfter(now)) {
            return ApprovalResult.deny("APPROVAL_EXPIRED");
        }
        if (!"APPROVED".equals(approval.status())) {
            return ApprovalResult.deny("APPROVAL_NOT_APPROVED");
        }

        boolean consumed = repository.consumeAtomic(requestId, now, now);
        if (!consumed) {
            return ApprovalResult.deny("APPROVAL_ALREADY_CONSUMED");
        }

        return ApprovalResult.allow(approval);
    }

    public record ApprovalResult(boolean allowed, String reason, Approval approval) {
        public static ApprovalResult allow(Approval approval) {
            return new ApprovalResult(true, "APPROVED", approval);
        }
        public static ApprovalResult deny(String reason) {
            return new ApprovalResult(false, reason, null);
        }
    }
}
