package io.intentguard.gateway.approval;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ApprovalServiceTest {

    private ApprovalRepository repository;
    private ApprovalService service;

    @BeforeEach
    void setUp() {
        repository = mock(ApprovalRepository.class);
        service = new ApprovalService(repository);
    }

    @Test
    void createPendingGeneratesValidRecord() {
        Approval approval = service.createPending("S-1", "T-1", "write_file", "hash123", Duration.ofMinutes(10));
        assertNotNull(approval.approvalId());
        assertNotNull(approval.requestId());
        assertEquals("PENDING", approval.status());
        assertEquals("S-1", approval.sessionId());
        assertEquals("T-1", approval.taskId());
        assertEquals("write_file", approval.toolName());
        assertEquals("hash123", approval.argumentsHash());
        verify(repository).insert(any(Approval.class));
    }

    @Test
    void approveSetsStatusToApproved() {
        Approval pending = new Approval("A-1", "REQ-1", "S-1", "T-1", "write_file", "hash123", "PENDING", null,
                Instant.now(), Instant.now().plusSeconds(600), null);
        when(repository.findByRequestId("REQ-1")).thenReturn(Optional.of(pending));
        when(repository.updateStatus("REQ-1", "APPROVED", "operator-1")).thenReturn(true);

        Approval approved = new Approval("A-1", "REQ-1", "S-1", "T-1", "write_file", "hash123", "APPROVED", "operator-1",
                pending.createdAt(), pending.expiresAt(), null);
        when(repository.findByRequestId("REQ-1")).thenReturn(Optional.of(pending), Optional.of(approved));

        Approval result = service.approve("operator-1", "REQ-1");
        assertEquals("APPROVED", result.status());
        assertEquals("operator-1", result.approverId());
    }

    @Test
    void denySetsStatusToDenied() {
        Approval pending = new Approval("A-1", "REQ-1", "S-1", "T-1", "write_file", "hash123", "PENDING", null,
                Instant.now(), Instant.now().plusSeconds(600), null);
        when(repository.findByRequestId("REQ-1")).thenReturn(Optional.of(pending));
        when(repository.updateStatus("REQ-1", "DENIED", "operator-1")).thenReturn(true);

        Approval denied = new Approval("A-1", "REQ-1", "S-1", "T-1", "write_file", "hash123", "DENIED", "operator-1",
                pending.createdAt(), pending.expiresAt(), null);
        when(repository.findByRequestId("REQ-1")).thenReturn(Optional.of(pending), Optional.of(denied));

        Approval result = service.deny("operator-1", "REQ-1");
        assertEquals("DENIED", result.status());
    }

    @Test
    void validateAndConsumeSucceedsForValidApprovedRequest() {
        Approval approved = new Approval("A-1", "REQ-1", "S-1", "T-1", "write_file", "hash123", "APPROVED", "operator-1",
                Instant.now().minusSeconds(10), Instant.now().plusSeconds(600), null);
        when(repository.findByRequestId("REQ-1")).thenReturn(Optional.of(approved));
        when(repository.consumeAtomic(eq("REQ-1"), any(Instant.class), any(Instant.class))).thenReturn(true);

        var result = service.validateAndConsume("REQ-1", "S-1", "T-1", "write_file", "hash123");
        assertTrue(result.allowed());
        assertEquals("APPROVED", result.reason());
        verify(repository).consumeAtomic(eq("REQ-1"), any(Instant.class), any(Instant.class));
    }

    @Test
    void validateAndConsumeFailsForMismatchedArgumentHash() {
        Approval approved = new Approval("A-1", "REQ-1", "S-1", "T-1", "write_file", "hash123", "APPROVED", "operator-1",
                Instant.now().minusSeconds(10), Instant.now().plusSeconds(600), null);
        when(repository.findByRequestId("REQ-1")).thenReturn(Optional.of(approved));

        var result = service.validateAndConsume("REQ-1", "S-1", "T-1", "write_file", "differentHash");
        assertFalse(result.allowed());
        assertEquals("APPROVAL_ARGUMENT_MISMATCH", result.reason());
        verify(repository, never()).consumeAtomic(anyString(), any(Instant.class), any(Instant.class));
    }

    @Test
    void validateAndConsumeFailsForExpiredApproval() {
        Approval expired = new Approval("A-1", "REQ-1", "S-1", "T-1", "write_file", "hash123", "APPROVED", "operator-1",
                Instant.now().minusSeconds(600), Instant.now().minusSeconds(10), null);
        when(repository.findByRequestId("REQ-1")).thenReturn(Optional.of(expired));

        var result = service.validateAndConsume("REQ-1", "S-1", "T-1", "write_file", "hash123");
        assertFalse(result.allowed());
        assertEquals("APPROVAL_EXPIRED", result.reason());
        verify(repository, never()).consumeAtomic(anyString(), any(Instant.class), any(Instant.class));
    }

    @Test
    void validateAndConsumeFailsOnReplayWhenAlreadyConsumed() {
        Approval consumed = new Approval("A-1", "REQ-1", "S-1", "T-1", "write_file", "hash123", "CONSUMED", "operator-1",
                Instant.now().minusSeconds(60), Instant.now().plusSeconds(500), Instant.now().minusSeconds(10));
        when(repository.findByRequestId("REQ-1")).thenReturn(Optional.of(consumed));

        var result = service.validateAndConsume("REQ-1", "S-1", "T-1", "write_file", "hash123");
        assertFalse(result.allowed());
        assertEquals("APPROVAL_ALREADY_CONSUMED", result.reason());
        verify(repository, never()).consumeAtomic(anyString(), any(Instant.class), any(Instant.class));
    }
}
