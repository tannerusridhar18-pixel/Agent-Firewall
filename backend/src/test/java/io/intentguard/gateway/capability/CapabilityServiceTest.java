package io.intentguard.gateway.capability;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CapabilityServiceTest {

    private CapabilityRepository repository;
    private CapabilityService service;

    @BeforeEach
    void setUp() {
        repository = mock(CapabilityRepository.class);
        service = new CapabilityService(repository);
    }

    @Test
    void issueCreatesActiveCapabilityWithHashedToken() {
        CapabilityService.IssuedCapability issued = service.issue("T-1", "read_file", "workspace/src/*", Duration.ofHours(1));

        assertNotNull(issued);
        assertNotNull(issued.token());
        assertFalse(issued.token().isBlank());

        Capability cap = issued.capability();
        assertNotNull(cap.id());
        assertTrue(cap.id().startsWith("CAP-"));
        assertEquals("T-1", cap.taskId());
        assertEquals("read_file", cap.toolName());
        assertEquals("workspace/src/*", cap.resourceScope());
        assertEquals("ACTIVE", cap.status());
        assertNotNull(cap.issuedAt());
        assertNotNull(cap.expiresAt());
        assertNull(cap.revokedAt());
        assertNotEquals(issued.token(), cap.tokenHash());

        verify(repository).insert(cap);
    }

    @Test
    void issueRejectsInvalidParameters() {
        assertThrows(IllegalArgumentException.class, () -> service.issue(null, "read_file", "scope", Duration.ofHours(1)));
        assertThrows(IllegalArgumentException.class, () -> service.issue("T-1", "", "scope", Duration.ofHours(1)));
        assertThrows(IllegalArgumentException.class, () -> service.issue("T-1", "read_file", null, Duration.ofHours(1)));
        assertThrows(IllegalArgumentException.class, () -> service.issue("T-1", "read_file", "scope", Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> service.issue("T-1", "read_file", "scope", Duration.ofHours(25)));
    }

    @Test
    void validateAllowsValidActiveMatchingCapability() {
        CapabilityService.IssuedCapability issued = service.issue("T-1", "read_file", "workspace/src/*", Duration.ofHours(1));
        when(repository.findByTokenHash(issued.capability().tokenHash())).thenReturn(Optional.of(issued.capability()));

        CapabilityDecision decision = service.validate(issued.token(), "T-1", "read_file", "workspace/src/Auth.java");
        assertTrue(decision.allowed());
        assertEquals("ALLOW", decision.reason());
    }

    @Test
    void validateAllowsExactScopeMatch() {
        CapabilityService.IssuedCapability issued = service.issue("T-1", "read_file", "workspace/README.md", Duration.ofHours(1));
        when(repository.findByTokenHash(issued.capability().tokenHash())).thenReturn(Optional.of(issued.capability()));

        CapabilityDecision decision = service.validate(issued.token(), "T-1", "read_file", "workspace/README.md");
        assertTrue(decision.allowed());
    }

    @Test
    void validateDeniesMissingOrBlankToken() {
        CapabilityDecision d1 = service.validate(null, "T-1", "read_file", "workspace/src/Auth.java");
        assertFalse(d1.allowed());
        assertEquals("CAPABILITY_REQUIRED", d1.reason());

        CapabilityDecision d2 = service.validate("   ", "T-1", "read_file", "workspace/src/Auth.java");
        assertFalse(d2.allowed());
        assertEquals("CAPABILITY_REQUIRED", d2.reason());
    }

    @Test
    void validateDeniesUnrecognizedToken() {
        when(repository.findByTokenHash(anyString())).thenReturn(Optional.empty());

        CapabilityDecision decision = service.validate("unknown-token", "T-1", "read_file", "workspace/src/Auth.java");
        assertFalse(decision.allowed());
        assertEquals("INVALID_CAPABILITY", decision.reason());
    }

    @Test
    void validateDeniesTaskMismatch() {
        CapabilityService.IssuedCapability issued = service.issue("T-OTHER", "read_file", "workspace/src/*", Duration.ofHours(1));
        when(repository.findByTokenHash(issued.capability().tokenHash())).thenReturn(Optional.of(issued.capability()));

        CapabilityDecision decision = service.validate(issued.token(), "T-1", "read_file", "workspace/src/Auth.java");
        assertFalse(decision.allowed());
        assertEquals("CAPABILITY_TASK_MISMATCH", decision.reason());
    }

    @Test
    void validateDeniesToolMismatch() {
        CapabilityService.IssuedCapability issued = service.issue("T-1", "write_file", "workspace/src/*", Duration.ofHours(1));
        when(repository.findByTokenHash(issued.capability().tokenHash())).thenReturn(Optional.of(issued.capability()));

        CapabilityDecision decision = service.validate(issued.token(), "T-1", "read_file", "workspace/src/Auth.java");
        assertFalse(decision.allowed());
        assertEquals("CAPABILITY_TOOL_MISMATCH", decision.reason());
    }

    @Test
    void validateDeniesRevokedCapability() {
        Capability cap = new Capability("CAP-1", "T-1", "read_file", "workspace/src/*", "hash",
                "REVOKED", Instant.now().minusSeconds(100), Instant.now().plusSeconds(3600), Instant.now().minusSeconds(50));
        when(repository.findByTokenHash(anyString())).thenReturn(Optional.of(cap));

        CapabilityDecision decision = service.validate("some-token", "T-1", "read_file", "workspace/src/Auth.java");
        assertFalse(decision.allowed());
        assertEquals("CAPABILITY_REVOKED", decision.reason());
    }

    @Test
    void validateDeniesExpiredCapability() {
        Capability cap = new Capability("CAP-1", "T-1", "read_file", "workspace/src/*", "hash",
                "ACTIVE", Instant.now().minusSeconds(3600), Instant.now().minusSeconds(10), null);
        when(repository.findByTokenHash(anyString())).thenReturn(Optional.of(cap));

        CapabilityDecision decision = service.validate("some-token", "T-1", "read_file", "workspace/src/Auth.java");
        assertFalse(decision.allowed());
        assertEquals("CAPABILITY_EXPIRED", decision.reason());
    }

    @Test
    void validateDeniesTargetOutOfScope() {
        CapabilityService.IssuedCapability issued = service.issue("T-1", "read_file", "workspace/src/*", Duration.ofHours(1));
        when(repository.findByTokenHash(issued.capability().tokenHash())).thenReturn(Optional.of(issued.capability()));

        CapabilityDecision decision = service.validate(issued.token(), "T-1", "read_file", "secrets/passwords.txt");
        assertFalse(decision.allowed());
        assertEquals("CAPABILITY_SCOPE_DENIED", decision.reason());

        CapabilityDecision nullTarget = service.validate(issued.token(), "T-1", "read_file", null);
        assertFalse(nullTarget.allowed());
        assertEquals("CAPABILITY_SCOPE_DENIED", nullTarget.reason());
    }

    @Test
    void revokeUpdatesRepository() {
        service.revoke("CAP-123");
        verify(repository).revoke(eq("CAP-123"), any(Instant.class));
    }
}
