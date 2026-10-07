package io.intentguard.gateway.capability;

import io.intentguard.gateway.mcp.McpToolRegistry;
import io.intentguard.gateway.mcp.ToolManifest;
import io.intentguard.gateway.model.Task;
import io.intentguard.gateway.repository.TaskRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class CapabilityServiceTest {

    private CapabilityRepository repository;
    private TaskRepository tasks;
    private McpToolRegistry registry;
    private CapabilityService service;

    private Task activeTask() {
        return new Task("T-1", "operator-1", "Read code",
                List.of("read_file"),
                List.of("workspace/src/*", "workspace/README.md"),
                List.of("delete"),
                "ACTIVE",
                Instant.now().plus(Duration.ofHours(5)),
                Instant.now());
    }

    @BeforeEach
    void setUp() {
        repository = mock(CapabilityRepository.class);
        tasks = mock(TaskRepository.class);
        registry = mock(McpToolRegistry.class);
        service = new CapabilityService(repository, tasks, registry);

        when(tasks.find("T-1")).thenReturn(activeTask());
        when(registry.findEnabled("read_file")).thenReturn(Optional.of(
                new ToolManifest("read_file", "demo-server", "Read tool", "{}", true)));
    }

    @Test
    void issueCreatesActiveCapabilityWithHashedToken() {
        CapabilityService.IssuedCapability issued = service.issue("operator-1", "T-1", "read_file", "workspace/src/*", Duration.ofHours(1));

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
        assertEquals(64, cap.tokenHash().length()); // SHA-256 hex string

        verify(repository).insert(cap);
    }

    @Test
    void issueRejectsInvalidParameters() {
        assertThrows(IllegalArgumentException.class, () -> service.issue("operator-1", null, "read_file", "workspace/src/*", Duration.ofHours(1)));
        assertThrows(IllegalArgumentException.class, () -> service.issue("operator-1", "T-1", "", "workspace/src/*", Duration.ofHours(1)));
        assertThrows(IllegalArgumentException.class, () -> service.issue("operator-1", "T-1", "read_file", null, Duration.ofHours(1)));
        assertThrows(IllegalArgumentException.class, () -> service.issue("operator-1", "T-1", "read_file", "workspace/src/*", Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> service.issue("operator-1", "T-1", "read_file", "workspace/src/*", Duration.ofHours(25)));
        assertThrows(IllegalArgumentException.class, () -> service.issue("", "T-1", "read_file", "workspace/src/*", Duration.ofHours(1)));
    }

    @Test
    void issueRejectsUnauthorizedOperator() {
        assertThrows(SecurityException.class, () ->
                service.issue("hacker", "T-1", "read_file", "workspace/src/*", Duration.ofHours(1)));
    }

    @Test
    void issueRejectsInactiveTask() {
        Task inactive = new Task("T-INACTIVE", "operator-1", "Read", List.of("read_file"), List.of("workspace/*"),
                List.of(), "TERMINATED", Instant.now().plus(Duration.ofHours(1)), Instant.now());
        when(tasks.find("T-INACTIVE")).thenReturn(inactive);

        assertThrows(IllegalStateException.class, () ->
                service.issue("operator-1", "T-INACTIVE", "read_file", "workspace/src/*", Duration.ofHours(1)));
    }

    @Test
    void issueRejectsExpiredTask() {
        Task expired = new Task("T-EXPIRED", "operator-1", "Read", List.of("read_file"), List.of("workspace/*"),
                List.of(), "ACTIVE", Instant.now().minusSeconds(10), Instant.now());
        when(tasks.find("T-EXPIRED")).thenReturn(expired);

        assertThrows(IllegalStateException.class, () ->
                service.issue("operator-1", "T-EXPIRED", "read_file", "workspace/src/*", Duration.ofHours(1)));
    }

    @Test
    void issueRejectsDisallowedTool() {
        assertThrows(IllegalArgumentException.class, () ->
                service.issue("operator-1", "T-1", "delete_file", "workspace/src/*", Duration.ofHours(1)));
    }

    @Test
    void issueRejectsUnregisteredTool() {
        Task taskWithUnregistered = new Task("T-1", "operator-1", "Read", List.of("unregistered_tool"),
                List.of("workspace/src/*"), List.of(), "ACTIVE", Instant.now().plusSeconds(3600), Instant.now());
        when(tasks.find("T-1")).thenReturn(taskWithUnregistered);
        when(registry.findEnabled("unregistered_tool")).thenReturn(Optional.empty());

        assertThrows(IllegalArgumentException.class, () ->
                service.issue("operator-1", "T-1", "unregistered_tool", "workspace/src/*", Duration.ofHours(1)));
    }

    @Test
    void issueRejectsOutOfScopeResource() {
        assertThrows(IllegalArgumentException.class, () ->
                service.issue("operator-1", "T-1", "read_file", "secrets/passwords.txt", Duration.ofHours(1)));
    }

    @Test
    void issueRejectsTtlExceedingTaskExpiration() {
        Task shortLived = new Task("T-SHORT", "operator-1", "Read", List.of("read_file"), List.of("workspace/src/*"),
                List.of(), "ACTIVE", Instant.now().plusSeconds(60), Instant.now());
        when(tasks.find("T-SHORT")).thenReturn(shortLived);

        assertThrows(IllegalArgumentException.class, () ->
                service.issue("operator-1", "T-SHORT", "read_file", "workspace/src/*", Duration.ofHours(2)));
    }

    @Test
    void validateAllowsValidActiveMatchingCapability() {
        CapabilityService.IssuedCapability issued = service.issue("operator-1", "T-1", "read_file", "workspace/src/*", Duration.ofHours(1));
        when(repository.findByTokenHash(issued.capability().tokenHash())).thenReturn(Optional.of(issued.capability()));

        CapabilityDecision decision = service.validate(issued.token(), "T-1", "read_file", "workspace/src/Auth.java");
        assertTrue(decision.allowed());
        assertEquals("ALLOW", decision.reason());
    }

    @Test
    void validateAllowsExactScopeMatch() {
        CapabilityService.IssuedCapability issued = service.issue("operator-1", "T-1", "read_file", "workspace/README.md", Duration.ofHours(1));
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
        CapabilityService.IssuedCapability issued = service.issue("operator-1", "T-1", "read_file", "workspace/src/*", Duration.ofHours(1));
        when(repository.findByTokenHash(issued.capability().tokenHash())).thenReturn(Optional.of(issued.capability()));

        CapabilityDecision decision = service.validate(issued.token(), "T-OTHER", "read_file", "workspace/src/Auth.java");
        assertFalse(decision.allowed());
        assertEquals("CAPABILITY_TASK_MISMATCH", decision.reason());
    }

    @Test
    void validateDeniesToolMismatch() {
        CapabilityService.IssuedCapability issued = service.issue("operator-1", "T-1", "read_file", "workspace/src/*", Duration.ofHours(1));
        when(repository.findByTokenHash(issued.capability().tokenHash())).thenReturn(Optional.of(issued.capability()));

        CapabilityDecision decision = service.validate(issued.token(), "T-1", "write_file", "workspace/src/Auth.java");
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
        CapabilityService.IssuedCapability issued = service.issue("operator-1", "T-1", "read_file", "workspace/src/*", Duration.ofHours(1));
        when(repository.findByTokenHash(issued.capability().tokenHash())).thenReturn(Optional.of(issued.capability()));

        CapabilityDecision decision = service.validate(issued.token(), "T-1", "read_file", "secrets/passwords.txt");
        assertFalse(decision.allowed());
        assertEquals("CAPABILITY_SCOPE_DENIED", decision.reason());

        CapabilityDecision nullTarget = service.validate(issued.token(), "T-1", "read_file", null);
        assertFalse(nullTarget.allowed());
        assertEquals("CAPABILITY_SCOPE_DENIED", nullTarget.reason());
    }

    @Test
    void rotateRevokesPreviousAndIssuesReplacementWithNewToken() {
        Instant now = Instant.now();
        Capability oldCap = new Capability("CAP-OLD", "T-1", "read_file", "workspace/src/*", "old-hash",
                "ACTIVE", now.minusSeconds(1800), now.plusSeconds(1800), null);
        when(repository.findById("CAP-OLD")).thenReturn(Optional.of(oldCap));

        CapabilityService.RotatedCapability rotated = service.rotate("operator-1", "CAP-OLD", Duration.ofHours(1));

        assertNotNull(rotated);
        assertEquals("CAP-OLD", rotated.rotatedFromId());
        assertNotNull(rotated.token());
        assertNotNull(rotated.capability());
        assertNotEquals("CAP-OLD", rotated.capability().id());
        assertEquals("ACTIVE", rotated.capability().status());

        // Verify previous capability was revoked in repository
        verify(repository).revoke(eq("CAP-OLD"), any(Instant.class));
        // Verify new capability was inserted into repository
        verify(repository).insert(rotated.capability());
    }

    @Test
    void rotateRejectsAlreadyRevokedCapability() {
        Capability revoked = new Capability("CAP-REVOKED", "T-1", "read_file", "workspace/src/*", "hash",
                "REVOKED", Instant.now().minusSeconds(3600), Instant.now().plusSeconds(3600), Instant.now());
        when(repository.findById("CAP-REVOKED")).thenReturn(Optional.of(revoked));

        assertThrows(IllegalStateException.class, () ->
                service.rotate("operator-1", "CAP-REVOKED", Duration.ofHours(1)));
    }

    @Test
    void rotateRejectsExpiredCapability() {
        Capability expired = new Capability("CAP-EXPIRED", "T-1", "read_file", "workspace/src/*", "hash",
                "ACTIVE", Instant.now().minusSeconds(7200), Instant.now().minusSeconds(3600), null);
        when(repository.findById("CAP-EXPIRED")).thenReturn(Optional.of(expired));

        assertThrows(IllegalStateException.class, () ->
                service.rotate("operator-1", "CAP-EXPIRED", Duration.ofHours(1)));
    }

    @Test
    void rotateRejectsUnauthorizedOperator() {
        Capability cap = new Capability("CAP-1", "T-1", "read_file", "workspace/src/*", "hash",
                "ACTIVE", Instant.now(), Instant.now().plusSeconds(3600), null);
        when(repository.findById("CAP-1")).thenReturn(Optional.of(cap));

        assertThrows(SecurityException.class, () ->
                service.rotate("unauthorized", "CAP-1", Duration.ofHours(1)));
    }

    @Test
    void revokeMarksCapabilityRevokedInRepository() {
        Capability cap = new Capability("CAP-1", "T-1", "read_file", "workspace/src/*", "hash",
                "ACTIVE", Instant.now(), Instant.now().plusSeconds(3600), null);
        when(repository.findById("CAP-1")).thenReturn(Optional.of(cap));

        service.revoke("operator-1", "CAP-1");
        verify(repository).revoke(eq("CAP-1"), any(Instant.class));
    }

    @Test
    void revokeRejectsUnauthorizedOperator() {
        Capability cap = new Capability("CAP-1", "T-1", "read_file", "workspace/src/*", "hash",
                "ACTIVE", Instant.now(), Instant.now().plusSeconds(3600), null);
        when(repository.findById("CAP-1")).thenReturn(Optional.of(cap));

        assertThrows(SecurityException.class, () ->
                service.revoke("intruder", "CAP-1"));
    }

    @Test
    void rawTokenIsNeverPersistedInDatabase() {
        CapabilityService.IssuedCapability issued = service.issue("operator-1", "T-1", "read_file", "workspace/src/*", Duration.ofHours(1));
        Capability cap = issued.capability();

        // Ensure tokenHash is not equal to raw token and is exactly 64 hex characters (SHA-256)
        assertNotEquals(issued.token(), cap.tokenHash());
        assertEquals(64, cap.tokenHash().length());
        assertTrue(cap.tokenHash().matches("^[a-f0-9]{64}$"));

        // Verify repository only received the Capability record with the hash
        verify(repository).insert(argThat(c -> c.tokenHash().equals(cap.tokenHash()) && !c.tokenHash().equals(issued.token())));
    }
}
