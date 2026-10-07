package io.intentguard.gateway.quarantine;

import io.intentguard.gateway.model.AgentSession;
import io.intentguard.gateway.repository.SessionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class QuarantineServiceTest {

    private QuarantineRepository repository;
    private SessionRepository sessions;
    private QuarantineService service;

    @BeforeEach
    void setUp() {
        repository = mock(QuarantineRepository.class);
        sessions = mock(SessionRepository.class);
        service = new QuarantineService(repository, sessions);
    }

    @Test
    void isQuarantinedReturnsTrueWhenSessionStatusIsQuarantined() {
        when(sessions.find("S-1")).thenReturn(new AgentSession("S-1", "ag", "0.4", "T-1", "QUARANTINED", "v0.4",
                Instant.now(), null, Instant.now()));

        assertTrue(service.isQuarantined("S-1"));
    }

    @Test
    void isQuarantinedReturnsTrueWhenActiveQuarantineRecordExists() {
        when(sessions.find("S-2")).thenReturn(new AgentSession("S-2", "ag", "0.4", "T-1", "ACTIVE", "v0.4",
                Instant.now(), null, Instant.now()));
        when(repository.findActiveBySessionId("S-2")).thenReturn(Optional.of(
                new QuarantineRecord("Q-1", "S-2", "suspicious", "{}", "operator", true, Instant.now(), null)));

        assertTrue(service.isQuarantined("S-2"));
    }

    @Test
    void isQuarantinedReturnsFalseForActiveSessionWithoutQuarantine() {
        when(sessions.find("S-3")).thenReturn(new AgentSession("S-3", "ag", "0.4", "T-1", "ACTIVE", "v0.4",
                Instant.now(), null, Instant.now()));
        when(repository.findActiveBySessionId("S-3")).thenReturn(Optional.empty());

        assertFalse(service.isQuarantined("S-3"));
    }

    @Test
    void quarantineSetsSessionStatusAndInsertsRecord() {
        QuarantineRecord record = service.quarantine("S-1", "MALICIOUS_BEHAVIOR", "operator-1", "{}");
        assertEquals("S-1", record.sessionId());
        assertEquals("MALICIOUS_BEHAVIOR", record.reason());
        assertTrue(record.active());

        verify(sessions).updateStatus("S-1", "QUARANTINED");
        verify(repository).insert(any(QuarantineRecord.class));
    }

    @Test
    void unquarantineReleasesRecordAndRestoresActiveStatus() {
        service.unquarantine("S-1", "operator-1");
        verify(repository).releaseActive(eq("S-1"), any(Instant.class));
        verify(sessions).updateStatus("S-1", "ACTIVE");
    }
}
