package io.intentguard.gateway.quarantine;

import io.intentguard.gateway.repository.SessionRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class QuarantineService {
    public static final int DEFAULT_HARD_DENIAL_THRESHOLD = 3;

    private final QuarantineRepository repository;
    private final SessionRepository sessions;

    public QuarantineService(QuarantineRepository repository, SessionRepository sessions) {
        this.repository = repository;
        this.sessions = sessions;
    }

    public boolean isQuarantined(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) return false;
        try {
            var session = sessions.find(sessionId);
            if ("QUARANTINED".equalsIgnoreCase(session.status())) {
                return true;
            }
        } catch (Exception ignored) {
        }
        return repository.findActiveBySessionId(sessionId).isPresent();
    }

    public QuarantineRecord quarantine(String sessionId, String reason, String quarantinedBy, String restrictions) {
        if (sessionId == null || sessionId.isBlank()) throw new IllegalArgumentException("sessionId is required");
        if (reason == null || reason.isBlank()) reason = "MANUAL_OPERATOR_QUARANTINE";
        if (quarantinedBy == null || quarantinedBy.isBlank()) quarantinedBy = "operator";

        // Deactivate any existing active record first
        repository.releaseActive(sessionId, Instant.now());

        QuarantineRecord record = new QuarantineRecord(
                "Q-" + UUID.randomUUID(),
                sessionId,
                reason,
                restrictions == null ? "{\"restrictedTools\":[\"*\"]}" : restrictions,
                quarantinedBy,
                true,
                Instant.now(),
                null
        );
        repository.insert(record);
        sessions.updateStatus(sessionId, "QUARANTINED");
        return record;
    }

    public void unquarantine(String sessionId, String releasedBy) {
        if (sessionId == null || sessionId.isBlank()) throw new IllegalArgumentException("sessionId is required");
        repository.releaseActive(sessionId, Instant.now());
        sessions.updateStatus(sessionId, "ACTIVE");
    }

    public Optional<QuarantineRecord> getActiveQuarantine(String sessionId) {
        return repository.findActiveBySessionId(sessionId);
    }
}
