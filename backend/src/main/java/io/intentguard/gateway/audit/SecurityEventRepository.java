package io.intentguard.gateway.audit;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

@Repository
public class SecurityEventRepository {
    private final JdbcTemplate jdbc;

    public SecurityEventRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void insert(SecurityEvent event) {
        jdbc.update("""
            INSERT INTO security_events(event_id, session_id, task_id, severity, event_type,
                                        request_id, message, metadata, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                event.eventId(),
                event.sessionId(),
                event.taskId(),
                event.severity(),
                event.eventType(),
                event.requestId(),
                event.message(),
                event.metadata(),
                Timestamp.from(event.createdAt())
        );
    }

    public List<SecurityEvent> listRecent(int limit) {
        return jdbc.query("""
            SELECT event_id, session_id, task_id, severity, event_type, request_id,
                   message, metadata, created_at
            FROM security_events ORDER BY created_at DESC LIMIT ?
            """, (r, n) -> map(r), limit);
    }

    public List<SecurityEvent> findBySessionId(String sessionId) {
        return jdbc.query("""
            SELECT event_id, session_id, task_id, severity, event_type, request_id,
                   message, metadata, created_at
            FROM security_events WHERE session_id = ? ORDER BY created_at DESC
            """, (r, n) -> map(r), sessionId);
    }

    private SecurityEvent map(ResultSet r) throws SQLException {
        return new SecurityEvent(
                r.getString("event_id"),
                r.getString("session_id"),
                r.getString("task_id"),
                r.getString("severity"),
                r.getString("event_type"),
                r.getString("request_id"),
                r.getString("message"),
                r.getString("metadata"),
                r.getTimestamp("created_at").toInstant()
        );
    }
}
