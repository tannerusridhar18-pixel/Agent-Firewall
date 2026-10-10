package io.intentguard.gateway.repository;

import io.intentguard.gateway.model.ActivityEvent;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
public class ActivityRepository {
    private final JdbcTemplate jdbc;

    public ActivityRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public ActivityEvent append(String sessionId, String taskId, String tool, String target, String decision, String classification, String reason) {
        return append(sessionId, taskId, tool, target, decision, classification, reason, "SIMULATOR", "UNKNOWN", "RECORDED");
    }

    public ActivityEvent append(String sessionId, String taskId, String tool, String target, String decision, String classification, String reason, String source) {
        return append(sessionId, taskId, tool, target, decision, classification, reason, source, "UNKNOWN", "RECORDED");
    }

    public ActivityEvent append(String sessionId, String taskId, String tool, String target, String decision,
                                String classification, String reason, String source, String riskLevel,
                                String executionStatus) {
        String id = "E-" + UUID.randomUUID();
        Instant now = Instant.now();
        jdbc.update(
                "INSERT INTO activity_events(event_id, session_id, task_id, activity_type, source, tool, target, decision, classification, reason, risk_level, execution_status, occurred_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                id, sessionId, taskId, "TOOL_CALL", source, tool, target == null ? "" : target, decision, classification, reason,
                riskLevel, executionStatus, Timestamp.from(now)
        );
        return find(id);
    }

    public void updateExecutionStatus(String eventId, String executionStatus) {
        jdbc.update("UPDATE activity_events SET execution_status=? WHERE event_id=?", executionStatus, eventId);
    }

    public ActivityEvent find(String id) {
        return jdbc.queryForObject("SELECT * FROM activity_events WHERE event_id=?", (r, n) -> map(r), id);
    }

    public List<ActivityEvent> recent() {
        return jdbc.query("SELECT * FROM activity_events ORDER BY occurred_at DESC LIMIT 100", (r, n) -> map(r));
    }

    public List<ActivityEvent> findBySession(String id) {
        return jdbc.query("SELECT * FROM activity_events WHERE session_id=? ORDER BY occurred_at ASC", (r, n) -> map(r), id);
    }

    private ActivityEvent map(ResultSet r) throws SQLException {
        return new ActivityEvent(
                r.getString("event_id"),
                r.getString("session_id"),
                r.getString("task_id"),
                r.getString("activity_type"),
                r.getString("source"),
                r.getString("tool"),
                r.getString("target"),
                r.getString("decision"),
                r.getString("classification"),
                r.getString("reason"),
                r.getString("risk_level"),
                r.getString("execution_status"),
                r.getTimestamp("occurred_at").toInstant()
        );
    }
}