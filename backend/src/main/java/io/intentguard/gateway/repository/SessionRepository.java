package io.intentguard.gateway.repository;

import io.intentguard.gateway.model.AgentSession;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
public class SessionRepository {
    private final JdbcTemplate jdbc;

    public SessionRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public AgentSession create(String agent, String version, String task) {
        String id = "S-" + UUID.randomUUID();
        Instant now = Instant.now();
        jdbc.update("INSERT INTO agent_sessions(session_id,agent_id,agent_version,task_id,status,policy_version,started_at,last_activity_at) VALUES (?,?,?,?,?,?,?,?)",
                id, agent, version, task, "ACTIVE", "v0.1", Timestamp.from(now), Timestamp.from(now));
        return find(id);
    }

    public AgentSession find(String id) {
        return jdbc.queryForObject("SELECT * FROM agent_sessions WHERE session_id=?", (r, n) -> map(r), id);
    }

    public List<AgentSession> findAll() {
        return jdbc.query("SELECT * FROM agent_sessions ORDER BY started_at DESC", (r, n) -> map(r));
    }

    public void touch(String id, Instant t) {
        jdbc.update("UPDATE agent_sessions SET last_activity_at=? WHERE session_id=?", Timestamp.from(t), id);
    }

    public void updateStatus(String id, String status) {
        jdbc.update("UPDATE agent_sessions SET status=? WHERE session_id=?", status, id);
    }

    private AgentSession map(ResultSet r) throws SQLException {
        return new AgentSession(
                r.getString("session_id"),
                r.getString("agent_id"),
                r.getString("agent_version"),
                r.getString("task_id"),
                r.getString("status"),
                r.getString("policy_version"),
                r.getTimestamp("started_at").toInstant(),
                r.getTimestamp("ended_at") == null ? null : r.getTimestamp("ended_at").toInstant(),
                r.getTimestamp("last_activity_at") == null ? null : r.getTimestamp("last_activity_at").toInstant()
        );
    }
}