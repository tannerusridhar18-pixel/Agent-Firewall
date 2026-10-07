package io.intentguard.gateway.capability;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;

@Repository
public class CapabilityRepository {
    private final JdbcTemplate jdbc;

    public CapabilityRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void insert(Capability capability) {
        jdbc.update("""
                INSERT INTO capabilities(
                    capability_id, task_id, tool_name, resource_scope, token_hash,
                    status, issued_at, expires_at, revoked_at
                ) VALUES (?,?,?,?,?,?,?,?,?)
                """,
                capability.id(), capability.taskId(), capability.toolName(),
                capability.resourceScope(), capability.tokenHash(), capability.status(),
                Timestamp.from(capability.issuedAt()), Timestamp.from(capability.expiresAt()),
                capability.revokedAt() == null ? null : Timestamp.from(capability.revokedAt()));
    }

    public Optional<Capability> findByTokenHash(String tokenHash) {
        var rows = jdbc.query("""
                SELECT capability_id, task_id, tool_name, resource_scope, token_hash,
                       status, issued_at, expires_at, revoked_at
                FROM capabilities
                WHERE token_hash = ?
                """, (r, n) -> new Capability(
                r.getString("capability_id"),
                r.getString("task_id"),
                r.getString("tool_name"),
                r.getString("resource_scope"),
                r.getString("token_hash"),
                r.getString("status"),
                r.getTimestamp("issued_at").toInstant(),
                r.getTimestamp("expires_at").toInstant(),
                r.getTimestamp("revoked_at") == null ? null : r.getTimestamp("revoked_at").toInstant()
        ), tokenHash);
        return rows.stream().findFirst();
    }

    public Optional<Capability> findById(String capabilityId) {
        var rows = jdbc.query("""
                SELECT capability_id, task_id, tool_name, resource_scope, token_hash,
                       status, issued_at, expires_at, revoked_at
                FROM capabilities
                WHERE capability_id = ?
                """, (r, n) -> new Capability(
                r.getString("capability_id"),
                r.getString("task_id"),
                r.getString("tool_name"),
                r.getString("resource_scope"),
                r.getString("token_hash"),
                r.getString("status"),
                r.getTimestamp("issued_at").toInstant(),
                r.getTimestamp("expires_at").toInstant(),
                r.getTimestamp("revoked_at") == null ? null : r.getTimestamp("revoked_at").toInstant()
        ), capabilityId);
        return rows.stream().findFirst();
    }

    public java.util.List<Capability> findByTaskId(String taskId) {
        return jdbc.query("""
                SELECT capability_id, task_id, tool_name, resource_scope, token_hash,
                       status, issued_at, expires_at, revoked_at
                FROM capabilities
                WHERE task_id = ?
                ORDER BY issued_at DESC
                """, (r, n) -> new Capability(
                r.getString("capability_id"),
                r.getString("task_id"),
                r.getString("tool_name"),
                r.getString("resource_scope"),
                r.getString("token_hash"),
                r.getString("status"),
                r.getTimestamp("issued_at").toInstant(),
                r.getTimestamp("expires_at").toInstant(),
                r.getTimestamp("revoked_at") == null ? null : r.getTimestamp("revoked_at").toInstant()
        ), taskId);
    }

    public void revoke(String capabilityId, Instant revokedAt) {
        jdbc.update("""
                UPDATE capabilities
                SET status = 'REVOKED', revoked_at = ?
                WHERE capability_id = ? AND status = 'ACTIVE'
                """, Timestamp.from(revokedAt), capabilityId);
    }
}
