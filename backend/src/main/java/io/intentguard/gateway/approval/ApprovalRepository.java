package io.intentguard.gateway.approval;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;

@Repository
public class ApprovalRepository {
    private final JdbcTemplate jdbc;

    public ApprovalRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void insert(Approval approval) {
        jdbc.update("""
            INSERT INTO approvals(approval_id, request_id, session_id, task_id, tool_name,
                                  arguments_hash, status, approver_id, created_at, expires_at, consumed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                approval.approvalId(),
                approval.requestId(),
                approval.sessionId(),
                approval.taskId(),
                approval.toolName(),
                approval.argumentsHash(),
                approval.status(),
                approval.approverId(),
                Timestamp.from(approval.createdAt()),
                Timestamp.from(approval.expiresAt()),
                approval.consumedAt() == null ? null : Timestamp.from(approval.consumedAt())
        );
    }

    public Optional<Approval> findByRequestId(String requestId) {
        try {
            Approval a = jdbc.queryForObject("""
                SELECT approval_id, request_id, session_id, task_id, tool_name,
                       arguments_hash, status, approver_id, created_at, expires_at, consumed_at
                FROM approvals WHERE request_id = ?
                """, (r, n) -> map(r), requestId);
            return Optional.ofNullable(a);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    public boolean updateStatus(String requestId, String status, String approverId) {
        int rows = jdbc.update("""
            UPDATE approvals
            SET status = ?, approver_id = ?
            WHERE request_id = ? AND status = 'PENDING'
            """, status, approverId, requestId);
        return rows > 0;
    }

    public boolean consumeAtomic(String requestId, Instant consumedAt, Instant now) {
        int rows = jdbc.update("""
            UPDATE approvals
            SET status = 'CONSUMED', consumed_at = ?
            WHERE request_id = ? AND status = 'APPROVED' AND expires_at > ?
            """, Timestamp.from(consumedAt), requestId, Timestamp.from(now));
        return rows == 1;
    }

    private Approval map(ResultSet r) throws SQLException {
        Timestamp consumedTs = r.getTimestamp("consumed_at");
        return new Approval(
                r.getString("approval_id"),
                r.getString("request_id"),
                r.getString("session_id"),
                r.getString("task_id"),
                r.getString("tool_name"),
                r.getString("arguments_hash"),
                r.getString("status"),
                r.getString("approver_id"),
                r.getTimestamp("created_at").toInstant(),
                r.getTimestamp("expires_at").toInstant(),
                consumedTs == null ? null : consumedTs.toInstant()
        );
    }
}
