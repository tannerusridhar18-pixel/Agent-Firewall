package io.intentguard.gateway.quarantine;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public class QuarantineRepository {
    private final JdbcTemplate jdbc;

    public QuarantineRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void insert(QuarantineRecord record) {
        jdbc.update("""
            INSERT INTO session_quarantines(quarantine_id, session_id, reason, restrictions,
                                           quarantined_by, active, quarantined_at, released_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                record.quarantineId(),
                record.sessionId(),
                record.reason(),
                record.restrictions(),
                record.quarantinedBy(),
                record.active(),
                Timestamp.from(record.quarantinedAt()),
                record.releasedAt() == null ? null : Timestamp.from(record.releasedAt())
        );
    }

    public Optional<QuarantineRecord> findActiveBySessionId(String sessionId) {
        try {
            QuarantineRecord record = jdbc.queryForObject("""
                SELECT quarantine_id, session_id, reason, restrictions, quarantined_by,
                       active, quarantined_at, released_at
                FROM session_quarantines
                WHERE session_id = ? AND active = TRUE
                ORDER BY quarantined_at DESC LIMIT 1
                """, (r, n) -> map(r), sessionId);
            return Optional.ofNullable(record);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    public void releaseActive(String sessionId, Instant releasedAt) {
        jdbc.update("""
            UPDATE session_quarantines
            SET active = FALSE, released_at = ?
            WHERE session_id = ? AND active = TRUE
            """, Timestamp.from(releasedAt), sessionId);
    }

    public List<QuarantineRecord> listBySessionId(String sessionId) {
        return jdbc.query("""
            SELECT quarantine_id, session_id, reason, restrictions, quarantined_by,
                   active, quarantined_at, released_at
            FROM session_quarantines
            WHERE session_id = ?
            ORDER BY quarantined_at DESC
            """, (r, n) -> map(r), sessionId);
    }

    private QuarantineRecord map(ResultSet r) throws SQLException {
        Timestamp releasedTs = r.getTimestamp("released_at");
        return new QuarantineRecord(
                r.getString("quarantine_id"),
                r.getString("session_id"),
                r.getString("reason"),
                r.getString("restrictions"),
                r.getString("quarantined_by"),
                r.getBoolean("active"),
                r.getTimestamp("quarantined_at").toInstant(),
                releasedTs == null ? null : releasedTs.toInstant()
        );
    }
}
