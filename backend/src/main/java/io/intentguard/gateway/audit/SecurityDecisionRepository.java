package io.intentguard.gateway.audit;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Repository
public class SecurityDecisionRepository {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final JdbcTemplate jdbc;

    public SecurityDecisionRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void insert(SecurityDecision decision) {
        String provJson = writeJson(decision.provenanceRefs() == null ? Collections.emptyList() : decision.provenanceRefs());
        String reasonsJson = writeJson(decision.reasonCodes() == null ? Collections.emptyList() : decision.reasonCodes());
        String factorsJson = writeJson(decision.riskFactors() == null ? Collections.emptyList() : decision.riskFactors());

        jdbc.update("""
            INSERT INTO security_decisions(decision_id, request_id, session_id, task_id, tool_name,
                                           arguments_hash, provenance_refs, decision, reason_codes,
                                           risk_level, risk_factors, policy_version, approval_id,
                                           executed, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                decision.decisionId(),
                decision.requestId(),
                decision.sessionId(),
                decision.taskId(),
                decision.toolName(),
                decision.argumentsHash(),
                provJson,
                decision.decision(),
                reasonsJson,
                decision.riskLevel(),
                factorsJson,
                decision.policyVersion(),
                decision.approvalId(),
                decision.executed(),
                Timestamp.from(decision.createdAt())
        );
    }

    public Optional<SecurityDecision> findByRequestId(String requestId) {
        try {
            SecurityDecision d = jdbc.queryForObject("""
                SELECT decision_id, request_id, session_id, task_id, tool_name,
                       arguments_hash, provenance_refs, decision, reason_codes,
                       risk_level, risk_factors, policy_version, approval_id,
                       executed, created_at
                FROM security_decisions WHERE request_id = ?
                """, (r, n) -> map(r), requestId);
            return Optional.ofNullable(d);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    public List<SecurityDecision> listRecent(int limit) {
        return jdbc.query("""
            SELECT decision_id, request_id, session_id, task_id, tool_name,
                   arguments_hash, provenance_refs, decision, reason_codes,
                   risk_level, risk_factors, policy_version, approval_id,
                   executed, created_at
            FROM security_decisions ORDER BY created_at DESC LIMIT ?
            """, (r, n) -> map(r), limit);
    }

    public int countRecentHardDenials(String sessionId, int limit) {
        // Query recent decisions for this session to count consecutive hard denials
        List<String> decisions = jdbc.query("""
            SELECT decision FROM security_decisions
            WHERE session_id = ? ORDER BY created_at DESC LIMIT ?
            """, (r, n) -> r.getString("decision"), sessionId, limit);
        int consecutive = 0;
        for (String dec : decisions) {
            if ("DENY".equalsIgnoreCase(dec)) {
                consecutive++;
            } else {
                break;
            }
        }
        return consecutive;
    }

    private SecurityDecision map(ResultSet r) throws SQLException {
        return new SecurityDecision(
                r.getString("decision_id"),
                r.getString("request_id"),
                r.getString("session_id"),
                r.getString("task_id"),
                r.getString("tool_name"),
                r.getString("arguments_hash"),
                readList(r.getString("provenance_refs")),
                r.getString("decision"),
                readList(r.getString("reason_codes")),
                r.getString("risk_level"),
                readList(r.getString("risk_factors")),
                r.getString("policy_version"),
                r.getString("approval_id"),
                r.getBoolean("executed"),
                r.getTimestamp("created_at").toInstant()
        );
    }

    private static String writeJson(Object obj) {
        try {
            return MAPPER.writeValueAsString(obj);
        } catch (Exception e) {
            return "[]";
        }
    }

    private static List<String> readList(String json) {
        if (json == null || json.isBlank()) return Collections.emptyList();
        try {
            return MAPPER.readValue(json, new TypeReference<>() {});
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }
}
