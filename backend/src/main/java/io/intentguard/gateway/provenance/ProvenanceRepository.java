package io.intentguard.gateway.provenance;

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
public class ProvenanceRepository {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final JdbcTemplate jdbc;

    public ProvenanceRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void insert(ProvenanceRecord record) {
        String parentRefsJson;
        try {
            parentRefsJson = MAPPER.writeValueAsString(record.parentRefs() == null ? Collections.emptyList() : record.parentRefs());
        } catch (Exception e) {
            parentRefsJson = "[]";
        }

        jdbc.update(
                "INSERT INTO provenance_records(id, source_type, trust_level, parent_refs, sensitivity, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                record.id(),
                record.sourceType(),
                record.trustLevel(),
                parentRefsJson,
                record.sensitivity(),
                Timestamp.from(record.createdAt())
        );
    }

    public Optional<ProvenanceRecord> findById(String id) {
        try {
            ProvenanceRecord record = jdbc.queryForObject(
                    "SELECT id, source_type, trust_level, parent_refs, sensitivity, created_at FROM provenance_records WHERE id = ?",
                    (r, n) -> map(r),
                    id
            );
            return Optional.ofNullable(record);
        } catch (EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }

    public List<ProvenanceRecord> listAll() {
        return jdbc.query(
                "SELECT id, source_type, trust_level, parent_refs, sensitivity, created_at FROM provenance_records ORDER BY created_at DESC",
                (r, n) -> map(r)
        );
    }

    private ProvenanceRecord map(ResultSet r) throws SQLException {
        String parentRefsJson = r.getString("parent_refs");
        List<String> parentRefs = Collections.emptyList();
        if (parentRefsJson != null && !parentRefsJson.isBlank()) {
            try {
                parentRefs = MAPPER.readValue(parentRefsJson, new TypeReference<>() {});
            } catch (Exception ignored) {
            }
        }

        return new ProvenanceRecord(
                r.getString("id"),
                r.getString("source_type"),
                r.getString("trust_level"),
                parentRefs,
                r.getString("sensitivity"),
                r.getTimestamp("created_at").toInstant()
        );
    }
}
