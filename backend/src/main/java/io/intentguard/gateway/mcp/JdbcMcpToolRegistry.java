package io.intentguard.gateway.mcp;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

@Repository
public class JdbcMcpToolRegistry implements McpToolRegistry {
    private final JdbcTemplate jdbc;

    public JdbcMcpToolRegistry(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<ToolManifest> findEnabled(String toolName) {
        return jdbc.query("""
            SELECT m.tool_name, m.server_id, m.description, m.input_schema, m.enabled,
                   m.risk_level, m.side_effect, m.sensitive_parameters, m.destination_constraints
            FROM mcp_tool_manifests m JOIN mcp_server_registrations s ON s.server_id = m.server_id
            WHERE m.tool_name = ? AND m.enabled = TRUE AND s.registration_status = 'ACTIVE'
            """, (r, n) -> map(r), toolName).stream().findFirst();
    }

    public List<ToolManifest> listEnabled() {
        return jdbc.query("""
            SELECT m.tool_name, m.server_id, m.description, m.input_schema, m.enabled,
                   m.risk_level, m.side_effect, m.sensitive_parameters, m.destination_constraints
            FROM mcp_tool_manifests m JOIN mcp_server_registrations s ON s.server_id = m.server_id
            WHERE m.enabled = TRUE AND s.registration_status = 'ACTIVE' ORDER BY m.tool_name
            """, (r, n) -> map(r));
    }

    private ToolManifest map(ResultSet r) throws SQLException {
        String risk = r.getString("risk_level");
        boolean sideEffect = r.getBoolean("side_effect");
        String sensitive = r.getString("sensitive_parameters");
        String dest = r.getString("destination_constraints");

        return new ToolManifest(
                r.getString("tool_name"),
                r.getString("server_id"),
                r.getString("description"),
                r.getString("input_schema"),
                r.getBoolean("enabled"),
                risk == null ? "LOW" : risk,
                sideEffect,
                sensitive == null ? "[]" : sensitive,
                dest == null ? "{}" : dest
        );
    }
}