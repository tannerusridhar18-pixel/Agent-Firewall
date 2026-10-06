package io.intentguard.gateway.mcp;
import org.springframework.jdbc.core.JdbcTemplate; import org.springframework.stereotype.Repository;
import java.util.List; import java.util.Optional;
@Repository public class JdbcMcpToolRegistry implements McpToolRegistry {
 private final JdbcTemplate jdbc;
 public JdbcMcpToolRegistry(JdbcTemplate jdbc){this.jdbc=jdbc;}
 public Optional<ToolManifest> findEnabled(String toolName){return jdbc.query("""
 SELECT m.tool_name,m.server_id,m.description,m.input_schema,m.enabled
 FROM mcp_tool_manifests m JOIN mcp_server_registrations s ON s.server_id=m.server_id
 WHERE m.tool_name=? AND m.enabled=TRUE AND s.registration_status='ACTIVE'
 """,(r,n)->new ToolManifest(r.getString("tool_name"),r.getString("server_id"),r.getString("description"),r.getString("input_schema"),r.getBoolean("enabled")),toolName).stream().findFirst();}
 public List<ToolManifest> listEnabled(){return jdbc.query("""
 SELECT m.tool_name,m.server_id,m.description,m.input_schema,m.enabled
 FROM mcp_tool_manifests m JOIN mcp_server_registrations s ON s.server_id=m.server_id
 WHERE m.enabled=TRUE AND s.registration_status='ACTIVE' ORDER BY m.tool_name
 """,(r,n)->new ToolManifest(r.getString("tool_name"),r.getString("server_id"),r.getString("description"),r.getString("input_schema"),r.getBoolean("enabled")));}
}