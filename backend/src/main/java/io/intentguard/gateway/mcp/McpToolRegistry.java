package io.intentguard.gateway.mcp;
import java.util.List; import java.util.Optional;
public interface McpToolRegistry { Optional<ToolManifest> findEnabled(String toolName); List<ToolManifest> listEnabled(); }