package io.intentguard.gateway.mcp;

public record ToolManifest(
        String toolName,
        String serverId,
        String description,
        String inputSchema,
        boolean enabled,
        String riskLevel,
        boolean sideEffect,
        String sensitiveParameters,
        String destinationConstraints
) {
    public ToolManifest(String toolName, String serverId, String description, String inputSchema, boolean enabled) {
        this(toolName, serverId, description, inputSchema, enabled, "LOW", false, "[]", "{}");
    }
}