package io.intentguard.gateway.mcp;
import com.fasterxml.jackson.databind.JsonNode;
public interface ProtectedTool { String name(); JsonNode execute(JsonNode arguments); }