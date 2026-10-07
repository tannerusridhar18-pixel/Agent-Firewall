package io.intentguard.gateway.mcp;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.intentguard.gateway.capability.CapabilityDecision;
import io.intentguard.gateway.capability.CapabilityService;
import io.intentguard.gateway.model.*;
import io.intentguard.gateway.policy.DefaultPolicyEngine;
import io.intentguard.gateway.repository.*;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class McpGatewayServiceTest {
    private final ObjectMapper mapper = new ObjectMapper();

    private Task task() {
        return new Task("T-1", "actor", "Read source", List.of("read_file"),
                List.of("workspace/src/*"), List.of("delete"), "ACTIVE",
                Instant.now().plusSeconds(3600), Instant.now());
    }

    private McpGatewayService service(ProtectedTool tool, McpToolRegistry registry) {
        SessionRepository sessions = mock(SessionRepository.class);
        TaskRepository tasks = mock(TaskRepository.class);
        ActivityRepository activity = mock(ActivityRepository.class);
        CapabilityService capabilities = mock(CapabilityService.class);

        when(sessions.find("S-1")).thenReturn(new AgentSession("S-1", "agent", "0.2", "T-1", "ACTIVE", "v0.3",
                Instant.now(), null, Instant.now()));
        when(tasks.find("T-1")).thenReturn(task());
        when(capabilities.validate(anyString(), eq("T-1"), anyString(), anyString())).thenReturn(CapabilityDecision.allow());
        when(activity.append(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(new ActivityEvent("E-1", "S-1", "T-1", "TOOL_CALL", "MCP_GATEWAY", "read_file",
                        "workspace/src/Auth.java", "ALLOW", "TOOL", "ALLOW", Instant.now()));

        return new McpGatewayService(sessions, tasks, activity, registry,
                new DefaultPolicyEngine(), capabilities, List.of(tool));
    }

    @Test
    void missingSessionNeverExecutesProtectedTool() throws Exception {
        CounterTool tool = new CounterTool();
        McpToolRegistry registry = mock(McpToolRegistry.class);
        var result = service(tool, registry).call(null, "cap-token", "read_file",
                mapper.readTree("{"target":"workspace/src/Auth.java"}"));
        assertTrue(result.protocolError());
        assertEquals(0, tool.count);
        verifyNoInteractions(registry);
    }

    @Test
    void denyNeverExecutesProtectedTool() throws Exception {
        CounterTool tool = new CounterTool();
        McpToolRegistry registry = mock(McpToolRegistry.class);
        when(registry.findEnabled("read_file")).thenReturn(Optional.of(
                new ToolManifest("read_file", "demo-protected-server", "Read", "{}", true)));
        var result = service(tool, registry).call("S-1", "cap-token", "read_file",
                mapper.readTree("{"target":"secrets/passwords.txt"}"));
        assertTrue(result.toolError());
        assertEquals(0, tool.count);
    }

    @Test
    void allowExecutesProtectedTool() throws Exception {
        CounterTool tool = new CounterTool();
        McpToolRegistry registry = mock(McpToolRegistry.class);
        when(registry.findEnabled("read_file")).thenReturn(Optional.of(
                new ToolManifest("read_file", "demo-protected-server", "Read", "{}", true)));
        var result = service(tool, registry).call("S-1", "cap-token", "read_file",
                mapper.readTree("{"target":"workspace/src/Auth.java"}"));
        assertFalse(result.protocolError());
        assertFalse(result.toolError());
        assertEquals(1, tool.count);
    }

    @Test
    void unknownToolNeverExecutes() throws Exception {
        CounterTool tool = new CounterTool();
        McpToolRegistry registry = mock(McpToolRegistry.class);
        when(registry.findEnabled("unknown")).thenReturn(Optional.empty());
        var result = service(tool, registry).call("S-1", "cap-token", "unknown",
                mapper.readTree("{"target":"workspace/src/Auth.java"}"));
        assertTrue(result.protocolError());
        assertEquals(0, tool.count);
    }

    @Test
    void invalidCapabilityNeverExecutesProtectedTool() throws Exception {
        CounterTool tool = new CounterTool();
        McpToolRegistry registry = mock(McpToolRegistry.class);
        CapabilityService capabilities = mock(CapabilityService.class);
        SessionRepository sessions = mock(SessionRepository.class);
        TaskRepository tasks = mock(TaskRepository.class);
        ActivityRepository activity = mock(ActivityRepository.class);

        when(sessions.find("S-1")).thenReturn(new AgentSession("S-1", "agent", "0.3", "T-1", "ACTIVE", "v0.3",
                Instant.now(), null, Instant.now()));
        when(tasks.find("T-1")).thenReturn(task());
        when(capabilities.validate(anyString(), eq("T-1"), eq("read_file"), anyString()))
                .thenReturn(CapabilityDecision.deny("CAPABILITY_SCOPE_DENIED"));

        var gateway = new McpGatewayService(sessions, tasks, activity, registry,
                new DefaultPolicyEngine(), capabilities, List.of(tool));
        var result = gateway.call("S-1", "cap-token", "read_file",
                mapper.readTree("{"target":"secrets/passwords.txt"}"));
        assertTrue(result.toolError());
        assertEquals(0, tool.count);
        verifyNoInteractions(registry);
    }

    static class CounterTool implements ProtectedTool {
        int count;
        public String name() { return "read_file"; }
        public com.fasterxml.jackson.databind.JsonNode execute(com.fasterxml.jackson.databind.JsonNode arguments) {
            count++;
            return new ObjectMapper().createObjectNode().put("ok", true);
        }
    }
}