package io.intentguard.gateway.mcp;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.intentguard.gateway.capability.CapabilityDecision;
import io.intentguard.gateway.capability.CapabilityService;
import io.intentguard.gateway.model.AgentSession;
import io.intentguard.gateway.model.Task;
import io.intentguard.gateway.policy.DefaultPolicyEngine;
import io.intentguard.gateway.repository.*;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class McpGatewayControllerTest {
    private static AgentSession session() {
        return new AgentSession("S-1", "agent", "0.3", "T-1", "ACTIVE", "v0.3", Instant.now(), null, Instant.now());
    }
    private static Task task() {
        return new Task("T-1", "actor", "Read source", List.of("read_file"), List.of("workspace/src/*"),
                List.of("delete"), "ACTIVE", Instant.now().plusSeconds(3600), Instant.now());
    }

    @Test
    void allowedMcpCallExecutesProtectedToolExactlyOnce() throws Exception {
        var sessions = mock(SessionRepository.class);
        var tasks = mock(TaskRepository.class);
        var activity = mock(ActivityRepository.class);
        var registry = mock(McpToolRegistry.class);
        var capabilities = mock(CapabilityService.class);
        var protectedTool = new CounterTool();

        when(sessions.find("S-1")).thenReturn(session());
        when(tasks.find("T-1")).thenReturn(task());
        when(capabilities.validate(eq("cap-token"), eq("T-1"), eq("read_file"), eq("workspace/src/Auth.java"))).thenReturn(CapabilityDecision.allow());
        when(activity.append(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(new io.intentguard.gateway.model.ActivityEvent("E-1","S-1","T-1","TOOL_CALL","MCP_GATEWAY",
                        "read_file","workspace/src/Auth.java","ALLOW","TOOL","ALLOW",Instant.now()));
        when(registry.findEnabled("read_file")).thenReturn(Optional.of(new ToolManifest("read_file","demo-protected-server","Read","{}",true)));

        var gateway = new McpGatewayService(sessions, tasks, activity, registry, new DefaultPolicyEngine(), capabilities, List.of(protectedTool));
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new McpGatewayController(gateway, registry)).build();

        String body = mvc.perform(post("/mcp").header("Mcp-Session-Id","S-1").header("X-IntentGuard-Capability","cap-token")
                .contentType("application/json").content("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"target\":\"workspace/src/Auth.java\"}}}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        assertTrue(body.contains("\"isError\":false"));
        assertEquals(1, protectedTool.count);
    }

    @Test
    void deniedMcpCallNeverReachesProtectedTool() throws Exception {
        var sessions = mock(SessionRepository.class);
        var tasks = mock(TaskRepository.class);
        var activity = mock(ActivityRepository.class);
        var registry = mock(McpToolRegistry.class);
        var capabilities = mock(CapabilityService.class);
        var protectedTool = new CounterTool();

        when(sessions.find("S-1")).thenReturn(session());
        when(tasks.find("T-1")).thenReturn(task());
        when(capabilities.validate(eq("cap-token"), eq("T-1"), eq("read_file"), eq("secrets/passwords.txt"))).thenReturn(CapabilityDecision.deny("CAPABILITY_SCOPE_DENIED"));
        when(activity.append(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(new io.intentguard.gateway.model.ActivityEvent("E-1","S-1","T-1","TOOL_CALL","MCP_GATEWAY",
                        "read_file","secrets/passwords.txt","DENY","TOOL","DENY",Instant.now()));

        var gateway = new McpGatewayService(sessions, tasks, activity, registry, new DefaultPolicyEngine(), capabilities, List.of(protectedTool));
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new McpGatewayController(gateway, registry)).build();

        mvc.perform(post("/mcp").header("Mcp-Session-Id","S-1").header("X-IntentGuard-Capability","cap-token")
                .contentType("application/json").content("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"target\":\"secrets/passwords.txt\"}}}"))
                .andExpect(status().isOk());

        assertEquals(0, protectedTool.count);
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