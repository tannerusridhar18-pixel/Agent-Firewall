package io.intentguard.gateway.mcp;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.intentguard.gateway.capability.CapabilityDecision;
import io.intentguard.gateway.capability.CapabilityService;
import io.intentguard.gateway.model.AgentSession;
import io.intentguard.gateway.model.Task;
import io.intentguard.gateway.policy.DefaultPolicyEngine;
import io.intentguard.gateway.repository.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class McpGatewayControllerTest {
    private SessionRepository sessions;
    private TaskRepository tasks;
    private ActivityRepository activity;
    private McpToolRegistry registry;
    private CapabilityService capabilities;
    private CounterTool protectedTool;
    private MockMvc mvc;

    private static AgentSession session() {
        return new AgentSession("S-1", "agent", "0.3", "T-1", "ACTIVE", "v0.3", Instant.now(), null, Instant.now());
    }

    private static Task task() {
        return new Task("T-1", "actor", "Read source", List.of("read_file"), List.of("workspace/src/*"),
                List.of("delete"), "ACTIVE", Instant.now().plusSeconds(3600), Instant.now());
    }

    @BeforeEach
    void setUp() {
        sessions = mock(SessionRepository.class);
        tasks = mock(TaskRepository.class);
        activity = mock(ActivityRepository.class);
        registry = mock(McpToolRegistry.class);
        capabilities = mock(CapabilityService.class);
        protectedTool = new CounterTool();

        when(sessions.find("S-1")).thenReturn(session());
        when(tasks.find("T-1")).thenReturn(task());
        when(activity.append(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(new io.intentguard.gateway.model.ActivityEvent("E-1", "S-1", "T-1", "TOOL_CALL", "MCP_GATEWAY",
                        "read_file", "workspace/src/Auth.java", "ALLOW", "TOOL", "ALLOW", "LOW", "EXECUTED", Instant.now()));

        var gateway = new McpGatewayService(sessions, tasks, activity, registry, new DefaultPolicyEngine(), capabilities, List.of(protectedTool));
        mvc = MockMvcBuilders.standaloneSetup(new McpGatewayController(gateway, registry)).build();
    }

    @Test
    void initializeReturnsServerInfoAndCapabilities() throws Exception {
        mvc.perform(post("/mcp")
                .header("Mcp-Protocol-Version", "2024-11-05")
                .contentType("application/json")
                .content("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.jsonrpc").value("2.0"))
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.result.protocolVersion").value("2024-11-05"))
                .andExpect(jsonPath("$.result.serverInfo.name").value("intentguard-mcp-gateway"))
                .andExpect(jsonPath("$.result.serverInfo.version").value("0.3.0"))
                .andExpect(jsonPath("$.result.capabilities.tools").isMap());
    }

    @Test
    void pingReturnsEmptyResult() throws Exception {
        mvc.perform(post("/mcp")
                .contentType("application/json")
                .content("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.jsonrpc").value("2.0"))
                .andExpect(jsonPath("$.id").value(2))
                .andExpect(jsonPath("$.result").isMap());
    }

    @Test
    void toolsListReturnsEnabledTools() throws Exception {
        when(registry.listEnabled()).thenReturn(List.of(
                new ToolManifest("read_file", "demo-server", "Read workspace file",
                        "{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\"}}}", true)));

        mvc.perform(post("/mcp")
                .contentType("application/json")
                .content("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result.tools", hasSize(1)))
                .andExpect(jsonPath("$.result.tools[0].name").value("read_file"))
                .andExpect(jsonPath("$.result.tools[0].description").value("Read workspace file"))
                .andExpect(jsonPath("$.result.tools[0].inputSchema.type").value("object"));
    }

    @Test
    void allowedMcpCallExecutesProtectedToolExactlyOnce() throws Exception {
        when(capabilities.validate(eq("cap-token"), eq("T-1"), eq("read_file"), eq("workspace/src/Auth.java")))
                .thenReturn(CapabilityDecision.allow());
        when(registry.findEnabled("read_file"))
                .thenReturn(Optional.of(new ToolManifest("read_file", "demo-protected-server", "Read", "{}", true)));

        mvc.perform(post("/mcp")
                .header("Mcp-Session-Id", "S-1")
                .header("X-IntentGuard-Capability", "cap-token")
                .contentType("application/json")
                .content("{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"target\":\"workspace/src/Auth.java\"}}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result.isError").value(false))
                .andExpect(jsonPath("$.result.content[0].type").value("text"))
                .andExpect(jsonPath("$.result.content[0].text").value(containsString("\"ok\":true")));

        assertEquals(1, protectedTool.count);
    }

    @Test
    void missingCapabilityHeaderIsDeniedAndNeverExecutesTool() throws Exception {
        when(capabilities.validate(isNull(), eq("T-1"), eq("read_file"), eq("workspace/src/Auth.java")))
                .thenReturn(CapabilityDecision.deny("CAPABILITY_REQUIRED"));

        mvc.perform(post("/mcp")
                .header("Mcp-Session-Id", "S-1")
                .contentType("application/json")
                .content("{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"target\":\"workspace/src/Auth.java\"}}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result.isError").value(true))
                .andExpect(jsonPath("$.result.content[0].text").value(containsString("CAPABILITY_REQUIRED")));

        assertEquals(0, protectedTool.count);
        verifyNoInteractions(registry);
    }

    @Test
    void invalidCapabilityHeaderIsDeniedAndNeverExecutesTool() throws Exception {
        when(capabilities.validate(eq("bad-token"), eq("T-1"), eq("read_file"), eq("workspace/src/Auth.java")))
                .thenReturn(CapabilityDecision.deny("INVALID_CAPABILITY"));

        mvc.perform(post("/mcp")
                .header("Mcp-Session-Id", "S-1")
                .header("X-IntentGuard-Capability", "bad-token")
                .contentType("application/json")
                .content("{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"target\":\"workspace/src/Auth.java\"}}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result.isError").value(true))
                .andExpect(jsonPath("$.result.content[0].text").value(containsString("INVALID_CAPABILITY")));

        assertEquals(0, protectedTool.count);
        verifyNoInteractions(registry);
    }

    @Test
    void expiredCapabilityHeaderIsDeniedAndNeverExecutesTool() throws Exception {
        when(capabilities.validate(eq("expired-token"), eq("T-1"), eq("read_file"), eq("workspace/src/Auth.java")))
                .thenReturn(CapabilityDecision.deny("CAPABILITY_EXPIRED"));

        mvc.perform(post("/mcp")
                .header("Mcp-Session-Id", "S-1")
                .header("X-IntentGuard-Capability", "expired-token")
                .contentType("application/json")
                .content("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"target\":\"workspace/src/Auth.java\"}}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result.isError").value(true))
                .andExpect(jsonPath("$.result.content[0].text").value(containsString("CAPABILITY_EXPIRED")));

        assertEquals(0, protectedTool.count);
        verifyNoInteractions(registry);
    }

    @Test
    void revokedCapabilityHeaderIsDeniedAndNeverExecutesTool() throws Exception {
        when(capabilities.validate(eq("revoked-token"), eq("T-1"), eq("read_file"), eq("workspace/src/Auth.java")))
                .thenReturn(CapabilityDecision.deny("CAPABILITY_REVOKED"));

        mvc.perform(post("/mcp")
                .header("Mcp-Session-Id", "S-1")
                .header("X-IntentGuard-Capability", "revoked-token")
                .contentType("application/json")
                .content("{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"target\":\"workspace/src/Auth.java\"}}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result.isError").value(true))
                .andExpect(jsonPath("$.result.content[0].text").value(containsString("CAPABILITY_REVOKED")));

        assertEquals(0, protectedTool.count);
        verifyNoInteractions(registry);
    }

    @Test
    void wrongScopeMcpCallIsDeniedAndNeverExecutesTool() throws Exception {
        when(capabilities.validate(eq("cap-token"), eq("T-1"), eq("read_file"), eq("secrets/passwords.txt")))
                .thenReturn(CapabilityDecision.deny("CAPABILITY_SCOPE_DENIED"));

        mvc.perform(post("/mcp")
                .header("Mcp-Session-Id", "S-1")
                .header("X-IntentGuard-Capability", "cap-token")
                .contentType("application/json")
                .content("{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"target\":\"secrets/passwords.txt\"}}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result.isError").value(true))
                .andExpect(jsonPath("$.result.content[0].text").value(containsString("CAPABILITY_SCOPE_DENIED")));

        assertEquals(0, protectedTool.count);
        verifyNoInteractions(registry);
    }

    @Test
    void toolsCallWithRotatedOldCapabilityIsDeniedAndNeverExecutesTool() throws Exception {
        when(capabilities.validate(eq("old-rotated-token"), eq("T-1"), eq("read_file"), eq("workspace/src/Auth.java")))
                .thenReturn(CapabilityDecision.deny("CAPABILITY_REVOKED"));

        mvc.perform(post("/mcp")
                .header("Mcp-Session-Id", "S-1")
                .header("X-IntentGuard-Capability", "old-rotated-token")
                .contentType("application/json")
                .content("{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"target\":\"workspace/src/Auth.java\"}}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result.isError").value(true))
                .andExpect(jsonPath("$.result.content[0].text").value(containsString("CAPABILITY_REVOKED")));

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