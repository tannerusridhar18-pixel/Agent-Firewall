package io.intentguard.gateway.mcp;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.intentguard.gateway.capability.CapabilityDecision;
import io.intentguard.gateway.capability.CapabilityService;
import io.intentguard.gateway.common.Decision;
import io.intentguard.gateway.model.*;
import io.intentguard.gateway.policy.PolicyEngine;
import io.intentguard.gateway.repository.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class McpGatewayServiceTest {
    private final ObjectMapper mapper = new ObjectMapper();

    private SessionRepository sessions;
    private TaskRepository tasks;
    private ActivityRepository activity;
    private McpToolRegistry registry;
    private PolicyEngine policy;
    private CapabilityService capabilities;
    private CounterTool tool;
    private McpGatewayService gateway;

    private Task task() {
        return new Task("T-1", "actor", "Read source", List.of("read_file"),
                List.of("workspace/src/*"), List.of("delete"), "ACTIVE",
                Instant.now().plusSeconds(3600), Instant.now());
    }

    private AgentSession session() {
        return new AgentSession("S-1", "agent", "0.3", "T-1", "ACTIVE", "v0.3",
                Instant.now(), null, Instant.now());
    }

    @BeforeEach
    void setUp() {
        sessions = mock(SessionRepository.class);
        tasks = mock(TaskRepository.class);
        activity = mock(ActivityRepository.class);
        registry = mock(McpToolRegistry.class);
        policy = mock(PolicyEngine.class);
        capabilities = mock(CapabilityService.class);
        tool = new CounterTool();

        when(sessions.find("S-1")).thenReturn(session());
        when(tasks.find("T-1")).thenReturn(task());
        when(activity.append(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(new ActivityEvent("E-1", "S-1", "T-1", "TOOL_CALL", "MCP_GATEWAY", "read_file",
                        "workspace/src/Auth.java", "ALLOW", "TOOL", "ALLOW", "LOW", "EXECUTED", Instant.now()));

        gateway = new McpGatewayService(sessions, tasks, activity, registry, policy, capabilities, List.of(tool));
    }

    @Test
    void missingSessionNeverExecutesProtectedTool() throws Exception {
        var result = gateway.call(null, "cap-token", "read_file",
                mapper.readTree("{\"target\":\"workspace/src/Auth.java\"}"));
        assertTrue(result.protocolError());
        assertEquals(-32001, result.errorCode());
        assertEquals(0, tool.count);
        verifyNoInteractions(capabilities);
        verifyNoInteractions(registry);
    }

    @Test
    void inactiveSessionNeverExecutesProtectedTool() throws Exception {
        when(sessions.find("S-INACTIVE")).thenReturn(new AgentSession("S-INACTIVE", "agent", "0.3", "T-1", "TERMINATED", "v0.3",
                Instant.now(), Instant.now(), Instant.now()));

        var result = gateway.call("S-INACTIVE", "cap-token", "read_file",
                mapper.readTree("{\"target\":\"workspace/src/Auth.java\"}"));
        assertTrue(result.toolError());
        assertEquals(0, tool.count);
        verifyNoInteractions(capabilities);
        verifyNoInteractions(registry);
    }

    @Test
    void validCapabilityAllowsRequestToReachPolicyEvaluationAndExecutesTool() throws Exception {
        when(capabilities.validate("cap-valid", "T-1", "read_file", "workspace/src/Auth.java"))
                .thenReturn(CapabilityDecision.allow());
        when(registry.findEnabled("read_file")).thenReturn(Optional.of(
                new ToolManifest("read_file", "demo-protected-server", "Read", "{}", true)));
        when(policy.evaluate(any(Task.class), eq("read_file"), eq("workspace/src/Auth.java")))
                .thenReturn(Decision.ALLOW);

        var result = gateway.call("S-1", "cap-valid", "read_file",
                mapper.readTree("{\"target\":\"workspace/src/Auth.java\"}"));

        assertFalse(result.protocolError());
        assertFalse(result.toolError());
        assertEquals(1, tool.count);
        verify(capabilities).validate("cap-valid", "T-1", "read_file", "workspace/src/Auth.java");
        verify(registry).findEnabled("read_file");
        verify(policy).evaluate(any(Task.class), eq("read_file"), eq("workspace/src/Auth.java"));
    }

    @Test
    void missingCapabilityIsDeniedBeforeToolLookupAndNeverExecutesTool() throws Exception {
        when(capabilities.validate(isNull(), eq("T-1"), eq("read_file"), eq("workspace/src/Auth.java")))
                .thenReturn(CapabilityDecision.deny("CAPABILITY_REQUIRED"));

        var result = gateway.call("S-1", null, "read_file",
                mapper.readTree("{\"target\":\"workspace/src/Auth.java\"}"));

        assertTrue(result.toolError());
        assertEquals("REQUEST_DENIED", result.content().get("reason").asText());
        assertEquals("CAPABILITY_REQUIRED", result.content().get("decision").asText());
        assertEquals(0, tool.count);
        verifyNoInteractions(registry);
        verifyNoInteractions(policy);
    }

    @Test
    void invalidCapabilityIsDeniedBeforeToolLookupAndNeverExecutesTool() throws Exception {
        when(capabilities.validate("invalid-cap", "T-1", "read_file", "workspace/src/Auth.java"))
                .thenReturn(CapabilityDecision.deny("INVALID_CAPABILITY"));

        var result = gateway.call("S-1", "invalid-cap", "read_file",
                mapper.readTree("{\"target\":\"workspace/src/Auth.java\"}"));

        assertTrue(result.toolError());
        assertEquals("REQUEST_DENIED", result.content().get("reason").asText());
        assertEquals("INVALID_CAPABILITY", result.content().get("decision").asText());
        assertEquals(0, tool.count);
        verifyNoInteractions(registry);
        verifyNoInteractions(policy);
    }

    @Test
    void expiredCapabilityIsDeniedBeforeToolLookupAndNeverExecutesTool() throws Exception {
        when(capabilities.validate("expired-cap", "T-1", "read_file", "workspace/src/Auth.java"))
                .thenReturn(CapabilityDecision.deny("CAPABILITY_EXPIRED"));

        var result = gateway.call("S-1", "expired-cap", "read_file",
                mapper.readTree("{\"target\":\"workspace/src/Auth.java\"}"));

        assertTrue(result.toolError());
        assertEquals("CAPABILITY_EXPIRED", result.content().get("decision").asText());
        assertEquals(0, tool.count);
        verifyNoInteractions(registry);
        verifyNoInteractions(policy);
    }

    @Test
    void revokedCapabilityIsDeniedBeforeToolLookupAndNeverExecutesTool() throws Exception {
        when(capabilities.validate("revoked-cap", "T-1", "read_file", "workspace/src/Auth.java"))
                .thenReturn(CapabilityDecision.deny("CAPABILITY_REVOKED"));

        var result = gateway.call("S-1", "revoked-cap", "read_file",
                mapper.readTree("{\"target\":\"workspace/src/Auth.java\"}"));

        assertTrue(result.toolError());
        assertEquals("CAPABILITY_REVOKED", result.content().get("decision").asText());
        assertEquals(0, tool.count);
        verifyNoInteractions(registry);
        verifyNoInteractions(policy);
    }

    @Test
    void wrongTaskMismatchIsDeniedBeforeToolLookupAndNeverExecutesTool() throws Exception {
        when(capabilities.validate("wrong-task-cap", "T-1", "read_file", "workspace/src/Auth.java"))
                .thenReturn(CapabilityDecision.deny("CAPABILITY_TASK_MISMATCH"));

        var result = gateway.call("S-1", "wrong-task-cap", "read_file",
                mapper.readTree("{\"target\":\"workspace/src/Auth.java\"}"));

        assertTrue(result.toolError());
        assertEquals("CAPABILITY_TASK_MISMATCH", result.content().get("decision").asText());
        assertEquals(0, tool.count);
        verifyNoInteractions(registry);
        verifyNoInteractions(policy);
    }

    @Test
    void wrongToolMismatchIsDeniedBeforeToolLookupAndNeverExecutesTool() throws Exception {
        when(capabilities.validate("wrong-tool-cap", "T-1", "read_file", "workspace/src/Auth.java"))
                .thenReturn(CapabilityDecision.deny("CAPABILITY_TOOL_MISMATCH"));

        var result = gateway.call("S-1", "wrong-tool-cap", "read_file",
                mapper.readTree("{\"target\":\"workspace/src/Auth.java\"}"));

        assertTrue(result.toolError());
        assertEquals("CAPABILITY_TOOL_MISMATCH", result.content().get("decision").asText());
        assertEquals(0, tool.count);
        verifyNoInteractions(registry);
        verifyNoInteractions(policy);
    }

    @Test
    void wrongResourceScopeIsDeniedBeforeToolLookupAndNeverExecutesTool() throws Exception {
        when(capabilities.validate("wrong-scope-cap", "T-1", "read_file", "secrets/passwords.txt"))
                .thenReturn(CapabilityDecision.deny("CAPABILITY_SCOPE_DENIED"));

        var result = gateway.call("S-1", "wrong-scope-cap", "read_file",
                mapper.readTree("{\"target\":\"secrets/passwords.txt\"}"));

        assertTrue(result.toolError());
        assertEquals("CAPABILITY_SCOPE_DENIED", result.content().get("decision").asText());
        assertEquals(0, tool.count);
        verifyNoInteractions(registry);
        verifyNoInteractions(policy);
    }

    @Test
    void policyDenialAfterValidCapabilityNeverExecutesProtectedTool() throws Exception {
        when(capabilities.validate("cap-valid", "T-1", "read_file", "workspace/src/Auth.java"))
                .thenReturn(CapabilityDecision.allow());
        when(registry.findEnabled("read_file")).thenReturn(Optional.of(
                new ToolManifest("read_file", "demo-protected-server", "Read", "{}", true)));
        when(policy.evaluate(any(Task.class), eq("read_file"), eq("workspace/src/Auth.java")))
                .thenReturn(Decision.DENY);

        var result = gateway.call("S-1", "cap-valid", "read_file",
                mapper.readTree("{\"target\":\"workspace/src/Auth.java\"}"));

        assertTrue(result.toolError());
        assertEquals("REQUEST_DENIED", result.content().get("reason").asText());
        assertEquals("DENY", result.content().get("decision").asText());
        assertEquals(0, tool.count);
    }

    @Test
    void unregisteredToolReturnsProtocolError() throws Exception {
        when(capabilities.validate("cap-valid", "T-1", "unknown_tool", "workspace/src/Auth.java"))
                .thenReturn(CapabilityDecision.allow());
        when(registry.findEnabled("unknown_tool")).thenReturn(Optional.empty());

        var result = gateway.call("S-1", "cap-valid", "unknown_tool",
                mapper.readTree("{\"target\":\"workspace/src/Auth.java\"}"));

        assertTrue(result.protocolError());
        assertEquals(-32602, result.errorCode());
        assertEquals(0, tool.count);
    }

    @Test
    void rotatedOldTokenIsDeniedAndNeverExecutesProtectedTool() throws Exception {
        when(capabilities.validate("old-token-after-rotation", "T-1", "read_file", "workspace/src/Auth.java"))
                .thenReturn(CapabilityDecision.deny("CAPABILITY_REVOKED"));

        var result = gateway.call("S-1", "old-token-after-rotation", "read_file",
                mapper.readTree("{\"target\":\"workspace/src/Auth.java\"}"));

        assertTrue(result.toolError());
        assertEquals("REQUEST_DENIED", result.content().get("reason").asText());
        assertEquals("CAPABILITY_REVOKED", result.content().get("decision").asText());
        assertEquals(0, tool.count);
        verifyNoInteractions(registry);
        verifyNoInteractions(policy);
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