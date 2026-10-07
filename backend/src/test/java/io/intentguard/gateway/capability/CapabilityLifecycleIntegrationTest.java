package io.intentguard.gateway.capability;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.intentguard.gateway.api.CapabilityControlPlaneController;
import io.intentguard.gateway.api.SessionController;
import io.intentguard.gateway.api.TaskController;
import io.intentguard.gateway.mcp.MockProtectedReadFileTool;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class CapabilityLifecycleIntegrationTest {

    private static final String OPERATOR_KEY = "intentguard-control-plane-secret-key";
    private static final String OPERATOR_ID = "operator-alice";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper mapper;

    @Autowired
    private MockProtectedReadFileTool mockTool;

    @Test
    void completeCapabilityLifecycleFlow() throws Exception {
        int initialToolExecutionCount = mockTool.executionCount();

        // 1. Create a Task owned by operator-alice
        var taskRequest = new TaskController.Request(
                OPERATOR_ID,
                "Inspect application source files",
                List.of("read_file"),
                List.of("workspace/src/*"),
                List.of("delete"),
                Instant.now().plus(Duration.ofHours(24)));

        String taskBody = mvc.perform(post("/api/v1/tasks")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(taskRequest)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonNode taskJson = mapper.readTree(taskBody);
        String taskId = taskJson.get("id").asText();
        assertNotNull(taskId);

        // 2. Create an Agent Session for this Task
        String sessionBody = mvc.perform(post("/api/v1/sessions")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(new SessionController.Request(
                        "agent-007", "0.3", taskId))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonNode sessionJson = mapper.readTree(sessionBody);
        String sessionId = sessionJson.get("sessionId").asText();
        assertNotNull(sessionId);

        // 3. Issue Capability via Control-Plane API
        String issueBody = mvc.perform(post("/api/v1/control-plane/capabilities")
                .header("X-IntentGuard-Operator-Key", OPERATOR_KEY)
                .header("X-Operator-Id", OPERATOR_ID)
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(new CapabilityControlPlaneController.IssueRequest(
                        taskId, "read_file", "workspace/src/*", 1800L))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.token").isString())
                .andReturn().getResponse().getContentAsString();
        JsonNode issueJson = mapper.readTree(issueBody);
        String capabilityId = issueJson.get("capabilityId").asText();
        String initialToken = issueJson.get("token").asText();
        assertNotNull(capabilityId);
        assertNotNull(initialToken);

        // 4. Verify GET metadata does NOT reveal the token
        mvc.perform(get("/api/v1/control-plane/capabilities/" + capabilityId)
                .header("X-IntentGuard-Operator-Key", OPERATOR_KEY)
                .header("X-Operator-Id", OPERATOR_ID))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.capabilityId").value(capabilityId))
                .andExpect(jsonPath("$.token").doesNotExist())
                .andExpect(jsonPath("$.tokenHash").doesNotExist());

        // 5. MCP tools/call with initial token -> SUCCESS
        mvc.perform(post("/mcp")
                .header("Mcp-Session-Id", sessionId)
                .header("X-IntentGuard-Capability", initialToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"jsonrpc\":\"2.0\",\"id\":100,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"target\":\"workspace/src/App.java\"}}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result.isError").value(false))
                .andExpect(jsonPath("$.result.content[0].text").value(containsString("DOWNSTREAM_TOOL_EXECUTED")));

        assertEquals(initialToolExecutionCount + 1, mockTool.executionCount());

        // 6. Rotate Capability via Control-Plane API
        String rotateBody = mvc.perform(post("/api/v1/control-plane/capabilities/" + capabilityId + "/rotate")
                .header("X-IntentGuard-Operator-Key", OPERATOR_KEY)
                .header("X-Operator-Id", OPERATOR_ID)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"ttlSeconds\": 3600}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rotatedFromId").value(capabilityId))
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.token").isString())
                .andReturn().getResponse().getContentAsString();
        JsonNode rotateJson = mapper.readTree(rotateBody);
        String rotatedCapabilityId = rotateJson.get("capabilityId").asText();
        String replacementToken = rotateJson.get("token").asText();
        assertNotEquals(capabilityId, rotatedCapabilityId);
        assertNotEquals(initialToken, replacementToken);

        // 7. Verify OLD token is now REJECTED at /mcp (Never executes tool!)
        mvc.perform(post("/mcp")
                .header("Mcp-Session-Id", sessionId)
                .header("X-IntentGuard-Capability", initialToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"jsonrpc\":\"2.0\",\"id\":101,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"target\":\"workspace/src/App.java\"}}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result.isError").value(true))
                .andExpect(jsonPath("$.result.content[0].text").value(containsString("CAPABILITY_REVOKED")));

        // Tool count MUST still be unchanged
        assertEquals(initialToolExecutionCount + 1, mockTool.executionCount());

        // 8. Verify NEW token is ALLOWED at /mcp
        mvc.perform(post("/mcp")
                .header("Mcp-Session-Id", sessionId)
                .header("X-IntentGuard-Capability", replacementToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"jsonrpc\":\"2.0\",\"id\":102,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"target\":\"workspace/src/App.java\"}}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result.isError").value(false))
                .andExpect(jsonPath("$.result.content[0].text").value(containsString("DOWNSTREAM_TOOL_EXECUTED")));

        assertEquals(initialToolExecutionCount + 2, mockTool.executionCount());

        // 9. Revoke replacement capability
        mvc.perform(post("/api/v1/control-plane/capabilities/" + rotatedCapabilityId + "/revoke")
                .header("X-IntentGuard-Operator-Key", OPERATOR_KEY)
                .header("X-Operator-Id", OPERATOR_ID))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("REVOKED"));

        // 10. Verify replacement token is now REJECTED at /mcp (Never executes tool!)
        mvc.perform(post("/mcp")
                .header("Mcp-Session-Id", sessionId)
                .header("X-IntentGuard-Capability", replacementToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"jsonrpc\":\"2.0\",\"id\":103,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"target\":\"workspace/src/App.java\"}}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result.isError").value(true))
                .andExpect(jsonPath("$.result.content[0].text").value(containsString("CAPABILITY_REVOKED")));

        // Tool execution count MUST NOT increment on denial
        assertEquals(initialToolExecutionCount + 2, mockTool.executionCount());
    }
}
