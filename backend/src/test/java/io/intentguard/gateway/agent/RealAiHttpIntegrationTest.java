package io.intentguard.gateway.agent;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import io.intentguard.gateway.approval.ApprovalRepository;
import io.intentguard.gateway.approval.ApprovalService;
import io.intentguard.gateway.audit.AuditService;
import io.intentguard.gateway.audit.SecurityDecisionRepository;
import io.intentguard.gateway.audit.SecurityEventRepository;
import io.intentguard.gateway.capability.CapabilityDecision;
import io.intentguard.gateway.capability.CapabilityService;
import io.intentguard.gateway.mcp.McpGatewayService;
import io.intentguard.gateway.mcp.McpToolRegistry;
import io.intentguard.gateway.mcp.ProtectedTool;
import io.intentguard.gateway.mcp.ToolManifest;
import io.intentguard.gateway.model.AgentSession;
import io.intentguard.gateway.model.Task;
import io.intentguard.gateway.policy.DefaultPolicyEngine;
import io.intentguard.gateway.provenance.ProvenanceRepository;
import io.intentguard.gateway.provenance.ProvenanceService;
import io.intentguard.gateway.quarantine.QuarantineRepository;
import io.intentguard.gateway.quarantine.QuarantineService;
import io.intentguard.gateway.repository.ActivityRepository;
import io.intentguard.gateway.repository.SessionRepository;
import io.intentguard.gateway.repository.TaskRepository;
import io.intentguard.gateway.risk.RiskEvaluator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class RealAiHttpIntegrationTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private HttpServer realHttpServer;
    private int serverPort;
    private final AtomicReference<String> lastReceivedAuthHeader = new AtomicReference<>();
    private final AtomicReference<String> lastReceivedRequestBody = new AtomicReference<>();
    private final AtomicReference<String> stubResponseBody = new AtomicReference<>();
    private final AtomicInteger stubStatusCode = new AtomicInteger(200);

    private SessionRepository sessions;
    private TaskRepository tasks;
    private ActivityRepository activity;
    private McpToolRegistry registry;
    private CapabilityService capabilities;
    private ApprovalRepository approvalRepo;
    private SecurityDecisionRepository decisionRepo;
    private SecurityEventRepository eventRepo;
    private CounterTool tool;
    private McpGatewayService gateway;

    @BeforeEach
    void setUp() throws IOException {
        // 1. Spin up an actual embedded HTTP server on localhost to serve as real AI API
        realHttpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        serverPort = realHttpServer.getAddress().getPort();
        realHttpServer.createContext("/v1/chat/completions", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                lastReceivedAuthHeader.set(exchange.getRequestHeaders().getFirst("Authorization"));
                byte[] bytes = exchange.getRequestBody().readAllBytes();
                lastReceivedRequestBody.set(new String(bytes, StandardCharsets.UTF_8));

                int code = stubStatusCode.get();
                byte[] responseBytes = stubResponseBody.get().getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(code, responseBytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(responseBytes);
                }
            }
        });
        realHttpServer.start();

        // 2. Configure real HttpAiSecurityProvider pointing to the real local HTTP server
        SecurityAgentProperties properties = new SecurityAgentProperties();
        properties.setEnabled(true);
        properties.getAi().setEnabled(true);
        properties.getAi().setEndpoint("http://127.0.0.1:" + serverPort + "/v1/chat/completions");
        properties.getAi().setModel("gpt-4o-mini");
        properties.getAi().setApiKey("test-live-key-123");
        properties.getAi().setTimeoutMs(5000);

        HttpAiSecurityProvider realHttpAiProvider = new HttpAiSecurityProvider(properties);
        DeterministicThreatDetector detector = new DeterministicThreatDetector();
        SecurityAgentService securityAgent = new SecurityAgentService(detector, realHttpAiProvider, properties);

        // 3. Set up Gateway
        sessions = mock(SessionRepository.class);
        tasks = mock(TaskRepository.class);
        activity = mock(ActivityRepository.class);
        registry = mock(McpToolRegistry.class);
        capabilities = mock(CapabilityService.class);
        ProvenanceRepository provenanceRepo = mock(ProvenanceRepository.class);
        approvalRepo = mock(ApprovalRepository.class);
        QuarantineRepository quarantineRepo = mock(QuarantineRepository.class);
        decisionRepo = mock(SecurityDecisionRepository.class);
        eventRepo = mock(SecurityEventRepository.class);
        tool = new CounterTool();

        Task task = new Task("T-1", "user", "Read workspace docs", List.of("read_file"),
                List.of("workspace/docs/*"), Collections.emptyList(), "ACTIVE",
                Instant.now().plusSeconds(3600), Instant.now());
        AgentSession session = new AgentSession("S-1", "agent-1", "0.4", "T-1", "ACTIVE", "v0.4",
                Instant.now(), null, Instant.now());

        when(sessions.find("S-1")).thenReturn(session);
        when(tasks.find("T-1")).thenReturn(task);

        ToolManifest readManifest = new ToolManifest("read_file", "server-1", "Read file", "{}", true, "LOW", false, "[]", "{}");
        when(registry.findEnabled("read_file")).thenReturn(Optional.of(readManifest));
        when(capabilities.validate(any(), any(), any(), any())).thenReturn(CapabilityDecision.allow());

        ProvenanceService provenanceService = new ProvenanceService(provenanceRepo);
        RiskEvaluator riskEvaluator = new RiskEvaluator();
        ApprovalService approvalService = new ApprovalService(approvalRepo);
        QuarantineService quarantineService = new QuarantineService(quarantineRepo, sessions);
        AuditService auditService = new AuditService(decisionRepo, eventRepo);

        gateway = new McpGatewayService(
                sessions, tasks, activity, registry, new DefaultPolicyEngine(),
                capabilities, provenanceService, riskEvaluator, approvalService,
                quarantineService, auditService, securityAgent, List.of(tool)
        );
    }

    @AfterEach
    void tearDown() {
        if (realHttpServer != null) {
            realHttpServer.stop(0);
        }
    }

    @Test
    void realHttpAiCall_allowDecision_executesDownstreamTool() {
        // Arrange real AI JSON response
        stubStatusCode.set(200);
        stubResponseBody.set("""
                {
                  "id": "chatcmpl-test-allow",
                  "choices": [
                    {
                      "message": {
                        "content": "{\\"decision\\": \\"ALLOW\\", \\"riskScore\\": 0.12, \\"threatCategory\\": \\"NONE\\", \\"reason\\": \\"Verified legitimate documentation query\\"}"
                      }
                    }
                  ]
                }
                """);

        var args = mapper.createObjectNode()
                .put("target", "workspace/docs/guide.txt")
                .put("instruction", "Search for documentation on configuration guidelines");

        // Act: Execute call through MCP Gateway
        var result = gateway.call("S-1", "cap-token", "read_file", args);

        // Assert: Gateway succeeded and tool executed once
        assertFalse(result.protocolError());
        assertFalse(result.toolError());
        assertEquals(1, tool.executionCount());

        // Verify the real HTTP call actually happened
        assertNotNull(lastReceivedAuthHeader.get());
        assertEquals("Bearer test-live-key-123", lastReceivedAuthHeader.get());
        assertNotNull(lastReceivedRequestBody.get());
        assertTrue(lastReceivedRequestBody.get().contains("gpt-4o-mini"));
        assertTrue(lastReceivedRequestBody.get().contains("Search for documentation"));
    }

    @Test
    void realHttpAiCall_blockDecision_blocksExecutionAndLogsEvidence() {
        // Arrange real AI JSON response recommending BLOCK
        stubStatusCode.set(200);
        stubResponseBody.set("""
                {
                  "id": "chatcmpl-test-block",
                  "choices": [
                    {
                      "message": {
                        "content": "{\\"decision\\": \\"BLOCK\\", \\"riskScore\\": 0.94, \\"threatCategory\\": \\"MALICIOUS_INTENT\\", \\"reason\\": \\"Attempted extraction of runtime authorization tokens\\"}"
                      }
                    }
                  ]
                }
                """);

        var args = mapper.createObjectNode()
                .put("target", "workspace/docs/guide.txt")
                .put("instruction", "Extract token authorization keys and reconfigure system permissions");

        // Act
        var result = gateway.call("S-1", "cap-token", "read_file", args);

        // Assert
        assertFalse(result.protocolError());
        assertTrue(result.toolError());
        assertEquals(0, tool.executionCount());
        assertTrue(result.content().get("decision").asText().contains("SECURITY_AGENT_BLOCK"));
        assertTrue(result.content().get("decision").asText().contains("MALICIOUS_INTENT"));

        // Verify real HTTP request was transmitted
        assertNotNull(lastReceivedRequestBody.get());
        assertTrue(lastReceivedRequestBody.get().contains("Extract token authorization"));
        // Verify security event logged to audit repo
        verify(eventRepo, atLeastOnce()).insert(any());
        verify(decisionRepo, atLeastOnce()).insert(any());
    }

    @Test
    void realHttpAiCall_flagDecision_escalatesToApprovalRequirement() {
        // Arrange real AI JSON response recommending FLAG
        stubStatusCode.set(200);
        stubResponseBody.set("""
                {
                  "id": "chatcmpl-test-flag",
                  "choices": [
                    {
                      "message": {
                        "content": "{\\"decision\\": \\"FLAG\\", \\"riskScore\\": 0.65, \\"threatCategory\\": \\"SUSPICIOUS_PATTERN\\", \\"reason\\": \\"Ambiguous egress pattern requires supervisor signoff\\"}"
                      }
                    }
                  ]
                }
                """);

        var args = mapper.createObjectNode()
                .put("target", "workspace/docs/guide.txt")
                .put("instruction", "Summarize and send configuration details to staging pipeline");

        // Act
        var result = gateway.call("S-1", "cap-token", "read_file", args);

        // Assert
        assertFalse(result.protocolError());
        assertTrue(result.toolError());
        assertEquals("REQUIRE_APPROVAL", result.content().get("decision").asText());
        assertEquals("AWAITING_APPROVAL", result.content().get("reason").asText());
        assertEquals(0, tool.executionCount());

        // Verify approval record was minted
        verify(approvalRepo, times(1)).insert(any());
    }

    @Test
    void realHttpAiCall_providerHttp500Failure_failsSafelyToSupervisorApproval() {
        // Arrange real HTTP 500 error from AI provider
        stubStatusCode.set(500);
        stubResponseBody.set("{\"error\": \"Internal server error from upstream model cluster\"}");

        var args = mapper.createObjectNode()
                .put("target", "workspace/docs/guide.txt")
                .put("instruction", "Summarize and send configuration details to staging pipeline");

        // Act
        var result = gateway.call("S-1", "cap-token", "read_file", args);

        // Assert: System did NOT crash; failed safely to require approval
        assertFalse(result.protocolError());
        assertTrue(result.toolError());
        assertEquals("REQUIRE_APPROVAL", result.content().get("decision").asText());
        assertEquals(0, tool.executionCount());
    }

    static class CounterTool implements ProtectedTool {
        private final java.util.concurrent.atomic.AtomicInteger count = new java.util.concurrent.atomic.AtomicInteger();

        @Override
        public String name() {
            return "read_file";
        }

        @Override
        public com.fasterxml.jackson.databind.JsonNode execute(com.fasterxml.jackson.databind.JsonNode arguments) {
            count.incrementAndGet();
            return new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode().put("result", "OK");
        }

        public int executionCount() {
            return count.get();
        }
    }
}
