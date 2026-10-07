package io.intentguard.gateway.mcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.intentguard.gateway.approval.Approval;
import io.intentguard.gateway.approval.ApprovalRepository;
import io.intentguard.gateway.approval.ApprovalService;
import io.intentguard.gateway.audit.AuditService;
import io.intentguard.gateway.audit.SecurityDecision;
import io.intentguard.gateway.audit.SecurityDecisionRepository;
import io.intentguard.gateway.audit.SecurityEventRepository;
import io.intentguard.gateway.capability.CapabilityDecision;
import io.intentguard.gateway.capability.CapabilityService;
import io.intentguard.gateway.common.ArgumentHasher;
import io.intentguard.gateway.model.AgentSession;
import io.intentguard.gateway.model.Task;
import io.intentguard.gateway.policy.DefaultPolicyEngine;
import io.intentguard.gateway.provenance.ProvenanceRecord;
import io.intentguard.gateway.provenance.ProvenanceRepository;
import io.intentguard.gateway.provenance.ProvenanceService;
import io.intentguard.gateway.quarantine.QuarantineRecord;
import io.intentguard.gateway.quarantine.QuarantineRepository;
import io.intentguard.gateway.quarantine.QuarantineService;
import io.intentguard.gateway.repository.ActivityRepository;
import io.intentguard.gateway.repository.SessionRepository;
import io.intentguard.gateway.repository.TaskRepository;
import io.intentguard.gateway.risk.RiskEvaluator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class McpSecurityBypassTest {
    private final ObjectMapper mapper = new ObjectMapper();

    private SessionRepository sessions;
    private TaskRepository tasks;
    private ActivityRepository activity;
    private McpToolRegistry registry;
    private CapabilityService capabilities;
    private ProvenanceRepository provenanceRepo;
    private ProvenanceService provenanceService;
    private RiskEvaluator riskEvaluator;
    private ApprovalRepository approvalRepo;
    private ApprovalService approvalService;
    private QuarantineRepository quarantineRepo;
    private QuarantineService quarantineService;
    private SecurityDecisionRepository decisionRepo;
    private SecurityEventRepository eventRepo;
    private AuditService auditService;
    private CounterTool tool;
    private McpGatewayService gateway;

    private Task task() {
        return new Task("T-1", "user", "Read workspace docs", List.of("read_file"), List.of("workspace/docs/*"), List.of("delete_file"), "ACTIVE", Instant.now().plusSeconds(3600), Instant.now());
    }

    private AgentSession session() {
        return new AgentSession("S-1", "agent-1", "0.4", "T-1", "ACTIVE", "v0.4", Instant.now(), null, Instant.now());
    }

    @BeforeEach
    void setUp() {
        sessions = mock(SessionRepository.class);
        tasks = mock(TaskRepository.class);
        activity = mock(ActivityRepository.class);
        registry = mock(McpToolRegistry.class);
        capabilities = mock(CapabilityService.class);
        provenanceRepo = mock(ProvenanceRepository.class);
        approvalRepo = mock(ApprovalRepository.class);
        quarantineRepo = mock(QuarantineRepository.class);
        decisionRepo = mock(SecurityDecisionRepository.class);
        eventRepo = mock(SecurityEventRepository.class);

        provenanceService = new ProvenanceService(provenanceRepo);
        riskEvaluator = new RiskEvaluator();
        approvalService = new ApprovalService(approvalRepo);
        quarantineService = new QuarantineService(quarantineRepo, sessions);
        auditService = new AuditService(decisionRepo, eventRepo);
        tool = new CounterTool();

        when(sessions.find("S-1")).thenReturn(session());
        when(tasks.find("T-1")).thenReturn(task());

        gateway = new McpGatewayService(
                sessions, tasks, activity, registry, new DefaultPolicyEngine(),
                capabilities, provenanceService, riskEvaluator, approvalService,
                quarantineService, auditService, List.of(tool)
        );
    }

    @Test
    void sec001_allowedToolInScopeExecutesExactlyOnce() throws Exception {
        when(capabilities.validate(eq("cap-token"), eq("T-1"), eq("read_file"), eq("workspace/docs/a.txt")))
                .thenReturn(CapabilityDecision.allow());
        when(registry.findEnabled("read_file")).thenReturn(Optional.of(
                new ToolManifest("read_file", "srv-1", "Read file", "{}", true, "LOW", false, "[]", "{}")));

        JsonNode args = mapper.readTree("{\"target\":\"workspace/docs/a.txt\"}");
        var result = gateway.call("S-1", "cap-token", null, "read_file", args, List.of());

        assertFalse(result.protocolError());
        assertFalse(result.toolError());
        assertEquals(1, tool.count);
        verify(decisionRepo).insert(argThat(d -> d.executed() && "ALLOW".equals(d.decision())));
    }

    @Test
    void sec002_unknownToolDeniedZeroExecution() throws Exception {
        when(capabilities.validate(eq("cap-token"), eq("T-1"), eq("unknown_tool"), any()))
                .thenReturn(CapabilityDecision.allow());
        when(registry.findEnabled("unknown_tool")).thenReturn(Optional.empty());

        JsonNode args = mapper.readTree("{\"target\":\"workspace/docs/a.txt\"}");
        var result = gateway.call("S-1", "cap-token", null, "unknown_tool", args, List.of());

        assertTrue(result.protocolError());
        assertEquals(-32602, result.errorCode());
        assertEquals(0, tool.count);
    }

    @Test
    void sec003_outOfScopeToolDeniedZeroExecution() throws Exception {
        when(capabilities.validate(eq("cap-token"), eq("T-1"), eq("delete_file"), any()))
                .thenReturn(CapabilityDecision.deny("CAPABILITY_TOOL_MISMATCH"));

        JsonNode args = mapper.readTree("{\"target\":\"workspace/docs/a.txt\"}");
        var result = gateway.call("S-1", "cap-token", null, "delete_file", args, List.of());

        assertTrue(result.toolError());
        assertEquals(0, tool.count);
    }

    @Test
    void sec004_argumentViolatesContractDeniedZeroExecution() throws Exception {
        when(capabilities.validate(eq("cap-token"), eq("T-1"), eq("read_file"), eq("etc/passwd")))
                .thenReturn(CapabilityDecision.deny("CAPABILITY_SCOPE_DENIED"));

        JsonNode args = mapper.readTree("{\"target\":\"etc/passwd\"}");
        var result = gateway.call("S-1", "cap-token", null, "read_file", args, List.of());

        assertTrue(result.toolError());
        assertEquals("CAPABILITY_SCOPE_DENIED", result.content().get("decision").asText());
        assertEquals(0, tool.count);
    }

    @Test
    void sec005_parameterSmugglingDeniedZeroExecution() throws Exception {
        when(capabilities.validate(eq("cap-token"), eq("T-1"), eq("read_file"), eq("workspace/docs/../../secrets.env")))
                .thenReturn(CapabilityDecision.deny("CAPABILITY_SCOPE_DENIED"));

        JsonNode args = mapper.readTree("{\"target\":\"workspace/docs/../../secrets.env\"}");
        var result = gateway.call("S-1", "cap-token", null, "read_file", args, List.of());

        assertTrue(result.toolError());
        assertEquals(0, tool.count);
    }

    @Test
    void sec006_untrustedProvenanceRestrictedDestinationDeniedZeroExecution() throws Exception {
        when(capabilities.validate(eq("cap-token"), eq("T-1"), eq("read_file"), eq("workspace/docs/a.txt")))
                .thenReturn(CapabilityDecision.allow());
        // Tool has sideEffect = true
        when(registry.findEnabled("read_file")).thenReturn(Optional.of(
                new ToolManifest("read_file", "srv-1", "Read", "{}", true, "HIGH", true, "[]", "{}")));

        when(provenanceRepo.findById("P-UNTRUSTED")).thenReturn(Optional.of(
                new ProvenanceRecord("P-UNTRUSTED", "web_crawler", "UNTRUSTED", List.of(), "PUBLIC", Instant.now())));

        JsonNode args = mapper.readTree("{\"target\":\"workspace/docs/a.txt\"}");
        var result = gateway.call("S-1", "cap-token", null, "read_file", args, List.of("P-UNTRUSTED"));

        assertTrue(result.toolError());
        assertEquals("UNTRUSTED_PROVENANCE", result.content().get("decision").asText());
        assertEquals(0, tool.count);
    }

    @Test
    void sec007_expiredApprovalDeniedZeroExecution() throws Exception {
        when(capabilities.validate(eq("cap-token"), eq("T-1"), eq("read_file"), eq("workspace/docs/a.txt")))
                .thenReturn(CapabilityDecision.allow());
        when(registry.findEnabled("read_file")).thenReturn(Optional.of(
                new ToolManifest("read_file", "srv-1", "Read", "{}", true, "HIGH", false, "[]", "{}")));

        JsonNode args = mapper.readTree("{\"target\":\"workspace/docs/a.txt\"}");
        String hash = ArgumentHasher.canonicalHash(args);

        // Expired approval
        Approval expired = new Approval("A-EXP", "REQ-EXP", "S-1", "T-1", "read_file", hash, "APPROVED", "op-1",
                Instant.now().minusSeconds(1000), Instant.now().minusSeconds(100), null);
        when(approvalRepo.findByRequestId("REQ-EXP")).thenReturn(Optional.of(expired));

        var result = gateway.call("S-1", "cap-token", "REQ-EXP", "read_file", args, List.of());

        assertTrue(result.toolError());
        assertEquals("APPROVAL_EXPIRED", result.content().get("decision").asText());
        assertEquals(0, tool.count);
    }

    @Test
    void sec008_replayedApprovalDeniedZeroExecution() throws Exception {
        when(capabilities.validate(eq("cap-token"), eq("T-1"), eq("read_file"), eq("workspace/docs/a.txt")))
                .thenReturn(CapabilityDecision.allow());
        when(registry.findEnabled("read_file")).thenReturn(Optional.of(
                new ToolManifest("read_file", "srv-1", "Read", "{}", true, "HIGH", false, "[]", "{}")));

        JsonNode args = mapper.readTree("{\"target\":\"workspace/docs/a.txt\"}");
        String hash = ArgumentHasher.canonicalHash(args);

        // Already consumed approval
        Approval consumed = new Approval("A-CON", "REQ-CON", "S-1", "T-1", "read_file", hash, "CONSUMED", "op-1",
                Instant.now().minusSeconds(200), Instant.now().plusSeconds(500), Instant.now().minusSeconds(50));
        when(approvalRepo.findByRequestId("REQ-CON")).thenReturn(Optional.of(consumed));

        var result = gateway.call("S-1", "cap-token", "REQ-CON", "read_file", args, List.of());

        assertTrue(result.toolError());
        assertEquals("APPROVAL_ALREADY_CONSUMED", result.content().get("decision").asText());
        assertEquals(0, tool.count);
    }

    @Test
    void sec009_quarantinedSessionDeniedZeroExecution() throws Exception {
        when(sessions.find("S-QUARANTINED")).thenReturn(new AgentSession(
                "S-QUARANTINED", "ag", "0.4", "T-1", "QUARANTINED", "v0.4", Instant.now(), null, Instant.now()));

        JsonNode args = mapper.readTree("{\"target\":\"workspace/docs/a.txt\"}");
        var result = gateway.call("S-QUARANTINED", "cap-token", null, "read_file", args, List.of());

        assertTrue(result.toolError());
        assertEquals("SESSION_QUARANTINED", result.content().get("decision").asText());
        assertEquals(0, tool.count);
        verifyNoInteractions(capabilities);
    }

    @Test
    void sec010_capabilityCrossSessionConfusionDeniedZeroExecution() throws Exception {
        // Token belongs to another task T-999
        when(capabilities.validate(eq("stolen-cap"), eq("T-1"), eq("read_file"), any()))
                .thenReturn(CapabilityDecision.deny("CAPABILITY_TASK_MISMATCH"));

        JsonNode args = mapper.readTree("{\"target\":\"workspace/docs/a.txt\"}");
        var result = gateway.call("S-1", "stolen-cap", null, "read_file", args, List.of());

        assertTrue(result.toolError());
        assertEquals("CAPABILITY_TASK_MISMATCH", result.content().get("decision").asText());
        assertEquals(0, tool.count);
    }

    @Test
    void sec011_unknownProvenanceReferenceFailsClosedZeroExecution() throws Exception {
        when(capabilities.validate(eq("cap-token"), eq("T-1"), eq("read_file"), eq("workspace/docs/a.txt")))
                .thenReturn(CapabilityDecision.allow());
        when(registry.findEnabled("read_file")).thenReturn(Optional.of(
                new ToolManifest("read_file", "srv-1", "Read", "{}", true, "LOW", false, "[]", "{}")));

        when(provenanceRepo.findById("P-NONEXISTENT")).thenReturn(Optional.empty());

        JsonNode args = mapper.readTree("{\"target\":\"workspace/docs/a.txt\"}");
        var result = gateway.call("S-1", "cap-token", null, "read_file", args, List.of("P-NONEXISTENT"));

        assertTrue(result.toolError());
        assertEquals("INVALID_PROVENANCE_REF", result.content().get("decision").asText());
        assertEquals(0, tool.count);
    }

    @Test
    void sec012_auditPersistenceFailureAbortsExecution() throws Exception {
        when(capabilities.validate(eq("cap-token"), eq("T-1"), eq("read_file"), eq("workspace/docs/a.txt")))
                .thenReturn(CapabilityDecision.allow());
        when(registry.findEnabled("read_file")).thenReturn(Optional.of(
                new ToolManifest("read_file", "srv-1", "Read", "{}", true, "LOW", false, "[]", "{}")));

        doThrow(new RuntimeException("Database disk full")).when(decisionRepo).insert(any(SecurityDecision.class));

        JsonNode args = mapper.readTree("{\"target\":\"workspace/docs/a.txt\"}");
        assertThrows(RuntimeException.class, () ->
                gateway.call("S-1", "cap-token", null, "read_file", args, List.of()));

        assertEquals(0, tool.count);
    }

    @Test
    void requireApprovalPausesExecutionAndGeneratesPendingApproval() throws Exception {
        when(capabilities.validate(eq("cap-token"), eq("T-1"), eq("read_file"), eq("workspace/docs/a.txt")))
                .thenReturn(CapabilityDecision.allow());
        // HIGH risk manifest triggers REQUIRE_APPROVAL
        when(registry.findEnabled("read_file")).thenReturn(Optional.of(
                new ToolManifest("read_file", "srv-1", "Read", "{}", true, "HIGH", false, "[]", "{}")));

        JsonNode args = mapper.readTree("{\"target\":\"workspace/docs/a.txt\"}");
        var result = gateway.call("S-1", "cap-token", null, "read_file", args, List.of());

        assertTrue(result.toolError());
        assertEquals("AWAITING_APPROVAL", result.content().get("reason").asText());
        assertEquals("REQUIRE_APPROVAL", result.content().get("decision").asText());
        assertNotNull(result.content().get("requestId").asText());
        assertEquals(0, tool.count);

        verify(approvalRepo).insert(argThat(a -> "PENDING".equals(a.status())));
    }

    @Test
    void repeatedHardDenialsTriggersAutomaticSessionQuarantine() throws Exception {
        when(capabilities.validate(eq("bad-cap"), eq("T-1"), eq("read_file"), any()))
                .thenReturn(CapabilityDecision.deny("INVALID_CAPABILITY"));

        // Audit reports 3 consecutive hard denials
        when(decisionRepo.countRecentHardDenials(eq("S-1"), eq(QuarantineService.DEFAULT_HARD_DENIAL_THRESHOLD)))
                .thenReturn(3);

        JsonNode args = mapper.readTree("{\"target\":\"workspace/docs/a.txt\"}");
        gateway.call("S-1", "bad-cap", null, "read_file", args, List.of());

        verify(quarantineRepo).insert(argThat(q -> "S-1".equals(q.sessionId()) && q.active()));
        verify(sessions).updateStatus("S-1", "QUARANTINED");
    }

    static class CounterTool implements ProtectedTool {
        int count;
        public String name() { return "read_file"; }
        public JsonNode execute(JsonNode arguments) {
            count++;
            return new ObjectMapper().createObjectNode().put("ok", true);
        }
    }
}
