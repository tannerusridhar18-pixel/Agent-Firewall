package io.intentguard.gateway.mcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.intentguard.gateway.approval.Approval;
import io.intentguard.gateway.approval.ApprovalService;
import io.intentguard.gateway.audit.AuditService;
import io.intentguard.gateway.audit.SecurityDecision;
import io.intentguard.gateway.capability.CapabilityDecision;
import io.intentguard.gateway.capability.CapabilityService;
import io.intentguard.gateway.common.ArgumentHasher;
import io.intentguard.gateway.common.Decision;
import io.intentguard.gateway.model.AgentSession;
import io.intentguard.gateway.model.ActivityEvent;
import io.intentguard.gateway.model.Task;
import io.intentguard.gateway.policy.PolicyEngine;
import io.intentguard.gateway.policy.PolicyEvaluationResult;
import io.intentguard.gateway.provenance.ProvenanceResolution;
import io.intentguard.gateway.provenance.ProvenanceService;
import io.intentguard.gateway.quarantine.QuarantineService;
import io.intentguard.gateway.repository.ActivityRepository;
import io.intentguard.gateway.repository.SessionRepository;
import io.intentguard.gateway.repository.TaskRepository;
import io.intentguard.gateway.risk.RiskEvaluator;
import io.intentguard.gateway.risk.RiskLevel;
import io.intentguard.gateway.risk.RiskSnapshot;
import io.intentguard.gateway.agent.SecurityAgentService;
import io.intentguard.gateway.agent.SecurityAnalysisResult;
import io.intentguard.gateway.agent.SecurityDecisionType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class McpGatewayService {
    private final SessionRepository sessions;
    private final TaskRepository tasks;
    private final ActivityRepository activity;
    private final McpToolRegistry registry;
    private final PolicyEngine policy;
    private final CapabilityService capabilities;
    private final ProvenanceService provenance;
    private final RiskEvaluator riskEvaluator;
    private final ApprovalService approvals;
    private final QuarantineService quarantineService;
    private final AuditService audit;
    private final SecurityAgentService securityAgent;
    private final Map<String, ProtectedTool> tools;

    @Autowired
    public McpGatewayService(SessionRepository sessions, TaskRepository tasks, ActivityRepository activity,
                             McpToolRegistry registry, PolicyEngine policy,
                             CapabilityService capabilities,
                             ProvenanceService provenance, RiskEvaluator riskEvaluator,
                             ApprovalService approvals, QuarantineService quarantineService,
                             AuditService audit, SecurityAgentService securityAgent,
                             List<ProtectedTool> tools) {
        this.sessions = sessions;
        this.tasks = tasks;
        this.activity = activity;
        this.registry = registry;
        this.policy = policy;
        this.capabilities = capabilities;
        this.provenance = provenance;
        this.riskEvaluator = riskEvaluator;
        this.approvals = approvals;
        this.quarantineService = quarantineService;
        this.audit = audit;
        this.securityAgent = securityAgent;
        this.tools = tools == null ? Collections.emptyMap() : tools.stream().collect(Collectors.toMap(ProtectedTool::name, Function.identity()));
    }

    public McpGatewayService(SessionRepository sessions, TaskRepository tasks, ActivityRepository activity,
                             McpToolRegistry registry, PolicyEngine policy,
                             CapabilityService capabilities,
                             ProvenanceService provenance, RiskEvaluator riskEvaluator,
                             ApprovalService approvals, QuarantineService quarantineService,
                             AuditService audit, List<ProtectedTool> tools) {
        this(sessions, tasks, activity, registry, policy, capabilities, provenance, riskEvaluator, approvals, quarantineService, audit, null, tools);
    }

    public McpGatewayService(SessionRepository sessions, TaskRepository tasks, ActivityRepository activity,
                             McpToolRegistry registry, PolicyEngine policy,
                             CapabilityService capabilities, List<ProtectedTool> tools) {
        this(sessions, tasks, activity, registry, policy, capabilities, null, null, null, null, null, null, tools);
    }

    public CallResult call(String sessionId, String capabilityToken, String toolName, JsonNode arguments) {
        return call(sessionId, capabilityToken, null, toolName, arguments, Collections.emptyList());
    }

    public CallResult call(String sessionId, String capabilityToken, String approvalRequestId,
                           String toolName, JsonNode arguments, List<String> provenanceRefs) {
        if (sessionId == null || sessionId.isBlank()) {
            return CallResult.protocolError(-32001, "MCP session is required");
        }

        AgentSession session;
        Task task;
        try {
            session = sessions.find(sessionId);
            task = tasks.find(session.taskId());
        } catch (EmptyResultDataAccessException ex) {
            return CallResult.protocolError(-32002, "MCP session or task was not found");
        }

        String target = target(arguments);
        String argumentsHash = ArgumentHasher.canonicalHash(arguments);
        String requestId = "REQ-" + UUID.randomUUID();

        // Gate 1: Session Status & Quarantine Check
        if (quarantineService != null && quarantineService.isQuarantined(sessionId)) {
            recordEvidence(requestId, sessionId, task.id(), toolName, argumentsHash, provenanceRefs,
                    Decision.DENY, List.of("SESSION_QUARANTINED"), "HIGH", List.of("QUARANTINED_SESSION"),
                    null, false, target, "SESSION_QUARANTINED");
            return CallResult.toolError("REQUEST_DENIED", "SESSION_QUARANTINED");
        }

        if (!"ACTIVE".equals(session.status())) {
            recordEvidence(requestId, sessionId, task.id(), toolName, argumentsHash, provenanceRefs,
                    Decision.DENY, List.of("INACTIVE_SESSION"), "LOW", Collections.emptyList(),
                    null, false, target, "INACTIVE_SESSION");
            return CallResult.toolError("REQUEST_DENIED", "INACTIVE_SESSION");
        }

        // Gate 2: Capability Validation (MANDATORY BEFORE TOOL LOOKUP)
        CapabilityDecision capabilityDecision = capabilities.validate(capabilityToken, task.id(), toolName, target);
        if (!capabilityDecision.allowed()) {
            recordEvidence(requestId, sessionId, task.id(), toolName, argumentsHash, provenanceRefs,
                    Decision.DENY, List.of(capabilityDecision.reason()), "MEDIUM", List.of("CAPABILITY_FAILURE"),
                    null, false, target, capabilityDecision.reason());
            checkRepeatedDenials(sessionId, task.id(), requestId);
            return CallResult.toolError("REQUEST_DENIED", capabilityDecision.reason());
        }

        // Gate 3: Tool Manifest & Argument Normalization
        var manifestOpt = registry.findEnabled(toolName);
        if (manifestOpt.isEmpty()) {
            recordEvidence(requestId, sessionId, task.id(), toolName, argumentsHash, provenanceRefs,
                    Decision.DENY, List.of("UNREGISTERED_TOOL"), "HIGH", List.of("UNKNOWN_TOOL"),
                    null, false, target, "UNREGISTERED_TOOL");
            checkRepeatedDenials(sessionId, task.id(), requestId);
            return CallResult.protocolError(-32602, "Tool is not registered");
        }
        ToolManifest manifest = manifestOpt.get();

        // Gate 4: Provenance Resolution
        ProvenanceResolution provRes = provenance != null
                ? provenance.resolve(provenanceRefs, toolName, target, manifest, task)
                : ProvenanceResolution.allow("TRUSTED", "PUBLIC", Collections.emptyList());

        if (!provRes.valid()) {
            String reason = provRes.failureReason() != null ? provRes.failureReason() : "UNTRUSTED_PROVENANCE";
            recordEvidence(requestId, sessionId, task.id(), toolName, argumentsHash, provenanceRefs,
                    Decision.DENY, List.of(reason), "HIGH", List.of("PROVENANCE_VIOLATION"),
                    null, false, target, reason);
            checkRepeatedDenials(sessionId, task.id(), requestId);
            return CallResult.toolError("REQUEST_DENIED", reason);
        }

        // Security / Intent Analysis (Step 5)
        SecurityAnalysisResult securityAnalysis = securityAgent != null
                ? securityAgent.analyze(task, manifest, toolName, target, arguments, provRes)
                : SecurityAnalysisResult.allow("Security agent not configured", "DEFAULT");

        if (securityAnalysis.decision() == SecurityDecisionType.BLOCK) {
            String blockReason = "SECURITY_AGENT_BLOCK: " + securityAnalysis.threatCategory() + " - " + securityAnalysis.reason();
            recordEvidence(requestId, sessionId, task.id(), toolName, argumentsHash, provenanceRefs,
                    Decision.DENY, List.of(securityAnalysis.threatCategory(), "SECURITY_AGENT_BLOCK"),
                    "CRITICAL", List.of("THREAT_DETECTED", securityAnalysis.threatCategory()),
                    null, false, target, blockReason);
            if (audit != null) {
                audit.recordSecurityEvent(sessionId, task.id(), "CRITICAL", "THREAT_BLOCKED", requestId,
                        "Request blocked by security agent: " + securityAnalysis.reason(),
                        "{\"threatCategory\":\"" + securityAnalysis.threatCategory() + "\",\"riskScore\":" + securityAnalysis.riskScore() + "}");
            }
            checkRepeatedDenials(sessionId, task.id(), requestId);
            return CallResult.toolError("REQUEST_DENIED", blockReason);
        }

        // Gate 5: Policy & Risk Evaluation
        int recentDenials = audit != null ? audit.countRecentHardDenials(sessionId, 5) : 0;
        RiskSnapshot risk = riskEvaluator != null
                ? riskEvaluator.evaluate(task, manifest, target, provRes, recentDenials)
                : new RiskSnapshot(RiskLevel.LOW, Collections.emptyList());

        if (securityAnalysis.decision() == SecurityDecisionType.FLAG) {
            List<String> escalatedFactors = new ArrayList<>(risk.factors());
            escalatedFactors.add("SECURITY_AGENT_FLAG");
            escalatedFactors.add(securityAnalysis.threatCategory());
            RiskLevel escalatedLevel = securityAnalysis.riskScore() >= 0.75 ? RiskLevel.CRITICAL : RiskLevel.HIGH;
            risk = new RiskSnapshot(escalatedLevel, escalatedFactors);
            if (audit != null) {
                audit.recordSecurityEvent(sessionId, task.id(), "HIGH", "THREAT_FLAGGED", requestId,
                        "Request flagged by security agent: " + securityAnalysis.reason(),
                        "{\"threatCategory\":\"" + securityAnalysis.threatCategory() + "\",\"riskScore\":" + securityAnalysis.riskScore() + "}");
            }
        }

        PolicyEvaluationResult policyDecision = policy.evaluate(task, manifest, target, provRes, risk);
        if (policyDecision == null) {
            Decision legacy = policy.evaluate(task, toolName, target);
            if (legacy == Decision.ALLOW) {
                policyDecision = PolicyEvaluationResult.allow();
            } else if (legacy == Decision.REQUIRE_APPROVAL) {
                policyDecision = PolicyEvaluationResult.requireApproval(List.of("REQUIRE_APPROVAL"));
            } else {
                policyDecision = PolicyEvaluationResult.deny("DENY");
            }
        }
        if (policyDecision.decision() == Decision.DENY) {
            String primaryReason = policyDecision.reasonCodes().isEmpty() ? "DENY" : policyDecision.reasonCodes().get(0);
            recordEvidence(requestId, sessionId, task.id(), toolName, argumentsHash, provenanceRefs,
                    Decision.DENY, policyDecision.reasonCodes(), risk.level().name(), risk.factors(),
                    null, false, target, primaryReason);
            checkRepeatedDenials(sessionId, task.id(), requestId);
            return CallResult.toolError("REQUEST_DENIED", primaryReason);
        }

        // Gate 6: Approval Resolution
        String consumedApprovalId = null;
        if (policyDecision.decision() == Decision.REQUIRE_APPROVAL) {
            if (approvalRequestId == null || approvalRequestId.isBlank()) {
                // Must pause execution and return REQUIRE_APPROVAL
                Approval pending = approvals != null
                        ? approvals.createPending(requestId, sessionId, task.id(), toolName, argumentsHash, null)
                        : null;
                String pendingReqId = pending != null ? pending.requestId() : requestId;
                String approvalId = pending != null ? pending.approvalId() : null;

                recordEvidence(requestId, sessionId, task.id(), toolName, argumentsHash, provenanceRefs,
                        Decision.REQUIRE_APPROVAL, List.of("AWAITING_APPROVAL"), risk.level().name(), risk.factors(),
                        approvalId, false, target, "AWAITING_APPROVAL");

                return CallResult.approvalRequired(pendingReqId, risk.level().name(), risk.factors());
            } else {
                // Validate and consume single-use approval atomically
                if (approvals == null) {
                    return CallResult.toolError("REQUEST_DENIED", "APPROVAL_NOT_SUPPORTED");
                }
                var approvalResult = approvals.validateAndConsume(approvalRequestId, sessionId, task.id(), toolName, argumentsHash);
                if (!approvalResult.allowed()) {
                    recordEvidence(requestId, sessionId, task.id(), toolName, argumentsHash, provenanceRefs,
                            Decision.DENY, List.of(approvalResult.reason()), risk.level().name(), risk.factors(),
                            null, false, target, approvalResult.reason());
                    return CallResult.toolError("REQUEST_DENIED", approvalResult.reason());
                }
                consumedApprovalId = approvalResult.approval().approvalId();
            }
        }

        // Gate 7: Fail-Closed Audit & Evidence Persistence
        ActivityEvent activityEvent = recordEvidence(requestId, sessionId, task.id(), toolName, argumentsHash, provenanceRefs,
                Decision.ALLOW, List.of("ALLOW"), risk.level().name(), risk.factors(),
                consumedApprovalId, true, target, "ALLOW");

        if (audit != null) {
            String eventType = consumedApprovalId != null ? "APPROVED_EXECUTION" : "ALLOW_VERIFIED";
            String reasonText = consumedApprovalId != null ? "Execution approved by operator" : "Execution permitted by security agent";
            audit.recordSecurityEvent(
                    sessionId,
                    task.id(),
                    "LOW",
                    eventType,
                    requestId,
                    reasonText + ": " + toolName,
                    String.format("{\"threatCategory\":\"%s\",\"riskScore\":%.2f,\"analysisSource\":\"%s\",\"decision\":\"ALLOW\",\"executed\":true}",
                            securityAnalysis.threatCategory(),
                            securityAnalysis.riskScore(),
                            securityAnalysis.analysisSource())
            );
        }

        // Gate 8: Protected Tool Execution
        ProtectedTool tool = tools.get(toolName);
        if (tool == null) {
            if (activityEvent != null) {
                activity.updateExecutionStatus(activityEvent.eventId(), "FAILED");
            }
            return CallResult.protocolError(-32003, "Registered tool has no protected handler");
        }
        try {
            CallResult result = CallResult.success(tool.execute(arguments));
            if (activityEvent != null) {
                activity.updateExecutionStatus(activityEvent.eventId(), "EXECUTED");
            }
            return result;
        } catch (RuntimeException ex) {
            if (activityEvent != null) {
                activity.updateExecutionStatus(activityEvent.eventId(), "FAILED");
            }
            throw ex;
        }
    }

    private ActivityEvent recordEvidence(String requestId, String sessionId, String taskId, String toolName,
                                String argumentsHash, List<String> provenanceRefs,
                                Decision decision, List<String> reasonCodes, String riskLevel,
                                List<String> riskFactors, String approvalId, boolean executed,
                                String target, String activityReason) {
        // Record security decision
        if (audit != null) {
            SecurityDecision secDecision = new SecurityDecision(
                    "DEC-" + UUID.randomUUID(),
                    requestId,
                    sessionId,
                    taskId,
                    toolName,
                    argumentsHash,
                    provenanceRefs == null ? Collections.emptyList() : provenanceRefs,
                    decision.name(),
                    reasonCodes == null ? Collections.emptyList() : reasonCodes,
                    riskLevel,
                    riskFactors == null ? Collections.emptyList() : riskFactors,
                    "v0.4",
                    approvalId,
                    executed,
                    Instant.now()
            );
            // Fail-closed invariant: database exception halts execution before Gate 8
            audit.recordDecision(secDecision);
        }

        // Record activity event
        if (activity != null) {
            var event = activity.append(sessionId, taskId, toolName, target == null ? "" : target,
                    decision.name(), "MCP_GATEWAY", activityReason, "MCP_GATEWAY", riskLevel,
                    executed ? "AUTHORIZED" : decision.name());
            if (event != null && sessions != null) {
                sessions.touch(sessionId, event.timestamp());
            }
            return event;
        }
        return null;
    }

    private void checkRepeatedDenials(String sessionId, String taskId, String requestId) {
        if (quarantineService == null || audit == null) return;
        int denials = audit.countRecentHardDenials(sessionId, QuarantineService.DEFAULT_HARD_DENIAL_THRESHOLD);
        if (denials >= QuarantineService.DEFAULT_HARD_DENIAL_THRESHOLD) {
            quarantineService.quarantine(sessionId, "AUTOMATIC_QUARANTINE_REPEATED_DENIALS", "system", null);
            audit.recordSecurityEvent(sessionId, taskId, "HIGH", "AUTOMATIC_QUARANTINE", requestId,
                    "Session automatically quarantined after " + denials + " consecutive hard denials", "{}");
        }
    }

    private String target(JsonNode arguments) {
        if (arguments == null) return null;
        JsonNode n = arguments.get("target");
        return n == null || n.isNull() ? null : n.asText();
    }

    public record CallResult(boolean protocolError, int errorCode, String errorMessage, boolean toolError, JsonNode content) {
        public static CallResult success(JsonNode content) {
            return new CallResult(false, 0, null, false, content);
        }

        public static CallResult toolError(String reason, String decision) {
            ObjectMapper mapper = new ObjectMapper();
            return new CallResult(false, 0, null, true,
                    mapper.createObjectNode().put("reason", reason).put("decision", decision));
        }

        public static CallResult approvalRequired(String requestId, String riskLevel, List<String> factors) {
            ObjectMapper mapper = new ObjectMapper();
            var node = mapper.createObjectNode()
                    .put("reason", "AWAITING_APPROVAL")
                    .put("decision", "REQUIRE_APPROVAL")
                    .put("requestId", requestId)
                    .put("riskLevel", riskLevel);
            var arr = node.putArray("riskFactors");
            if (factors != null) factors.forEach(arr::add);
            return new CallResult(false, 0, null, true, node);
        }

        public static CallResult protocolError(int code, String message) {
            return new CallResult(true, code, message, false, null);
        }
    }
}