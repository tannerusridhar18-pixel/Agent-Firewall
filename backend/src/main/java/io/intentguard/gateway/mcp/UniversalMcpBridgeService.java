package io.intentguard.gateway.mcp;

import com.fasterxml.jackson.databind.JsonNode;
import io.intentguard.gateway.approval.Approval;
import io.intentguard.gateway.approval.ApprovalService;
import io.intentguard.gateway.audit.AuditService;
import io.intentguard.gateway.audit.SecurityDecision;
import io.intentguard.gateway.capability.CapabilityService;
import io.intentguard.gateway.common.ArgumentHasher;
import io.intentguard.gateway.model.AgentSession;
import io.intentguard.gateway.model.Task;
import io.intentguard.gateway.repository.ActivityRepository;
import io.intentguard.gateway.repository.SessionRepository;
import io.intentguard.gateway.repository.TaskRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class UniversalMcpBridgeService {
    private static final Logger log = LoggerFactory.getLogger(UniversalMcpBridgeService.class);

    private final TaskRepository tasks;
    private final SessionRepository sessions;
    private final CapabilityService capabilities;
    private final McpToolRegistry registry;
    private final ApprovalService approvals;
    private final McpGatewayService gateway;
    private final ActivityRepository activity;
    private final AuditService audit;
    private final String configuredMcpApiKey;
    private final String configuredControlPlaneApiKey;

    @Autowired
    public UniversalMcpBridgeService(
            TaskRepository tasks,
            SessionRepository sessions,
            CapabilityService capabilities,
            McpToolRegistry registry,
            ApprovalService approvals,
            McpGatewayService gateway,
            ActivityRepository activity,
            AuditService audit,
            @Value("${intentguard.mcp.api-key:intentguard-mcp-client-secret-key}") String configuredMcpApiKey,
            @Value("${intentguard.control-plane.api-key:intentguard-control-plane-secret-key}") String configuredControlPlaneApiKey) {
        this.tasks = tasks;
        this.sessions = sessions;
        this.capabilities = capabilities;
        this.registry = registry;
        this.approvals = approvals;
        this.gateway = gateway;
        this.activity = activity;
        this.audit = audit;
        this.configuredMcpApiKey = configuredMcpApiKey;
        this.configuredControlPlaneApiKey = configuredControlPlaneApiKey;
    }

    public UniversalMcpBridgeService(
            TaskRepository tasks,
            SessionRepository sessions,
            CapabilityService capabilities,
            McpToolRegistry registry,
            ApprovalService approvals,
            McpGatewayService gateway,
            String configuredMcpApiKey,
            String configuredControlPlaneApiKey) {
        this(tasks, sessions, capabilities, registry, approvals, gateway, null, null,
                configuredMcpApiKey, configuredControlPlaneApiKey);
    }

    public boolean authenticate(String authHeader, String apiKeyHeader) {
        String token = extractToken(authHeader, apiKeyHeader);
        if (token == null || token.isBlank()) {
            return false;
        }
        return constantTimeEquals(token, configuredMcpApiKey)
                || constantTimeEquals(token, configuredControlPlaneApiKey);
    }

    public McpGatewayService.CallResult call(
            String authHeader,
            String apiKeyHeader,
            String explicitSessionId,
            String explicitApprovalId,
            String clientIdentity,
            String toolName,
            JsonNode arguments,
            List<String> provenanceRefs) {

        if (!authenticate(authHeader, apiKeyHeader)) {
            return McpGatewayService.CallResult.protocolError(-32001, "Unauthorized: Invalid or missing API key");
        }

        String actor = (clientIdentity != null && !clientIdentity.isBlank()) ? clientIdentity : "github-copilot";
        ClientContext ctx;
        try {
            ctx = resolveClientContext(explicitSessionId, actor);
        } catch (Exception ex) {
            log.error("Failed to resolve client context for actor {}: {}", actor, ex.getMessage(), ex);
            return McpGatewayService.CallResult.protocolError(-32002, "Failed to resolve agent session or task: " + ex.getMessage());
        }

        Task task = ctx.task();
        AgentSession session = ctx.session();

        String target = (arguments != null && arguments.has("target") && !arguments.get("target").isNull())
                ? arguments.get("target").asText()
                : null;

        String resourceScope = resolveScope(task, target);

        CapabilityService.IssuedCapability issued;
        try {
            issued = capabilities.issue(task.actorId(), task.id(), toolName, resourceScope, Duration.ofMinutes(15));
        } catch (IllegalArgumentException | IllegalStateException ex) {
            String msg = ex.getMessage() != null ? ex.getMessage() : "";
            log.warn("Capability issuance denied for tool {} scope {}: {}", toolName, resourceScope, msg);
            if (msg.contains("Tool") && msg.contains("not permitted")) {
                recordCapabilityDenial(session, task, toolName, target, arguments, "CAPABILITY_TOOL_MISMATCH");
                return McpGatewayService.CallResult.toolError("REQUEST_DENIED", "CAPABILITY_TOOL_MISMATCH");
            }
            if (msg.contains("Resource scope") || msg.contains("not permitted")) {
                recordCapabilityDenial(session, task, toolName, target, arguments, "CAPABILITY_SCOPE_DENIED");
                return McpGatewayService.CallResult.toolError("REQUEST_DENIED", "CAPABILITY_SCOPE_DENIED");
            }
            recordCapabilityDenial(session, task, toolName, target, arguments, "CAPABILITY_FAILURE");
            return McpGatewayService.CallResult.toolError("REQUEST_DENIED", "CAPABILITY_FAILURE");
        } catch (SecurityException ex) {
            log.warn("Capability security violation for task {}: {}", task.id(), ex.getMessage());
            recordCapabilityDenial(session, task, toolName, target, arguments, "CAPABILITY_TASK_MISMATCH");
            return McpGatewayService.CallResult.toolError("REQUEST_DENIED", "CAPABILITY_TASK_MISMATCH");
        }

        String resolvedApprovalId = explicitApprovalId;
        if (resolvedApprovalId == null || resolvedApprovalId.isBlank()) {
            String argumentsHash = ArgumentHasher.canonicalHash(arguments);
            Optional<Approval> approvedOpt = approvals.findLatestApproved(session.sessionId(), toolName, argumentsHash);
            if (approvedOpt.isPresent()) {
                resolvedApprovalId = approvedOpt.get().requestId();
            }
        }

        return gateway.call(session.sessionId(), issued.token(), resolvedApprovalId, toolName, arguments, provenanceRefs);
    }

    private void recordCapabilityDenial(AgentSession session, Task task, String toolName,
                                        String target, JsonNode arguments, String reason) {
        if (activity == null && audit == null) {
            return;
        }

        String requestId = "REQ-" + UUID.randomUUID();
        String riskLevel = "MEDIUM";
        if (audit != null) {
            audit.recordDecision(new SecurityDecision(
                    "DEC-" + UUID.randomUUID(),
                    requestId,
                    session.sessionId(),
                    task.id(),
                    toolName,
                    ArgumentHasher.canonicalHash(arguments),
                    List.of(),
                    "DENY",
                    List.of(reason),
                    riskLevel,
                    List.of("CAPABILITY_FAILURE"),
                    "v0.4",
                    null,
                    false,
                    Instant.now()
            ));
        }

        if (activity != null) {
            var event = activity.append(
                    session.sessionId(),
                    task.id(),
                    toolName,
                    target == null ? "" : target,
                    "DENY",
                    "MCP_BRIDGE",
                    reason,
                    "MCP_BRIDGE",
                    riskLevel,
                    "DENY"
            );
            if (event != null) {
                sessions.touch(session.sessionId(), event.timestamp());
            }
        }
    }

    public synchronized ClientContext resolveClientContext(String explicitSessionId, String actor) {
        if (explicitSessionId != null && !explicitSessionId.isBlank()) {
            try {
                AgentSession session = sessions.find(explicitSessionId);
                Task task = tasks.find(session.taskId());
                if ("ACTIVE".equals(session.status()) && "ACTIVE".equals(task.status())
                        && (task.expiresAt() == null || task.expiresAt().isAfter(Instant.now()))) {
                    return new ClientContext(task, session);
                }
            } catch (EmptyResultDataAccessException ignored) {
                // Fall back to resolving/creating context for actor
            }
        }

        List<Task> allTasks = tasks.findAll();
        Task activeTask = allTasks.stream()
                .filter(t -> actor.equals(t.actorId()) && "ACTIVE".equals(t.status()))
                .filter(t -> t.expiresAt() == null || t.expiresAt().isAfter(Instant.now()))
                .findFirst()
                .orElse(null);

        if (activeTask == null) {
            List<String> allowedTools = registry.listEnabled().stream().map(ToolManifest::toolName).toList();
            List<String> allowedResources = List.of("workspace/*", "customers/*", "orders/*", "public/*", "internal/*");
            List<String> forbiddenActions = List.of("delete_database", "exfiltrate_secrets", "drop_table");
            activeTask = tasks.create(
                    actor,
                    "Universal MCP Session: " + actor,
                    allowedTools,
                    allowedResources,
                    forbiddenActions,
                    Instant.now().plus(Duration.ofHours(24))
            );
        }

        final String taskId = activeTask.id();
        List<AgentSession> allSessions = sessions.findAll();
        AgentSession activeSession = allSessions.stream()
                .filter(s -> taskId.equals(s.taskId()) && "ACTIVE".equals(s.status()))
                .findFirst()
                .orElse(null);

        if (activeSession == null) {
            activeSession = sessions.create(actor, "1.0", taskId);
        }

        return new ClientContext(activeTask, activeSession);
    }

    private String resolveScope(Task task, String target) {
        if (target != null && !target.isBlank()) {
            if (task.allowedResources() != null) {
                for (String allowed : task.allowedResources()) {
                    if (allowed.endsWith("*")) {
                        String prefix = allowed.substring(0, allowed.length() - 1);
                        if (target.startsWith(prefix)) {
                            return allowed;
                        }
                    } else if (allowed.equals(target)) {
                        return allowed;
                    }
                }
            }
            return target;
        }
        if (task.allowedResources() != null && task.allowedResources().contains("workspace/*")) {
            return "workspace/*";
        }
        return (task.allowedResources() != null && !task.allowedResources().isEmpty())
                ? task.allowedResources().get(0)
                : "workspace/*";
    }

    private String extractToken(String authHeader, String apiKeyHeader) {
        if (apiKeyHeader != null && !apiKeyHeader.isBlank()) {
            return apiKeyHeader.trim();
        }
        if (authHeader != null && !authHeader.isBlank()) {
            String trimmed = authHeader.trim();
            if (trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) {
                return trimmed.substring(7).trim();
            }
            return trimmed;
        }
        return null;
    }

    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    public record ClientContext(Task task, AgentSession session) {}
}
