package io.intentguard.gateway.mcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.intentguard.gateway.capability.CapabilityDecision;
import io.intentguard.gateway.capability.CapabilityService;
import io.intentguard.gateway.common.Decision;
import io.intentguard.gateway.model.Task;
import io.intentguard.gateway.policy.PolicyEngine;
import io.intentguard.gateway.repository.ActivityRepository;
import io.intentguard.gateway.mcp.McpToolRegistry;
import io.intentguard.gateway.repository.SessionRepository;
import io.intentguard.gateway.repository.TaskRepository;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Map;
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
    private final Map<String, ProtectedTool> tools;

    public McpGatewayService(SessionRepository sessions, TaskRepository tasks, ActivityRepository activity,
                             McpToolRegistry registry, PolicyEngine policy,
                             CapabilityService capabilities, List<ProtectedTool> tools) {
        this.sessions = sessions; this.tasks = tasks; this.activity = activity;
        this.registry = registry; this.policy = policy; this.capabilities = capabilities;
        this.tools = tools.stream().collect(Collectors.toMap(ProtectedTool::name, Function.identity()));
    }

    public CallResult call(String sessionId, String capabilityToken, String toolName, JsonNode arguments) {
        if (sessionId == null || sessionId.isBlank()) return CallResult.protocolError(-32001, "MCP session is required");

        io.intentguard.gateway.model.AgentSession session;
        Task task;
        try {
            session = sessions.find(sessionId);
            task = tasks.find(session.taskId());
        } catch (EmptyResultDataAccessException ex) {
            return CallResult.protocolError(-32002, "MCP session or task was not found");
        }

        String target = target(arguments);
        if (!"ACTIVE".equals(session.status())) {
            record(session.sessionId(), task.id(), toolName, target, Decision.DENY, "INACTIVE_SESSION");
            return CallResult.toolError("REQUEST_DENIED", "INACTIVE_SESSION");
        }

        CapabilityDecision capabilityDecision = capabilities.validate(capabilityToken, task.id(), toolName, target);
        if (!capabilityDecision.allowed()) {
            record(session.sessionId(), task.id(), toolName, target, Decision.DENY, capabilityDecision.reason());
            return CallResult.toolError("REQUEST_DENIED", capabilityDecision.reason());
        }

        var manifest = registry.findEnabled(toolName);
        if (manifest.isEmpty()) {
            record(session.sessionId(), task.id(), toolName, target, Decision.DENY, "UNREGISTERED_TOOL");
            return CallResult.protocolError(-32602, "Tool is not registered");
        }

        Decision decision = policy.evaluate(task, toolName, target);
        record(session.sessionId(), task.id(), toolName, target, decision, decision.name());
        if (decision != Decision.ALLOW) return CallResult.toolError("REQUEST_DENIED", decision.name());

        ProtectedTool tool = tools.get(toolName);
        if (tool == null) return CallResult.protocolError(-32003, "Registered tool has no protected handler");
        return CallResult.success(tool.execute(arguments));
    }

    private String target(JsonNode arguments) {
        if (arguments == null) return null;
        JsonNode n = arguments.get("target");
        return n == null || n.isNull() ? null : n.asText();
    }

    private void record(String sessionId, String taskId, String tool, String target, Decision decision, String reason) {
        var event = activity.append(sessionId, taskId, tool, target == null ? "" : target, decision.name(), "MCP_GATEWAY", reason);
        if (event != null) {
            sessions.touch(sessionId, event.timestamp());
        }
    }

    public record CallResult(boolean protocolError, int errorCode, String errorMessage, boolean toolError, JsonNode content) {
        static CallResult success(JsonNode content) { return new CallResult(false, 0, null, false, content); }
        static CallResult toolError(String reason, String decision) {
            ObjectMapper mapper = new ObjectMapper();
            return new CallResult(false, 0, null, true, mapper.createObjectNode().put("reason", reason).put("decision", decision));
        }
        static CallResult protocolError(int code, String message) { return new CallResult(true, code, message, false, null); }
    }
}