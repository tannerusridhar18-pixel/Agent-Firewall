package io.intentguard.gateway.mcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/mcp")
public class McpGatewayController {
    private final McpGatewayService gateway;
    private final McpToolRegistry registry;
    private final UniversalMcpBridgeService bridge;

    public McpGatewayController(McpGatewayService gateway, McpToolRegistry registry) {
        this(gateway, registry, null);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public McpGatewayController(McpGatewayService gateway, McpToolRegistry registry, UniversalMcpBridgeService bridge) {
        this.gateway = gateway;
        this.registry = registry;
        this.bridge = bridge;
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> handle(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestHeader(value = "X-API-Key", required = false) String apiKeyHeader,
            @RequestHeader(value = "X-Client-Id", required = false) String clientIdHeader,
            @RequestHeader(value = "Mcp-Session-Id", required = false) String sessionId,
            @RequestHeader(value = "Mcp-Protocol-Version", required = false) String protocolVersion,
            @RequestHeader(value = "X-IntentGuard-Capability", required = false) String capabilityToken,
            @RequestHeader(value = "X-IntentGuard-Approval", required = false) String approvalRequestId,
            @RequestBody JsonNode request) {
        Object id = request.has("id") ? request.get("id") : null;
        String method = request.path("method").asText();

        if ("notifications/initialized".equals(method)) {
            return ResponseEntity.ok(Map.of());
        }

        if ("initialize".equals(method)) {
            if ((authHeader != null || apiKeyHeader != null) && bridge != null && !bridge.authenticate(authHeader, apiKeyHeader)) {
                return ResponseEntity.ok(error(id, -32001, "Unauthorized: Invalid or missing API key"));
            }
            return ResponseEntity.ok(response(id, Map.of(
                    "protocolVersion", protocolVersion == null ? "2024-11-05" : protocolVersion,
                    "capabilities", Map.of("tools", Map.of()),
                    "serverInfo", Map.of("name", "intentguard-mcp-gateway", "version", "0.3.0")
            )));
        }

        if ("ping".equals(method)) {
            return ResponseEntity.ok(response(id, Map.of()));
        }

        if ("tools/list".equals(method)) {
            if ((authHeader != null || apiKeyHeader != null) && bridge != null && !bridge.authenticate(authHeader, apiKeyHeader)) {
                return ResponseEntity.ok(error(id, -32001, "Unauthorized: Invalid or missing API key"));
            }
            var tools = registry.listEnabled().stream().map(t -> Map.of(
                    "name", t.toolName(),
                    "description", t.description(),
                    "inputSchema", parseSchema(t.inputSchema()),
                    "riskLevel", t.riskLevel(),
                    "sideEffect", t.sideEffect()
            )).toList();
            return ResponseEntity.ok(response(id, Map.of("tools", tools)));
        }

        if ("tools/call".equals(method)) {
            JsonNode p = request.path("params");
            String name = p.path("name").asText(null);
            JsonNode args = p.path("arguments");
            if (name == null || name.isBlank()) {
                return ResponseEntity.ok(error(id, -32602, "Tool name is required"));
            }

            List<String> provenanceRefs = new ArrayList<>();
            JsonNode provNode = p.path("provenanceRefs");
            if (provNode.isArray()) {
                for (JsonNode refNode : provNode) {
                    provenanceRefs.add(refNode.asText());
                }
            }

            String explicitApprovalId = approvalRequestId;
            if (explicitApprovalId == null || explicitApprovalId.isBlank()) {
                if (p.has("approvalRequestId")) {
                    explicitApprovalId = p.get("approvalRequestId").asText();
                } else if (args != null && args.has("approvalRequestId")) {
                    explicitApprovalId = args.get("approvalRequestId").asText();
                } else if (args != null && args.has("_intentguard_approval")) {
                    explicitApprovalId = args.get("_intentguard_approval").asText();
                }
            }

            McpGatewayService.CallResult result;

            boolean isLegacyHeaderClient = (sessionId != null && !sessionId.isBlank() && authHeader == null && apiKeyHeader == null)
                    || (capabilityToken != null && !capabilityToken.isBlank());

            if (isLegacyHeaderClient || bridge == null) {
                result = gateway.call(sessionId, capabilityToken, explicitApprovalId, name, args, provenanceRefs);
            } else {
                String clientIdentity = clientIdHeader;
                if (clientIdentity == null || clientIdentity.isBlank()) {
                    JsonNode clientInfo = p.path("clientInfo");
                    if (!clientInfo.isMissingNode() && clientInfo.has("name")) {
                        clientIdentity = clientInfo.get("name").asText();
                    }
                }
                if (clientIdentity == null || clientIdentity.isBlank()) {
                    clientIdentity = "github-copilot";
                }
                result = bridge.call(authHeader, apiKeyHeader, sessionId, explicitApprovalId, clientIdentity, name, args, provenanceRefs);
            }

            if (result.protocolError()) {
                return ResponseEntity.ok(error(id, result.errorCode(), result.errorMessage()));
            }
            return ResponseEntity.ok(response(id, Map.of(
                    "content", java.util.List.of(Map.of("type", "text", "text", result.content() == null ? "{}" : result.content().toString())),
                    "isError", result.toolError()
            )));
        }

        return ResponseEntity.ok(error(id, -32601, "Method not found"));
    }

    private Object parseSchema(String schema) {
        try {
            return new ObjectMapper().readTree(schema);
        } catch (Exception e) {
            return Map.of("type", "object");
        }
    }

    private Map<String, Object> response(Object id, Object result) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("jsonrpc", "2.0");
        o.put("id", id);
        o.put("result", result);
        return o;
    }

    private Map<String, Object> error(Object id, int code, String message) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("jsonrpc", "2.0");
        o.put("id", id);
        o.put("error", Map.of("code", code, "message", message));
        return o;
    }
}