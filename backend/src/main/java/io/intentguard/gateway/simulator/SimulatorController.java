package io.intentguard.gateway.simulator;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import io.intentguard.gateway.activity.ActivityEvent;
import io.intentguard.gateway.common.Decision;
import io.intentguard.gateway.policy.PolicyEngine;

@RestController
@RequestMapping("/api/v1/simulator")
public class SimulatorController {

    private final PolicyEngine policyEngine;

    public SimulatorController(PolicyEngine policyEngine) {
        this.policyEngine = policyEngine;
    }

    @PostMapping("/activity")
    public ResponseEntity<Map<String, Object>> simulate(
            @RequestBody SimulatorRequest request) {

        var event = new ActivityEvent(
                "E-" + UUID.randomUUID(),
                request.sessionId(),
                request.taskId(),
                "TOOL_CALL",
                "SIMULATOR",
                request.target(),
                Instant.now()
        );

        Decision decision = policyEngine.evaluate(
                new PolicyEngine.PolicyInput(
                        request.taskId(),
                        request.sessionId(),
                        request.tool(),
                        request.registered(),
                        request.inTaskScope()
                )
        );

        return ResponseEntity.ok(Map.of(
                "event", event,
                "decision", decision,
                "executed", false,
                "message", "V0.1 simulator only; protected MCP forwarding is introduced in V0.2."
        ));
    }

    public record SimulatorRequest(
            String taskId,
            String sessionId,
            String tool,
            String target,
            boolean registered,
            boolean inTaskScope
    ) {}
}
