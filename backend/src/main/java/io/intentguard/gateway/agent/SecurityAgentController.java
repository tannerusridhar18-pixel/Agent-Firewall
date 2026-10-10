package io.intentguard.gateway.agent;

import com.fasterxml.jackson.databind.JsonNode;
import io.intentguard.gateway.model.Task;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

@RestController
@RequestMapping("/api/v1/security")
public class SecurityAgentController {
    private final SecurityAgentService securityAgent;

    public SecurityAgentController(SecurityAgentService securityAgent) {
        this.securityAgent = securityAgent;
    }

    public record AnalyzeRequest(
            String toolName,
            String target,
            JsonNode arguments,
            String taskObjective
    ) {}

    @PostMapping("/analyze")
    public ResponseEntity<SecurityAnalysisResult> analyze(@RequestBody AnalyzeRequest request) {
        Task task = null;
        if (request.taskObjective() != null && !request.taskObjective().isBlank()) {
            task = new Task(
                    "INSPECT-TASK",
                    "operator",
                    request.taskObjective(),
                    request.toolName() != null ? List.of(request.toolName()) : Collections.emptyList(),
                    List.of("*"),
                    Collections.emptyList(),
                    "ACTIVE",
                    Instant.now().plusSeconds(3600),
                    Instant.now()
            );
        }

        SecurityAnalysisResult result = securityAgent.analyze(
                task,
                null,
                request.toolName(),
                request.target(),
                request.arguments(),
                null
        );

        return ResponseEntity.ok(result);
    }
}
