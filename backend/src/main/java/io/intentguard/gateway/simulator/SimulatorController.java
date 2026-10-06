package io.intentguard.gateway.simulator;

import io.intentguard.gateway.common.Decision;
import io.intentguard.gateway.model.ActivityEvent;
import io.intentguard.gateway.model.Task;
import io.intentguard.gateway.policy.PolicyEngine;
import io.intentguard.gateway.repository.ActivityRepository;
import io.intentguard.gateway.repository.SessionRepository;
import io.intentguard.gateway.repository.TaskRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/simulator")
public class SimulatorController {
    private final TaskRepository tasks;
    private final SessionRepository sessions;
    private final ActivityRepository activity;
    private final PolicyEngine policy;

    public SimulatorController(TaskRepository tasks, SessionRepository sessions,
                               ActivityRepository activity, PolicyEngine policy) {
        this.tasks = tasks;
        this.sessions = sessions;
        this.activity = activity;
        this.policy = policy;
    }

    @PostMapping("/activity")
    public Result run(@Valid @RequestBody Request request) {
        var session = sessions.find(request.sessionId());
        Task task = tasks.find(session.taskId());

        Decision decision = policy.evaluate(task, request.tool(), request.target());

        ActivityEvent event = activity.append(
                session.sessionId(), task.id(), request.tool(), request.target(),
                decision.name(), "POLICY", decision.name());

        sessions.touch(session.sessionId(), event.timestamp());

        return new Result(event, decision.name(), decision == Decision.ALLOW);
    }

    public record Request(
            @NotBlank String sessionId,
            @NotBlank String tool,
            @NotBlank String target) {}

    public record Result(ActivityEvent event, String decision, boolean executed) {}
}