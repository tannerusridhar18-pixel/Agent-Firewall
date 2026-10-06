package io.intentguard.gateway.policy;

import io.intentguard.gateway.common.Decision;
import io.intentguard.gateway.model.Task;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DefaultPolicyEngineTest {

    private final DefaultPolicyEngine engine = new DefaultPolicyEngine();

    private Task activeTask() {
        return new Task(
                "T-1",
                "actor-1",
                "Analyze project",
                List.of("read_file", "run_tests"),
                List.of("workspace/src/*"),
                List.of("delete", "external_upload"),
                "ACTIVE",
                Instant.now().plusSeconds(3600),
                Instant.now());
    }

    @Test
    void allowsToolInsideTaskAndResourceScope() {
        assertEquals(
                Decision.ALLOW,
                engine.evaluate(activeTask(), "read_file", "workspace/src/Auth.java"));
    }

    @Test
    void deniesUnregisteredTool() {
        assertEquals(
                Decision.DENY,
                engine.evaluate(activeTask(), "shell", "workspace/src/Auth.java"));
    }

    @Test
    void deniesOutOfScopeResource() {
        assertEquals(
                Decision.DENY,
                engine.evaluate(activeTask(), "read_file", "secrets/passwords.txt"));
    }

    @Test
    void deniesExpiredTask() {
        Task expired = new Task(
                activeTask().id(), activeTask().actorId(), activeTask().objective(),
                activeTask().allowedTools(), activeTask().allowedResources(),
                activeTask().forbiddenActions(), activeTask().status(),
                Instant.now().minusSeconds(1), activeTask().createdAt());

        assertEquals(
                Decision.DENY,
                engine.evaluate(expired, "read_file", "workspace/src/Auth.java"));
    }

    @Test
    void deniesInactiveTask() {
        Task inactive = new Task(
                activeTask().id(), activeTask().actorId(), activeTask().objective(),
                activeTask().allowedTools(), activeTask().allowedResources(),
                activeTask().forbiddenActions(), "CLOSED",
                activeTask().expiresAt(), activeTask().createdAt());

        assertEquals(
                Decision.DENY,
                engine.evaluate(inactive, "read_file", "workspace/src/Auth.java"));
    }

    @Test
    void deniesForbiddenAction() {
        assertEquals(
                Decision.DENY,
                engine.evaluate(activeTask(), "delete", "workspace/src/Auth.java"));
    }
}