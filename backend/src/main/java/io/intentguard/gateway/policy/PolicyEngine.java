package io.intentguard.gateway.policy;

import io.intentguard.gateway.common.Decision;

public interface PolicyEngine {

    Decision evaluate(PolicyInput input);

    record PolicyInput(
            String taskId,
            String sessionId,
            String tool,
            boolean registered,
            boolean inTaskScope
    ) {}
}
