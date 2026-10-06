package io.intentguard.gateway.policy;

import io.intentguard.gateway.common.Decision;
import io.intentguard.gateway.model.Task;

public interface PolicyEngine {
    Decision evaluate(Task task, String tool, String target);
}