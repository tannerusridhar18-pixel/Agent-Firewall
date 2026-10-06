package io.intentguard.gateway.policy;

import org.springframework.stereotype.Service;

import io.intentguard.gateway.common.Decision;

@Service
public class DefaultPolicyEngine implements PolicyEngine {

    @Override
    public Decision evaluate(PolicyInput input) {
        if (input == null
                || input.taskId() == null
                || input.sessionId() == null
                || input.tool() == null
                || !input.registered()
                || !input.inTaskScope()) {
            return Decision.DENY;
        }

        // V0.1 policy skeleton only. Protected MCP forwarding starts in V0.2.
        return Decision.REQUIRE_APPROVAL;
    }
}
