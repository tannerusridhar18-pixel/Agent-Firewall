package io.intentguard.gateway.policy;

import io.intentguard.gateway.common.Decision;
import java.util.List;

public record PolicyEvaluationResult(
        Decision decision,
        List<String> reasonCodes
) {
    public static PolicyEvaluationResult allow() {
        return new PolicyEvaluationResult(Decision.ALLOW, List.of("ALLOW"));
    }

    public static PolicyEvaluationResult deny(String reason) {
        return new PolicyEvaluationResult(Decision.DENY, List.of(reason));
    }

    public static PolicyEvaluationResult deny(List<String> reasons) {
        return new PolicyEvaluationResult(Decision.DENY, reasons);
    }

    public static PolicyEvaluationResult requireApproval(List<String> reasons) {
        return new PolicyEvaluationResult(Decision.REQUIRE_APPROVAL, reasons);
    }
}
