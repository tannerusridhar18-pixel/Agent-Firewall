package io.intentguard.gateway.agent;

public record AiAnalysisResponse(
        SecurityDecisionType decision,
        double riskScore,
        String threatCategory,
        String reason
) {}
