package io.intentguard.gateway.agent;

public record SecurityAnalysisResult(
        SecurityDecisionType decision,
        double riskScore,
        String threatCategory,
        String reason,
        String analysisSource
) {
    public static SecurityAnalysisResult allow(String reason, String source) {
        return new SecurityAnalysisResult(SecurityDecisionType.ALLOW, 0.05, "NONE", reason, source);
    }

    public static SecurityAnalysisResult flag(String threatCategory, double riskScore, String reason, String source) {
        double boundedScore = Math.min(1.0, Math.max(0.0, riskScore));
        return new SecurityAnalysisResult(SecurityDecisionType.FLAG, boundedScore, threatCategory, reason, source);
    }

    public static SecurityAnalysisResult block(String threatCategory, double riskScore, String reason, String source) {
        double boundedScore = Math.min(1.0, Math.max(0.0, riskScore));
        return new SecurityAnalysisResult(SecurityDecisionType.BLOCK, boundedScore, threatCategory, reason, source);
    }
}
