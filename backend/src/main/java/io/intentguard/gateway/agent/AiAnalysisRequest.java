package io.intentguard.gateway.agent;

public record AiAnalysisRequest(
        String toolName,
        String target,
        String argumentsSnippet,
        String taskObjective
) {}
