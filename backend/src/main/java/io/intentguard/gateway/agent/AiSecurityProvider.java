package io.intentguard.gateway.agent;

public interface AiSecurityProvider {
    AiAnalysisResponse analyze(AiAnalysisRequest request) throws AiProviderException;
}
