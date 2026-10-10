package io.intentguard.gateway.agent;

import com.fasterxml.jackson.databind.JsonNode;
import io.intentguard.gateway.mcp.ToolManifest;
import io.intentguard.gateway.model.Task;
import io.intentguard.gateway.provenance.ProvenanceResolution;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class SecurityAgentService {
    private static final Logger log = LoggerFactory.getLogger(SecurityAgentService.class);

    private final DeterministicThreatDetector threatDetector;
    private final AiSecurityProvider aiProvider;
    private final SecurityAgentProperties properties;

    @Autowired
    public SecurityAgentService(DeterministicThreatDetector threatDetector,
                                AiSecurityProvider aiProvider,
                                SecurityAgentProperties properties) {
        this.threatDetector = threatDetector;
        this.aiProvider = aiProvider;
        this.properties = properties;
    }

    public SecurityAnalysisResult analyze(Task task, ToolManifest manifest, String toolName,
                                          String target, JsonNode arguments,
                                          ProvenanceResolution provenance) {
        if (!properties.isEnabled()) {
            return SecurityAnalysisResult.allow("Security agent disabled", "CONFIG");
        }

        String argsString = formatArguments(arguments);
        String taskObjective = task != null ? task.objective() : "None";

        // 1. Cheap Deterministic Pre-Check: Block obvious known attacks immediately without wasting AI tokens
        Optional<DeterministicThreatDetector.Detection> detection =
                threatDetector.detectThreat(toolName, target, argsString);

        if (detection.isPresent()) {
            var det = detection.get();
            log.warn("Deterministic threat detected: category={}, score={}, reason={}",
                    det.threatCategory(), det.riskScore(), det.reason());
            return SecurityAnalysisResult.block(det.threatCategory(), det.riskScore(), det.reason(), "DETERMINISTIC");
        }

        // 2. Active AI Security Agent: Intent & Threat Analysis
        boolean hasApiKey = (properties.getAi().getApiKey() != null && !properties.getAi().getApiKey().isBlank())
                || (System.getenv("OPENAI_API_KEY") != null && !System.getenv("OPENAI_API_KEY").isBlank())
                || !(aiProvider instanceof HttpAiSecurityProvider);

        if (properties.getAi().isEnabled() && aiProvider != null && hasApiKey) {
            try {
                AiAnalysisRequest aiReq = new AiAnalysisRequest(toolName, target, argsString, taskObjective);
                AiAnalysisResponse aiResp = aiProvider.analyze(aiReq);

                // Apply security policy to convert AI analysis into final decision
                double risk = aiResp.riskScore();
                if (aiResp.decision() == SecurityDecisionType.BLOCK || risk >= properties.getBlockThreshold()) {
                    return SecurityAnalysisResult.block(aiResp.threatCategory(), risk, aiResp.reason(), "AI");
                } else if (aiResp.decision() == SecurityDecisionType.FLAG || risk >= properties.getFlagThreshold()) {
                    return SecurityAnalysisResult.flag(aiResp.threatCategory(), risk, aiResp.reason(), "AI");
                } else {
                    return SecurityAnalysisResult.allow(aiResp.reason(), "AI");
                }

            } catch (AiProviderException e) {
                // Fail-Safe Principle: Provider errors or malformed AI output must never crash the system
                log.warn("AI security provider failure or malformed response: {}", e.getMessage());
                String category = e.getMessage().contains("Malformed") ? "MALFORMED_AI_RESPONSE" : "AI_ANALYSIS_FAILED";
                return SecurityAnalysisResult.flag(category, 0.70,
                        "AI analysis failed; failing safely to supervisor approval", "FAILSAFE");
            } catch (Exception e) {
                log.error("Unexpected error during AI security analysis: {}", e.getMessage(), e);
                return SecurityAnalysisResult.flag("SECURITY_AGENT_ERROR", 0.75,
                        "Security agent evaluation error; failing safely to supervisor approval", "FAILSAFE");
            }
        }

        // 3. Fallback when AI is disabled: evaluate using deterministic rules
        boolean ambiguous = threatDetector.isAmbiguous(toolName, target, argsString);
        if (ambiguous) {
            return SecurityAnalysisResult.flag("SUSPICIOUS_PATTERN", 0.50,
                    "Ambiguous request flagged for supervisor review (AI evaluation disabled)", "DETERMINISTIC");
        }

        return SecurityAnalysisResult.allow("Benign request verified deterministically", "DETERMINISTIC");
    }

    private String formatArguments(JsonNode arguments) {
        if (arguments == null || arguments.isNull() || arguments.isEmpty()) {
            return "";
        }
        return arguments.toString();
    }
}
