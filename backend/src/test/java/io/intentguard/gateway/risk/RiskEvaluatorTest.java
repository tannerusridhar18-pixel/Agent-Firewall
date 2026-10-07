package io.intentguard.gateway.risk;

import io.intentguard.gateway.mcp.ToolManifest;
import io.intentguard.gateway.model.Task;
import io.intentguard.gateway.provenance.ProvenanceResolution;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RiskEvaluatorTest {

    private final RiskEvaluator evaluator = new RiskEvaluator();

    private Task task() {
        return new Task("T-1", "user", "Test", List.of("read_file", "send_email"), List.of("workspace/*"), List.of(), "ACTIVE", Instant.now().plusSeconds(3600), Instant.now());
    }

    @Test
    void benignReadOnlyActionYieldsLowRisk() {
        ToolManifest manifest = new ToolManifest("read_file", "s1", "Read", "{}", true, "LOW", false, "[]", "{}");
        ProvenanceResolution prov = ProvenanceResolution.allow("TRUSTED", "PUBLIC", Collections.emptyList());

        RiskSnapshot snapshot = evaluator.evaluate(task(), manifest, "workspace/A.txt", prov, 0);
        assertEquals(RiskLevel.LOW, snapshot.level());
        assertTrue(snapshot.factors().isEmpty());
    }

    @Test
    void sideEffectToolYieldsMediumRisk() {
        ToolManifest manifest = new ToolManifest("write_file", "s1", "Write", "{}", true, "LOW", true, "[]", "{}");
        ProvenanceResolution prov = ProvenanceResolution.allow("TRUSTED", "PUBLIC", Collections.emptyList());

        RiskSnapshot snapshot = evaluator.evaluate(task(), manifest, "workspace/out.txt", prov, 0);
        assertEquals(RiskLevel.MEDIUM, snapshot.level());
        assertTrue(snapshot.factors().contains("SIDE_EFFECT"));
    }

    @Test
    void highRiskToolYieldsHighRisk() {
        ToolManifest manifest = new ToolManifest("delete_file", "s1", "Delete", "{}", true, "HIGH", true, "[]", "{}");
        ProvenanceResolution prov = ProvenanceResolution.allow("TRUSTED", "PUBLIC", Collections.emptyList());

        RiskSnapshot snapshot = evaluator.evaluate(task(), manifest, "workspace/old.txt", prov, 0);
        assertEquals(RiskLevel.HIGH, snapshot.level());
        assertTrue(snapshot.factors().contains("HIGH_RISK_TOOL"));
        assertTrue(snapshot.factors().contains("SIDE_EFFECT"));
    }

    @Test
    void sideEffectWithUntrustedInputYieldsCriticalRisk() {
        ToolManifest manifest = new ToolManifest("send_email", "s1", "Send", "{}", true, "MEDIUM", true, "[]", "{}");
        ProvenanceResolution prov = ProvenanceResolution.allow("UNTRUSTED", "PUBLIC", Collections.emptyList());

        RiskSnapshot snapshot = evaluator.evaluate(task(), manifest, "target@example.com", prov, 0);
        assertEquals(RiskLevel.CRITICAL, snapshot.level());
        assertTrue(snapshot.factors().contains("UNTRUSTED_INPUT_PROVENANCE"));
        assertTrue(snapshot.factors().contains("SIDE_EFFECT"));
    }

    @Test
    void elevatedRecentDenialsIncreasesRiskFactor() {
        ToolManifest manifest = new ToolManifest("read_file", "s1", "Read", "{}", true, "LOW", false, "[]", "{}");
        ProvenanceResolution prov = ProvenanceResolution.allow("TRUSTED", "PUBLIC", Collections.emptyList());

        RiskSnapshot snapshot = evaluator.evaluate(task(), manifest, "workspace/A.txt", prov, 3);
        assertEquals(RiskLevel.HIGH, snapshot.level());
        assertTrue(snapshot.factors().contains("ELEVATED_SESSION_DENIALS"));
    }
}
