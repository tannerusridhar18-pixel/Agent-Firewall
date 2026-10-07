package io.intentguard.gateway.api;

import io.intentguard.gateway.audit.AuditService;
import io.intentguard.gateway.audit.SecurityDecision;
import io.intentguard.gateway.audit.SecurityEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AuditControllerTest {

    private AuditService auditService;
    private MockMvc mvc;
    private final String operatorKey = "test-operator-key";

    @BeforeEach
    void setUp() {
        auditService = mock(AuditService.class);
        AuditController controller = new AuditController(auditService, operatorKey);
        mvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    void unauthenticatedAuditRequestIsRejected() throws Exception {
        mvc.perform(get("/api/v1/audit/REQ-1"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void getDecisionReturnsFullEvidenceTrail() throws Exception {
        SecurityDecision decision = new SecurityDecision(
                "DEC-1", "REQ-1", "S-1", "T-1", "read_file", "hash123",
                List.of("P-1"), "ALLOW", List.of("ALLOW"), "LOW", List.of(),
                "v0.4", null, true, Instant.now()
        );
        when(auditService.findDecisionByRequestId("REQ-1")).thenReturn(Optional.of(decision));

        mvc.perform(get("/api/v1/audit/REQ-1")
                .header("X-IntentGuard-Operator-Key", operatorKey)
                .header("X-Operator-Id", "op-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decisionId").value("DEC-1"))
                .andExpect(jsonPath("$.requestId").value("REQ-1"))
                .andExpect(jsonPath("$.argumentsHash").value("hash123"))
                .andExpect(jsonPath("$.executed").value(true));
    }

    @Test
    void listSecurityEventsReturnsEventsList() throws Exception {
        SecurityEvent event = new SecurityEvent(
                "EVT-1", "S-1", "T-1", "HIGH", "AUTOMATIC_QUARANTINE", "REQ-1",
                "Quarantined due to repeat violations", "{}", Instant.now()
        );
        when(auditService.listSecurityEvents(50)).thenReturn(List.of(event));

        mvc.perform(get("/api/v1/security-events?limit=50")
                .header("X-IntentGuard-Operator-Key", operatorKey)
                .header("X-Operator-Id", "op-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].eventId").value("EVT-1"))
                .andExpect(jsonPath("$[0].severity").value("HIGH"));
    }
}
