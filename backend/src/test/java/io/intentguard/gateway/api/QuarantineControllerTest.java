package io.intentguard.gateway.api;

import io.intentguard.gateway.quarantine.QuarantineRecord;
import io.intentguard.gateway.quarantine.QuarantineService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;
import java.util.Optional;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class QuarantineControllerTest {

    private QuarantineService quarantineService;
    private MockMvc mvc;
    private final String operatorKey = "test-operator-key";

    @BeforeEach
    void setUp() {
        quarantineService = mock(QuarantineService.class);
        QuarantineController controller = new QuarantineController(quarantineService, operatorKey);
        mvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    void unauthenticatedQuarantineIsRejected() throws Exception {
        mvc.perform(post("/api/v1/sessions/S-1/quarantine"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void quarantineSessionReturnsRecord() throws Exception {
        QuarantineRecord record = new QuarantineRecord("Q-1", "S-1", "SUSPICIOUS_CALLS", "{}", "op-1", true, Instant.now(), null);
        when(quarantineService.quarantine(eq("S-1"), eq("SUSPICIOUS_CALLS"), eq("op-1"), any())).thenReturn(record);

        mvc.perform(post("/api/v1/sessions/S-1/quarantine")
                .header("X-IntentGuard-Operator-Key", operatorKey)
                .header("X-Operator-Id", "op-1")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"reason\":\"SUSPICIOUS_CALLS\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.quarantineId").value("Q-1"))
                .andExpect(jsonPath("$.sessionId").value("S-1"))
                .andExpect(jsonPath("$.active").value(true));
    }

    @Test
    void unquarantineSessionReturnsOk() throws Exception {
        mvc.perform(post("/api/v1/sessions/S-1/unquarantine")
                .header("X-IntentGuard-Operator-Key", operatorKey)
                .header("X-Operator-Id", "op-1"))
                .andExpect(status().isOk());

        verify(quarantineService).unquarantine("S-1", "op-1");
    }

    @Test
    void getQuarantineReturnsActiveRecord() throws Exception {
        QuarantineRecord record = new QuarantineRecord("Q-1", "S-1", "MANUAL", "{}", "op-1", true, Instant.now(), null);
        when(quarantineService.getActiveQuarantine("S-1")).thenReturn(Optional.of(record));

        mvc.perform(get("/api/v1/sessions/S-1/quarantine")
                .header("X-IntentGuard-Operator-Key", operatorKey)
                .header("X-Operator-Id", "op-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sessionId").value("S-1"))
                .andExpect(jsonPath("$.active").value(true));
    }
}
