package io.intentguard.gateway.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.intentguard.gateway.capability.Capability;
import io.intentguard.gateway.capability.CapabilityService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class CapabilityControlPlaneControllerTest {

    private static final String VALID_KEY = "test-secret-operator-key";
    private CapabilityService capabilityService;
    private MockMvc mvc;
    private ObjectMapper mapper;

    @BeforeEach
    void setUp() {
        capabilityService = mock(CapabilityService.class);
        var controller = new CapabilityControlPlaneController(capabilityService, VALID_KEY);
        mvc = MockMvcBuilders.standaloneSetup(controller).build();
        mapper = new ObjectMapper();
    }

    @Test
    void issueWithValidOperatorCredentialsSucceeds() throws Exception {
        Instant now = Instant.now();
        Capability cap = new Capability("CAP-1", "T-1", "read_file", "workspace/src/*",
                "hash123", "ACTIVE", now, now.plusSeconds(3600), null);
        when(capabilityService.issue(eq("operator-1"), eq("T-1"), eq("read_file"), eq("workspace/src/*"), any(Duration.class)))
                .thenReturn(new CapabilityService.IssuedCapability(cap, "raw-token-abc"));

        mvc.perform(post("/api/v1/control-plane/capabilities")
                .header("X-IntentGuard-Operator-Key", VALID_KEY)
                .header("X-Operator-Id", "operator-1")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(new CapabilityControlPlaneController.IssueRequest(
                        "T-1", "read_file", "workspace/src/*", 3600L))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.capabilityId").value("CAP-1"))
                .andExpect(jsonPath("$.taskId").value("T-1"))
                .andExpect(jsonPath("$.toolName").value("read_file"))
                .andExpect(jsonPath("$.resourceScope").value("workspace/src/*"))
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.token").value("raw-token-abc"));
    }

    @Test
    void issueWithoutOperatorKeyReturnsUnauthorized() throws Exception {
        mvc.perform(post("/api/v1/control-plane/capabilities")
                .header("X-Operator-Id", "operator-1")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(new CapabilityControlPlaneController.IssueRequest(
                        "T-1", "read_file", "workspace/src/*", 3600L))))
                .andExpect(status().isUnauthorized());

        verifyNoInteractions(capabilityService);
    }

    @Test
    void issueWithInvalidOperatorKeyReturnsUnauthorized() throws Exception {
        mvc.perform(post("/api/v1/control-plane/capabilities")
                .header("X-IntentGuard-Operator-Key", "wrong-key")
                .header("X-Operator-Id", "operator-1")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(new CapabilityControlPlaneController.IssueRequest(
                        "T-1", "read_file", "workspace/src/*", 3600L))))
                .andExpect(status().isUnauthorized());

        verifyNoInteractions(capabilityService);
    }

    @Test
    void issueWithoutOperatorIdReturnsUnauthorized() throws Exception {
        mvc.perform(post("/api/v1/control-plane/capabilities")
                .header("X-IntentGuard-Operator-Key", VALID_KEY)
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(new CapabilityControlPlaneController.IssueRequest(
                        "T-1", "read_file", "workspace/src/*", 3600L))))
                .andExpect(status().isUnauthorized());

        verifyNoInteractions(capabilityService);
    }

    @Test
    void issueWithUnauthorizedOperatorReturnsForbidden() throws Exception {
        when(capabilityService.issue(eq("unauthorized-operator"), eq("T-1"), eq("read_file"), eq("workspace/src/*"), any(Duration.class)))
                .thenThrow(new SecurityException("Operator unauthorized-operator is not authorized for task T-1"));

        mvc.perform(post("/api/v1/control-plane/capabilities")
                .header("X-IntentGuard-Operator-Key", VALID_KEY)
                .header("X-Operator-Id", "unauthorized-operator")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(new CapabilityControlPlaneController.IssueRequest(
                        "T-1", "read_file", "workspace/src/*", 3600L))))
                .andExpect(status().isForbidden());
    }

    @Test
    void issueWithInvalidParametersReturnsBadRequest() throws Exception {
        when(capabilityService.issue(eq("operator-1"), eq("T-1"), eq("forbidden_tool"), eq("workspace/src/*"), any(Duration.class)))
                .thenThrow(new IllegalArgumentException("Tool forbidden_tool is not permitted by task"));

        mvc.perform(post("/api/v1/control-plane/capabilities")
                .header("X-IntentGuard-Operator-Key", VALID_KEY)
                .header("X-Operator-Id", "operator-1")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(new CapabilityControlPlaneController.IssueRequest(
                        "T-1", "forbidden_tool", "workspace/src/*", 3600L))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void rotateRevokesOldAndIssuesReplacementWithNewToken() throws Exception {
        Instant now = Instant.now();
        Capability newCap = new Capability("CAP-2", "T-1", "read_file", "workspace/src/*",
                "hash456", "ACTIVE", now, now.plusSeconds(3600), null);
        when(capabilityService.rotate(eq("operator-1"), eq("CAP-1"), any()))
                .thenReturn(new CapabilityService.RotatedCapability("CAP-1", newCap, "new-token-xyz"));

        mvc.perform(post("/api/v1/control-plane/capabilities/CAP-1/rotate")
                .header("X-IntentGuard-Operator-Key", VALID_KEY)
                .header("X-Operator-Id", "operator-1")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"ttlSeconds\": 3600}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.capabilityId").value("CAP-2"))
                .andExpect(jsonPath("$.rotatedFromId").value("CAP-1"))
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.token").value("new-token-xyz"));
    }

    @Test
    void rotateUnknownCapabilityReturnsNotFound() throws Exception {
        when(capabilityService.rotate(eq("operator-1"), eq("CAP-UNKNOWN"), any()))
                .thenThrow(new IllegalArgumentException("Capability not found: CAP-UNKNOWN"));

        mvc.perform(post("/api/v1/control-plane/capabilities/CAP-UNKNOWN/rotate")
                .header("X-IntentGuard-Operator-Key", VALID_KEY)
                .header("X-Operator-Id", "operator-1"))
                .andExpect(status().isNotFound());
    }

    @Test
    void revokeCapabilitySucceeds() throws Exception {
        doNothing().when(capabilityService).revoke("operator-1", "CAP-1");

        mvc.perform(post("/api/v1/control-plane/capabilities/CAP-1/revoke")
                .header("X-IntentGuard-Operator-Key", VALID_KEY)
                .header("X-Operator-Id", "operator-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.capabilityId").value("CAP-1"))
                .andExpect(jsonPath("$.status").value("REVOKED"));

        verify(capabilityService).revoke("operator-1", "CAP-1");
    }

    @Test
    void getCapabilityMetadataReturnsDetailsWithoutRawToken() throws Exception {
        Instant now = Instant.now();
        Capability cap = new Capability("CAP-1", "T-1", "read_file", "workspace/src/*",
                "secret-hash-not-token", "ACTIVE", now, now.plusSeconds(3600), null);
        when(capabilityService.findById("CAP-1")).thenReturn(Optional.of(cap));

        mvc.perform(get("/api/v1/control-plane/capabilities/CAP-1")
                .header("X-IntentGuard-Operator-Key", VALID_KEY)
                .header("X-Operator-Id", "operator-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.capabilityId").value("CAP-1"))
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.token").doesNotExist())
                .andExpect(jsonPath("$.tokenHash").doesNotExist());
    }

    @Test
    void listCapabilitiesByTaskReturnsMetadataWithoutRawTokens() throws Exception {
        Instant now = Instant.now();
        Capability cap = new Capability("CAP-1", "T-1", "read_file", "workspace/src/*",
                "secret-hash-not-token", "ACTIVE", now, now.plusSeconds(3600), null);
        when(capabilityService.findByTaskId("T-1")).thenReturn(List.of(cap));

        mvc.perform(get("/api/v1/control-plane/capabilities")
                .header("X-IntentGuard-Operator-Key", VALID_KEY)
                .header("X-Operator-Id", "operator-1")
                .param("taskId", "T-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].capabilityId").value("CAP-1"))
                .andExpect(jsonPath("$[0].token").doesNotExist())
                .andExpect(jsonPath("$[0].tokenHash").doesNotExist());
    }
}
