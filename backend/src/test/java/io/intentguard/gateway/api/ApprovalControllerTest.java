package io.intentguard.gateway.api;

import io.intentguard.gateway.approval.Approval;
import io.intentguard.gateway.approval.ApprovalService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;
import java.util.Optional;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class ApprovalControllerTest {

    private ApprovalService approvalService;
    private MockMvc mvc;
    private final String operatorKey = "test-operator-key";

    @BeforeEach
    void setUp() {
        approvalService = mock(ApprovalService.class);
        ApprovalController controller = new ApprovalController(approvalService, operatorKey);
        mvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    void unauthenticatedRequestIsRejected() throws Exception {
        mvc.perform(post("/api/v1/approvals/REQ-1/approve"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void approveSetsStatusAndReturnsOk() throws Exception {
        Approval approved = new Approval("A-1", "REQ-1", "S-1", "T-1", "read_file", "hash1",
                "APPROVED", "op-1", Instant.now(), Instant.now().plusSeconds(600), null);
        when(approvalService.approve("op-1", "REQ-1")).thenReturn(approved);

        mvc.perform(post("/api/v1/approvals/REQ-1/approve")
                .header("X-IntentGuard-Operator-Key", operatorKey)
                .header("X-Operator-Id", "op-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("APPROVED"))
                .andExpect(jsonPath("$.approverId").value("op-1"));
    }

    @Test
    void denySetsStatusAndReturnsOk() throws Exception {
        Approval denied = new Approval("A-1", "REQ-1", "S-1", "T-1", "read_file", "hash1",
                "DENIED", "op-1", Instant.now(), Instant.now().plusSeconds(600), null);
        when(approvalService.deny("op-1", "REQ-1")).thenReturn(denied);

        mvc.perform(post("/api/v1/approvals/REQ-1/deny")
                .header("X-IntentGuard-Operator-Key", operatorKey)
                .header("X-Operator-Id", "op-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DENIED"));
    }

    @Test
    void getReturnsApprovalDetails() throws Exception {
        Approval approval = new Approval("A-1", "REQ-1", "S-1", "T-1", "read_file", "hash1",
                "PENDING", null, Instant.now(), Instant.now().plusSeconds(600), null);
        when(approvalService.findByRequestId("REQ-1")).thenReturn(Optional.of(approval));

        mvc.perform(get("/api/v1/approvals/REQ-1")
                .header("X-IntentGuard-Operator-Key", operatorKey)
                .header("X-Operator-Id", "op-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.requestId").value("REQ-1"))
                .andExpect(jsonPath("$.status").value("PENDING"));
    }
}
