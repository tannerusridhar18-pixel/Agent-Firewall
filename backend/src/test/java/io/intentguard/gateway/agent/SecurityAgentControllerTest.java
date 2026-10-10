package io.intentguard.gateway.agent;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class SecurityAgentControllerTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private SecurityAgentService securityAgent;
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        securityAgent = mock(SecurityAgentService.class);
        SecurityAgentController controller = new SecurityAgentController(securityAgent);
        mvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    void analyzeEndpoint_returnsStructuredSecurityAnalysis() throws Exception {
        when(securityAgent.analyze(any(), any(), any(), any(), any(), any()))
                .thenReturn(new SecurityAnalysisResult(SecurityDecisionType.ALLOW, 0.05, "NONE", "Legitimate query", "DETERMINISTIC"));

        var body = new SecurityAgentController.AnalyzeRequest(
                "read_file",
                "workspace/docs/a.txt",
                mapper.createObjectNode().put("target", "workspace/docs/a.txt"),
                "Read documentation"
        );

        mvc.perform(post("/api/v1/security/analyze")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(body)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision", is("ALLOW")))
                .andExpect(jsonPath("$.riskScore", is(0.05)))
                .andExpect(jsonPath("$.threatCategory", is("NONE")))
                .andExpect(jsonPath("$.reason", is("Legitimate query")))
                .andExpect(jsonPath("$.analysisSource", is("DETERMINISTIC")));
    }
}
