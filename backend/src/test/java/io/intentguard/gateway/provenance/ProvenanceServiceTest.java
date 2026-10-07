package io.intentguard.gateway.provenance;

import io.intentguard.gateway.mcp.ToolManifest;
import io.intentguard.gateway.model.Task;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ProvenanceServiceTest {

    private ProvenanceRepository repository;
    private ProvenanceService service;

    @BeforeEach
    void setUp() {
        repository = mock(ProvenanceRepository.class);
        service = new ProvenanceService(repository);
    }

    @Test
    void emptyProvenanceResolvesToTrustedPublic() {
        var res = service.resolve(Collections.emptyList(), "read_file", "workspace/src/A.java", null, null);
        assertTrue(res.valid());
        assertEquals("TRUSTED", res.trustLevel());
        assertEquals("PUBLIC", res.sensitivity());
    }

    @Test
    void validTrustedProvenanceIsAllowed() {
        when(repository.findById("P-1")).thenReturn(Optional.of(
                new ProvenanceRecord("P-1", "user_input", "TRUSTED", List.of(), "INTERNAL", Instant.now())));

        var res = service.resolve(List.of("P-1"), "read_file", "workspace/src/A.java", null, null);
        assertTrue(res.valid());
        assertEquals("TRUSTED", res.trustLevel());
        assertEquals("INTERNAL", res.sensitivity());
    }

    @Test
    void unknownProvenanceReferenceFailsClosed() {
        when(repository.findById("P-UNKNOWN")).thenReturn(Optional.empty());

        var res = service.resolve(List.of("P-UNKNOWN"), "read_file", "workspace/src/A.java", null, null);
        assertFalse(res.valid());
        assertEquals("INVALID_PROVENANCE_REF", res.failureReason());
    }

    @Test
    void untrustedProvenanceWithSideEffectToolIsDenied() {
        when(repository.findById("P-WEB")).thenReturn(Optional.of(
                new ProvenanceRecord("P-WEB", "web_fetch", "UNTRUSTED", List.of(), "PUBLIC", Instant.now())));

        ToolManifest writeManifest = new ToolManifest("write_file", "srv-1", "Write", "{}", true, "HIGH", true, "[]", "{}");

        var res = service.resolve(List.of("P-WEB"), "write_file", "workspace/output.txt", writeManifest, null);
        assertFalse(res.valid());
        assertEquals("UNTRUSTED_PROVENANCE", res.failureReason());
    }

    @Test
    void untrustedProvenanceWithEgressOperationIsDenied() {
        when(repository.findById("P-EXTERNAL")).thenReturn(Optional.of(
                new ProvenanceRecord("P-EXTERNAL", "untrusted_api", "UNTRUSTED", List.of(), "RESTRICTED", Instant.now())));

        ToolManifest emailManifest = new ToolManifest("send_email", "srv-1", "Email", "{}", true, "HIGH", true, "[]", "{}");

        var res = service.resolve(List.of("P-EXTERNAL"), "send_email", "external@dest.com", emailManifest, null);
        assertFalse(res.valid());
        assertEquals("UNTRUSTED_PROVENANCE", res.failureReason());
    }

    @Test
    void highestSensitivityIsAccuratelyAggregated() {
        when(repository.findById("P-1")).thenReturn(Optional.of(
                new ProvenanceRecord("P-1", "doc", "TRUSTED", List.of(), "INTERNAL", Instant.now())));
        when(repository.findById("P-2")).thenReturn(Optional.of(
                new ProvenanceRecord("P-2", "secret", "TRUSTED", List.of(), "RESTRICTED", Instant.now())));

        ToolManifest readManifest = new ToolManifest("read_file", "srv-1", "Read", "{}", true, "LOW", false, "[]", "{}");

        var res = service.resolve(List.of("P-1", "P-2"), "read_file", "workspace/docs", readManifest, null);
        assertTrue(res.valid());
        assertEquals("RESTRICTED", res.sensitivity());
    }
}
