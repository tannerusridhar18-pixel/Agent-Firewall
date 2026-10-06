package io.intentguard.gateway.api;

import java.time.Instant;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class SystemController {

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "service", "intentguard-gateway",
                "version", "0.1.0",
                "timestamp", Instant.now().toString()
        ));
    }

    @GetMapping("/readiness")
    public ResponseEntity<Map<String, Object>> readiness() {
        return ResponseEntity.ok(Map.of(
                "status", "READY",
                "service", "intentguard-gateway",
                "timestamp", Instant.now().toString()
        ));
    }
}
