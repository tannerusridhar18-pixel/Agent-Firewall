package io.intentguard.gateway.risk;

import java.util.List;

public record RiskSnapshot(
        RiskLevel level,
        List<String> factors
) {}
