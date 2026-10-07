package io.intentguard.gateway.capability;

public record CapabilityDecision(boolean allowed, String reason) {
    public static CapabilityDecision allow() {
        return new CapabilityDecision(true, "ALLOW");
    }

    public static CapabilityDecision deny(String reason) {
        return new CapabilityDecision(false, reason);
    }
}
