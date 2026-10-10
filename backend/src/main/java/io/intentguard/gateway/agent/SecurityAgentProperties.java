package io.intentguard.gateway.agent;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "intentguard.security-agent")
public class SecurityAgentProperties {
    private boolean enabled = true;
    private double blockThreshold = 0.80;
    private double flagThreshold = 0.40;
    private Ai ai = new Ai();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public double getBlockThreshold() {
        return blockThreshold;
    }

    public void setBlockThreshold(double blockThreshold) {
        this.blockThreshold = blockThreshold;
    }

    public double getFlagThreshold() {
        return flagThreshold;
    }

    public void setFlagThreshold(double flagThreshold) {
        this.flagThreshold = flagThreshold;
    }

    public Ai getAi() {
        return ai;
    }

    public void setAi(Ai ai) {
        this.ai = ai;
    }

    public static class Ai {
        private boolean enabled = false;
        private String provider = "openai";
        private String apiKey = "";
        private String endpoint = "https://api.openai.com/v1/chat/completions";
        private String model = "gpt-4o-mini";
        private int timeoutMs = 3000;
        private double temperature = 0.0;
        private int maxTokens = 150;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getProvider() {
            return provider;
        }

        public void setProvider(String provider) {
            this.provider = provider;
        }

        public String getApiKey() {
            return apiKey;
        }

        public void setApiKey(String apiKey) {
            this.apiKey = apiKey;
        }

        public String getEndpoint() {
            return endpoint;
        }

        public void setEndpoint(String endpoint) {
            this.endpoint = endpoint;
        }

        public String getModel() {
            return model;
        }

        public void setModel(String model) {
            this.model = model;
        }

        public int getTimeoutMs() {
            return timeoutMs;
        }

        public void setTimeoutMs(int timeoutMs) {
            this.timeoutMs = timeoutMs;
        }

        public double getTemperature() {
            return temperature;
        }

        public void setTemperature(double temperature) {
            this.temperature = temperature;
        }

        public int getMaxTokens() {
            return maxTokens;
        }

        public void setMaxTokens(int maxTokens) {
            this.maxTokens = maxTokens;
        }
    }
}
