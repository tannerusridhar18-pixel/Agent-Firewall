package io.intentguard.gateway.agent;

import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

@Component
public class DeterministicThreatDetector {

    public record Detection(String threatCategory, double riskScore, String reason) {}

    private static final List<Pattern> PROMPT_INJECTION_PATTERNS = List.of(
            Pattern.compile("ignore\\s+(all\\s+)?(previous|prior|above)\\s+(instructions|directives|rules|prompts)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("disregard\\s+(all\\s+)?(previous|prior|above)\\s+(instructions|directives|rules)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(system\\s+prompt|prompt\\s+injection|jailbreak|dan\\s+mode|developer\\s+mode\\s+enabled)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(reveal|leak|output|dump|print)\\s+(your\\s+)?(system\\s+prompt|instructions|secret|api[\\s_-]?key|credentials)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(<\\|im_start\\|>|<\\|endoftext\\|>|\\[INST\\]|<<SYS>>|```system)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("you\\s+are\\s+now\\s+(an?\\s+)?(unrestricted|evil|unfiltered|jailbroken)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("bypass\\s+(all\\s+)?(guardrails|safety\\s+filters|security\\s+checks)", Pattern.CASE_INSENSITIVE)
    );

    private static final List<Pattern> COMMAND_INJECTION_PATTERNS = List.of(
            Pattern.compile("(;|\\|\\||&&)\\s*(rm\\s+-rf|del\\s+/f|shutdown|reboot|mkfs)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(\\|\\s*(sh|bash|zsh|dash|powershell|cmd\\.exe))", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(\\$\\((whoami|id|uname|cat\\s+/etc/passwd)\\)|`whoami`|`id`)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(curl|wget)\\s+https?://[^\\s]+\\s*(\\|\\s*(sh|bash)|>\\s*/)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(powershell\\s+(-enc|-encodedcommand)|cmd\\.exe\\s+/c)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(nc\\s+(-e|/bin/sh)|bash\\s+-i\\s+>&\\s*/dev/tcp/)", Pattern.CASE_INSENSITIVE)
    );

    private static final List<Pattern> PATH_TRAVERSAL_PATTERNS = List.of(
            Pattern.compile("(\\.\\./\\.\\./|\\.\\.\\\\|/etc/(passwd|shadow)|C:\\\\Windows\\\\System32)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(/proc/self/environ|~/.ssh/id_rsa|~/.aws/credentials)", Pattern.CASE_INSENSITIVE)
    );

    private static final List<Pattern> DATA_EXFILTRATION_PATTERNS = List.of(
            Pattern.compile("(webhook\\.site|burpcollaborator\\.net|oastify\\.com|ngrok\\.io)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(exfiltrate|leak_data|steal_keys)", Pattern.CASE_INSENSITIVE)
    );

    private static final List<Pattern> AMBIGUOUS_INTENT_PATTERNS = List.of(
            Pattern.compile("(override|reconfigure|execute\\s+arbitrary|extract\\s+token|admin\\s+rights)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(summarize\\s+and\\s+send|forward\\s+credentials|modify\\s+permissions)", Pattern.CASE_INSENSITIVE)
    );

    public Optional<Detection> detectThreat(String toolName, String target, String argumentsText) {
        String combined = combine(toolName, target, argumentsText);
        if (combined.isBlank()) {
            return Optional.empty();
        }

        // 1. Check Prompt Injection
        for (Pattern p : PROMPT_INJECTION_PATTERNS) {
            if (p.matcher(combined).find()) {
                return Optional.of(new Detection("PROMPT_INJECTION", 0.95, "Detected prompt injection attack pattern"));
            }
        }

        // 2. Check Command Injection
        for (Pattern p : COMMAND_INJECTION_PATTERNS) {
            if (p.matcher(combined).find()) {
                return Optional.of(new Detection("COMMAND_INJECTION", 0.98, "Detected malicious command execution syntax"));
            }
        }

        // 3. Check Path Traversal
        for (Pattern p : PATH_TRAVERSAL_PATTERNS) {
            if (p.matcher(combined).find()) {
                return Optional.of(new Detection("PATH_TRAVERSAL", 0.90, "Detected path traversal attempt"));
            }
        }

        // 4. Check Data Exfiltration
        for (Pattern p : DATA_EXFILTRATION_PATTERNS) {
            if (p.matcher(combined).find()) {
                return Optional.of(new Detection("DATA_EXFILTRATION", 0.92, "Detected data exfiltration destination"));
            }
        }

        return Optional.empty();
    }

    public boolean isAmbiguous(String toolName, String target, String argumentsText) {
        String combined = combine(toolName, target, argumentsText);
        if (combined.isBlank()) {
            return false;
        }

        for (Pattern p : AMBIGUOUS_INTENT_PATTERNS) {
            if (p.matcher(combined).find()) {
                return true;
            }
        }

        // Long natural language instructions in arguments warrant AI intent analysis
        if (argumentsText != null && argumentsText.length() > 60) {
            String lower = argumentsText.toLowerCase(Locale.ROOT);
            if (lower.contains("instruction") || lower.contains("query") || lower.contains("prompt")
                    || lower.contains("action") || lower.contains("script") || lower.contains("task")) {
                return true;
            }
        }

        return false;
    }

    private String combine(String toolName, String target, String argumentsText) {
        StringBuilder sb = new StringBuilder();
        if (toolName != null) sb.append(toolName).append(" ");
        if (target != null) sb.append(target).append(" ");
        if (argumentsText != null) sb.append(argumentsText);
        return sb.toString();
    }
}
