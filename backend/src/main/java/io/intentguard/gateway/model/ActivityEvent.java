package io.intentguard.gateway.model;
import java.time.Instant;
public record ActivityEvent(String eventId,String sessionId,String taskId,String activityType,String source,String tool,String target,String decision,String classification,String reason,Instant timestamp) {}