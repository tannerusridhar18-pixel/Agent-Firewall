package io.intentguard.gateway.model;
import java.time.Instant; import java.util.List;
public record Task(String id,String actorId,String objective,List<String> allowedTools,List<String> allowedResources,List<String> forbiddenActions,String status,Instant expiresAt,Instant createdAt) {}