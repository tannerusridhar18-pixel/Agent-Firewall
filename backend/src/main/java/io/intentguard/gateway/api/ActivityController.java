package io.intentguard.gateway.api;
import io.intentguard.gateway.model.ActivityEvent;
import io.intentguard.gateway.repository.ActivityRepository;
import org.springframework.web.bind.annotation.*;
import java.util.List;
@RestController @RequestMapping("/api/v1")
public class ActivityController {
 private final ActivityRepository repo;
 public ActivityController(ActivityRepository repo){this.repo=repo;}
 @GetMapping("/activity") public List<ActivityEvent> recent(){return repo.recent();}
 @GetMapping("/sessions/{sessionId}/activity") public List<ActivityEvent> bySession(@PathVariable String sessionId){return repo.findBySession(sessionId);}
}