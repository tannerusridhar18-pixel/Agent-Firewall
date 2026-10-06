package io.intentguard.gateway.api;
import io.intentguard.gateway.model.AgentSession;
import io.intentguard.gateway.repository.SessionRepository;
import io.intentguard.gateway.repository.TaskRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.web.bind.annotation.*;
import java.util.List;
@RestController @RequestMapping("/api/v1/sessions")
public class SessionController {
 private final SessionRepository sessions; private final TaskRepository tasks;
 public SessionController(SessionRepository sessions,TaskRepository tasks){this.sessions=sessions;this.tasks=tasks;}
 @PostMapping public AgentSession create(@Valid @RequestBody Request r){tasks.find(r.taskId());return sessions.create(r.agentId(),r.agentVersion(),r.taskId());}
 @GetMapping public List<AgentSession> list(){return sessions.findAll();}
 @GetMapping("/{id}") public AgentSession get(@PathVariable String id){return sessions.find(id);}
 public record Request(@NotBlank String agentId,@NotBlank String agentVersion,@NotBlank String taskId){}
}