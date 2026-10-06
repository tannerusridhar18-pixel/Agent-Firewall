package io.intentguard.gateway.api;
import io.intentguard.gateway.model.Task;
import io.intentguard.gateway.repository.TaskRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.web.bind.annotation.*;
import java.time.Instant;
import java.util.List;
@RestController @RequestMapping("/api/v1/tasks")
public class TaskController {
 private final TaskRepository repo;
 public TaskController(TaskRepository repo){this.repo=repo;}
 @PostMapping public Task create(@Valid @RequestBody Request r){return repo.create(r.actorId(),r.objective(),r.allowedTools(),r.allowedResources(),r.forbiddenActions(),r.expiresAt()==null?Instant.now().plusSeconds(3600):r.expiresAt());}
 @GetMapping public List<Task> list(){return repo.findAll();}
 @GetMapping("/{id}") public Task get(@PathVariable String id){return repo.find(id);}
 public record Request(@NotBlank String actorId,@NotBlank String objective,List<String> allowedTools,List<String> allowedResources,List<String> forbiddenActions,Instant expiresAt){}
}