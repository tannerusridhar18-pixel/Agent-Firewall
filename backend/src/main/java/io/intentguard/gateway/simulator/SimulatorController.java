package io.intentguard.gateway.simulator;

import io.intentguard.gateway.common.Decision;
import io.intentguard.gateway.model.*;
import io.intentguard.gateway.policy.PolicyEngine;
import io.intentguard.gateway.repository.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/simulator")
public class SimulatorController {
 private final TaskRepository tasks;
 private final SessionRepository sessions;
 private final ActivityRepository activity;
 private final PolicyEngine policy;

 public SimulatorController(TaskRepository tasks, SessionRepository sessions, ActivityRepository activity, PolicyEngine policy){
  this.tasks=tasks; this.sessions=sessions; this.activity=activity; this.policy=policy;
 }

 @PostMapping("/activity")
 public Result run(@Valid @RequestBody Request r){
  var session=sessions.find(r.sessionId());
  var task=tasks.find(session.taskId());
  boolean registered=task.allowedTools()!=null && task.allowedTools().contains(r.tool());
  boolean inTaskScope=task.allowedResources()!=null && task.allowedResources().stream().anyMatch(scope -> r.target().equals(scope) || r.target().startsWith(scope.replace("*","")));
  var decision=policy.evaluate(new PolicyEngine.PolicyInput(task.id(),session.sessionId(),r.tool(),registered,inTaskScope));
  var event=activity.append(session.sessionId(),task.id(),r.tool(),r.target(),decision.name(),"POLICY",decision.name());
  sessions.touch(session.sessionId(),event.timestamp());
  return new Result(event,decision.name(),decision==Decision.ALLOW);
 }

 public record Request(@NotBlank String sessionId,@NotBlank String tool,@NotBlank String target){}
 public record Result(ActivityEvent event,String decision,boolean executed){}
}