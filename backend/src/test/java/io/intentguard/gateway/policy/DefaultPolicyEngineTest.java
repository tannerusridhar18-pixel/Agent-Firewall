package io.intentguard.gateway.policy;
import io.intentguard.gateway.model.*; import org.junit.jupiter.api.Test; import java.time.Instant; import java.util.List; import static org.junit.jupiter.api.Assertions.assertEquals;
class DefaultPolicyEngineTest {
 private final DefaultPolicyEngine engine=new DefaultPolicyEngine();
 private Task task(){return new Task("T-1","actor","Analyze",List.of("read_file","run_tests"),List.of("workspace/src/*"),List.of("delete","external_upload"),"ACTIVE",Instant.now().plusSeconds(3600),Instant.now());}
 @Test void allowsInScope(){assertEquals(Decision.ALLOW,engine.evaluate(task(),"read_file","workspace/src/Auth.java").decision());}
 @Test void deniesUnknownTool(){assertEquals(Decision.DENY,engine.evaluate(task(),"shell","workspace/src/Auth.java").decision());}
 @Test void deniesOutOfScope(){assertEquals(Decision.DENY,engine.evaluate(task(),"read_file","secrets/passwords.txt").decision());}
 @Test void deniesExpired(){Task t=task();t=new Task(t.id(),t.actorId(),t.objective(),t.allowedTools(),t.allowedResources(),t.forbiddenActions(),t.status(),Instant.now().minusSeconds(1),t.createdAt());assertEquals(Decision.DENY,engine.evaluate(t,"read_file","workspace/src/Auth.java").decision());}
}