package io.intentguard.gateway.mcp;
import com.fasterxml.jackson.databind.JsonNode; import com.fasterxml.jackson.databind.ObjectMapper; import org.springframework.stereotype.Component;
import java.util.concurrent.atomic.AtomicInteger;
@Component public class MockProtectedReadFileTool implements ProtectedTool {
 private final ObjectMapper mapper; private final AtomicInteger executionCount=new AtomicInteger();
 public MockProtectedReadFileTool(ObjectMapper mapper){this.mapper=mapper;}
 public String name(){return "read_file";}
 public JsonNode execute(JsonNode arguments){executionCount.incrementAndGet();String target=arguments.path("target").asText();return mapper.createObjectNode().put("tool",name()).put("target",target).put("content","MOCK_PROTECTED_CONTENT").put("execution","DOWNSTREAM_TOOL_EXECUTED");}
 public int executionCount(){return executionCount.get();}
}