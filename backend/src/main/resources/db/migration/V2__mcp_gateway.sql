CREATE TABLE mcp_server_registrations (
 server_id VARCHAR(64) PRIMARY KEY,
 server_name VARCHAR(255) NOT NULL,
 endpoint_identity VARCHAR(512) NOT NULL,
 registration_status VARCHAR(32) NOT NULL,
 created_at TIMESTAMP(6) NOT NULL
);
CREATE TABLE mcp_tool_manifests (
 tool_name VARCHAR(128) PRIMARY KEY,
 server_id VARCHAR(64) NOT NULL,
 description TEXT NOT NULL,
 input_schema JSON NOT NULL,
 enabled BOOLEAN NOT NULL,
 created_at TIMESTAMP(6) NOT NULL,
 CONSTRAINT fk_mcp_tool_server FOREIGN KEY (server_id) REFERENCES mcp_server_registrations(server_id)
);
CREATE INDEX idx_mcp_tool_server ON mcp_tool_manifests(server_id);
INSERT INTO mcp_server_registrations(server_id,server_name,endpoint_identity,registration_status,created_at)
VALUES ('demo-protected-server','IntentGuard Protected Demo MCP Server','internal://intentguard/demo-protected-server','ACTIVE',CURRENT_TIMESTAMP(6));
INSERT INTO mcp_tool_manifests(tool_name,server_id,description,input_schema,enabled,created_at)
VALUES ('read_file','demo-protected-server','Read a file from the task-approved workspace.',
JSON_OBJECT('type','object','properties',JSON_OBJECT('target',JSON_OBJECT('type','string')),'required',JSON_ARRAY('target')),
TRUE,CURRENT_TIMESTAMP(6));