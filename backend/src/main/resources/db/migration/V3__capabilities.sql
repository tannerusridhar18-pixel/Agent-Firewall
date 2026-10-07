CREATE TABLE capabilities (
 capability_id VARCHAR(64) PRIMARY KEY,
 task_id VARCHAR(64) NOT NULL,
 tool_name VARCHAR(128) NOT NULL,
 resource_scope VARCHAR(512) NOT NULL,
 token_hash CHAR(64) NOT NULL UNIQUE,
 status VARCHAR(32) NOT NULL,
 issued_at TIMESTAMP(6) NOT NULL,
 expires_at TIMESTAMP(6) NOT NULL,
 revoked_at TIMESTAMP(6) NULL,
 CONSTRAINT fk_capability_task FOREIGN KEY (task_id) REFERENCES tasks(id)
);
CREATE INDEX idx_capability_task_tool ON capabilities(task_id, tool_name);
CREATE INDEX idx_capability_status_expiry ON capabilities(status, expires_at);
