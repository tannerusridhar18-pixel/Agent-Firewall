CREATE TABLE tasks (
 id VARCHAR(64) PRIMARY KEY,
 actor_id VARCHAR(128) NOT NULL,
 objective TEXT NOT NULL,
 allowed_tools JSON NOT NULL,
 allowed_resources JSON NOT NULL,
 forbidden_actions JSON NOT NULL,
 status VARCHAR(32) NOT NULL,
 expires_at TIMESTAMP(6) NOT NULL,
 created_at TIMESTAMP(6) NOT NULL
);
CREATE TABLE agent_sessions (
 session_id VARCHAR(64) PRIMARY KEY,
 agent_id VARCHAR(128) NOT NULL,
 agent_version VARCHAR(64) NOT NULL,
 task_id VARCHAR(64) NOT NULL,
 status VARCHAR(32) NOT NULL,
 policy_version VARCHAR(32) NOT NULL,
 started_at TIMESTAMP(6) NOT NULL,
 ended_at TIMESTAMP(6),
 last_activity_at TIMESTAMP(6),
 CONSTRAINT fk_session_task FOREIGN KEY (task_id) REFERENCES tasks(id)
);
CREATE INDEX idx_sessions_task ON agent_sessions(task_id);
CREATE INDEX idx_sessions_status ON agent_sessions(status);
CREATE TABLE activity_events (
 event_id VARCHAR(64) PRIMARY KEY,
 session_id VARCHAR(64) NOT NULL,
 task_id VARCHAR(64) NOT NULL,
 activity_type VARCHAR(64) NOT NULL,
 source VARCHAR(64) NOT NULL,
 tool VARCHAR(128) NOT NULL,
 target VARCHAR(512) NOT NULL,
 decision VARCHAR(32) NOT NULL,
 classification VARCHAR(64) NOT NULL,
 reason VARCHAR(255) NOT NULL,
 occurred_at TIMESTAMP(6) NOT NULL,
 CONSTRAINT fk_activity_session FOREIGN KEY (session_id) REFERENCES agent_sessions(session_id),
 CONSTRAINT fk_activity_task FOREIGN KEY (task_id) REFERENCES tasks(id)
);
CREATE INDEX idx_activity_session_time ON activity_events(session_id, occurred_at);
CREATE INDEX idx_activity_time ON activity_events(occurred_at);