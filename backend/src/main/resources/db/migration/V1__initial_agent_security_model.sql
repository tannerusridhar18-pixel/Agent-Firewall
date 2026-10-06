CREATE TABLE tasks (
    id VARCHAR(64) PRIMARY KEY,
    actor_id VARCHAR(128) NOT NULL,
    objective TEXT NOT NULL,
    status VARCHAR(32) NOT NULL,
    expires_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
);

CREATE TABLE agent_sessions (
    session_id VARCHAR(64) PRIMARY KEY,
    agent_id VARCHAR(128) NOT NULL,
    actor_id VARCHAR(128) NOT NULL,
    task_id VARCHAR(64) NULL,
    status VARCHAR(32) NOT NULL,
    started_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    ended_at TIMESTAMP(6) NULL,
    last_activity_at TIMESTAMP(6) NULL,
    CONSTRAINT fk_agent_session_task
        FOREIGN KEY (task_id) REFERENCES tasks(id)
);

CREATE INDEX idx_agent_sessions_task_id ON agent_sessions(task_id);
CREATE INDEX idx_agent_sessions_status ON agent_sessions(status);

CREATE TABLE activity_events (
    event_id VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL,
    task_id VARCHAR(64) NULL,
    event_type VARCHAR(64) NOT NULL,
    target VARCHAR(255) NOT NULL,
    classification VARCHAR(32) NULL,
    occurred_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_activity_session
        FOREIGN KEY (session_id) REFERENCES agent_sessions(session_id),
    CONSTRAINT fk_activity_task
        FOREIGN KEY (task_id) REFERENCES tasks(id)
);

CREATE INDEX idx_activity_events_session_time
    ON activity_events(session_id, occurred_at);
