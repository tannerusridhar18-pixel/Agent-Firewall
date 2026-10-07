CREATE TABLE provenance_records (
    id VARCHAR(64) PRIMARY KEY,
    source_type VARCHAR(64) NOT NULL,
    trust_level VARCHAR(32) NOT NULL,
    parent_refs JSON NULL,
    sensitivity VARCHAR(32) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_provenance_trust ON provenance_records(trust_level);

ALTER TABLE mcp_tool_manifests
    ADD COLUMN risk_level VARCHAR(32) NOT NULL DEFAULT 'LOW',
    ADD COLUMN side_effect BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN sensitive_parameters JSON NULL,
    ADD COLUMN destination_constraints JSON NULL;

UPDATE mcp_tool_manifests
    SET risk_level = 'LOW', side_effect = FALSE, sensitive_parameters = JSON_ARRAY(), destination_constraints = JSON_OBJECT()
    WHERE tool_name = 'read_file';

CREATE TABLE approvals (
    approval_id VARCHAR(64) PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL UNIQUE,
    session_id VARCHAR(64) NOT NULL,
    task_id VARCHAR(64) NOT NULL,
    tool_name VARCHAR(128) NOT NULL,
    arguments_hash CHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    approver_id VARCHAR(128) NULL,
    created_at TIMESTAMP(6) NOT NULL,
    expires_at TIMESTAMP(6) NOT NULL,
    consumed_at TIMESTAMP(6) NULL,
    CONSTRAINT fk_approval_session FOREIGN KEY (session_id) REFERENCES agent_sessions(session_id),
    CONSTRAINT fk_approval_task FOREIGN KEY (task_id) REFERENCES tasks(id)
);
CREATE INDEX idx_approvals_request ON approvals(request_id);
CREATE INDEX idx_approvals_status_expiry ON approvals(status, expires_at);

CREATE TABLE session_quarantines (
    quarantine_id VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL,
    reason VARCHAR(255) NOT NULL,
    restrictions JSON NULL,
    quarantined_by VARCHAR(128) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    quarantined_at TIMESTAMP(6) NOT NULL,
    released_at TIMESTAMP(6) NULL,
    CONSTRAINT fk_quarantine_session FOREIGN KEY (session_id) REFERENCES agent_sessions(session_id)
);
CREATE INDEX idx_quarantine_session_active ON session_quarantines(session_id, active);

CREATE TABLE security_decisions (
    decision_id VARCHAR(64) PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL UNIQUE,
    session_id VARCHAR(64) NOT NULL,
    task_id VARCHAR(64) NOT NULL,
    tool_name VARCHAR(128) NOT NULL,
    arguments_hash CHAR(64) NOT NULL,
    provenance_refs JSON NULL,
    decision VARCHAR(32) NOT NULL,
    reason_codes JSON NOT NULL,
    risk_level VARCHAR(32) NOT NULL,
    risk_factors JSON NULL,
    policy_version VARCHAR(32) NOT NULL,
    approval_id VARCHAR(64) NULL,
    executed BOOLEAN NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT fk_decision_session FOREIGN KEY (session_id) REFERENCES agent_sessions(session_id),
    CONSTRAINT fk_decision_task FOREIGN KEY (task_id) REFERENCES tasks(id)
);
CREATE INDEX idx_decisions_request ON security_decisions(request_id);
CREATE INDEX idx_decisions_created ON security_decisions(created_at);

CREATE TABLE security_events (
    event_id VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL,
    task_id VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    request_id VARCHAR(64) NULL,
    message TEXT NOT NULL,
    metadata JSON NULL,
    created_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT fk_events_session FOREIGN KEY (session_id) REFERENCES agent_sessions(session_id),
    CONSTRAINT fk_events_task FOREIGN KEY (task_id) REFERENCES tasks(id)
);
CREATE INDEX idx_events_session ON security_events(session_id, created_at);
