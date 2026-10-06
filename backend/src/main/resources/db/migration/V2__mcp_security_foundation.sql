CREATE TABLE tool_server_registrations (
    server_id VARCHAR(64) PRIMARY KEY,
    server_name VARCHAR(255) NOT NULL,
    endpoint_identity VARCHAR(512) NOT NULL,
    trust_status VARCHAR(32) NOT NULL,
    registration_status VARCHAR(32) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
);

CREATE TABLE tool_manifests (
    tool_name VARCHAR(128) NOT NULL,
    server_id VARCHAR(64) NOT NULL,
    risk_level VARCHAR(32) NOT NULL,
    side_effect BOOLEAN NOT NULL,
    operation_class VARCHAR(64) NULL,
    sensitive_parameters JSON NULL,
    resource_constraints JSON NULL,
    version VARCHAR(32) NOT NULL,
    PRIMARY KEY (tool_name, server_id),
    CONSTRAINT fk_tool_manifest_server
        FOREIGN KEY (server_id) REFERENCES tool_server_registrations(server_id)
);

CREATE TABLE security_decisions (
    decision_id VARCHAR(64) PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL,
    decision VARCHAR(32) NOT NULL,
    reason_codes JSON NOT NULL,
    policy_version VARCHAR(32) NOT NULL,
    approval_id VARCHAR(64) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_security_decision_request (request_id)
);

CREATE TABLE audit_events (
    audit_id VARCHAR(64) PRIMARY KEY,
    request_id VARCHAR(64) NULL,
    session_id VARCHAR(64) NULL,
    task_id VARCHAR(64) NULL,
    event_type VARCHAR(64) NOT NULL,
    decision_ref VARCHAR(64) NULL,
    target_metadata JSON NULL,
    result_ref VARCHAR(128) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
);

CREATE INDEX idx_audit_events_session_time
    ON audit_events(session_id, created_at);
CREATE INDEX idx_security_decisions_created
    ON security_decisions(created_at);
