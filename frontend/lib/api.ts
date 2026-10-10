/**
 * IntentGuard V0.4 Gateway API Client
 * Proxied through Next.js rewrites to Spring Boot backend
 */

export interface SystemHealth {
  status: string;
  service?: string;
  version?: string;
  timestamp?: string;
}

export interface ActuatorHealth {
  status: string;
  groups?: string[];
}

export interface Task {
  id: string;
  actorId: string;
  objective: string;
  allowedTools: string[];
  allowedResources: string[];
  forbiddenActions: string[];
  status: string;
  expiresAt: string;
  createdAt: string;
}

export interface AgentSession {
  sessionId: string;
  agentId: string;
  agentVersion: string;
  taskId: string;
  status: string;
  createdAt: string;
}

export interface CapabilityMetadata {
  capabilityId: string;
  taskId: string;
  toolName: string;
  resourceScope: string;
  status: string;
  issuedAt: string;
  expiresAt: string;
  revokedAt?: string | null;
}

export interface IssueResponse extends CapabilityMetadata {
  token: string;
}

export interface RotateResponse extends CapabilityMetadata {
  rotatedFromId: string;
  token: string;
}

export interface QuarantineRecord {
  quarantineId: string;
  sessionId: string;
  reason: string;
  restrictions?: string | null;
  quarantinedBy: string;
  active: boolean;
  quarantinedAt: string;
  releasedAt?: string | null;
}

export interface Approval {
  approvalId: string;
  requestId: string;
  sessionId: string;
  taskId: string;
  toolName: string;
  argumentsHash: string;
  status: string;
  approverId?: string | null;
  createdAt: string;
  expiresAt: string;
  consumedAt?: string | null;
}

export interface SecurityDecision {
  decisionId: string;
  requestId: string;
  sessionId: string;
  taskId: string;
  toolName: string;
  argumentsHash: string;
  provenanceRefs?: string[];
  decision: string;
  reasonCodes: string[];
  riskLevel: string;
  riskFactors?: string[];
  policyVersion: string;
  approvalId?: string | null;
  executed: boolean;
  createdAt: string;
}

export interface SecuritySummary {
  totalAnalyzed: number;
  allowedRequests: number;
  flaggedRequests: number;
  blockedRequests: number;
  threatCategories: Record<string, number>;
  riskLevels: Record<string, number>;
  recentEvents: SecurityEvent[];
}

export interface SecurityEvent {
  eventId: string;
  sessionId: string;
  taskId: string;
  severity: string;
  eventType: string;
  requestId?: string | null;
  message: string;
  metadata?: Record<string, unknown> | null;
  createdAt: string;
}

export interface ActivityEvent {
  eventId: string;
  sessionId: string;
  taskId: string;
  activityType: string;
  source: string;
  tool: string;
  target?: string | null;
  decision: string;
  classification: string;
  reason: string;
  riskLevel: string;
  executionStatus: string;
  timestamp: string;
}

export interface McpTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  riskLevel?: string;
  sideEffect?: boolean;
}

export interface McpCallResult {
  jsonrpc: string;
  id: string | number;
  result?: {
    content?: Array<{ type: string; text: string }>;
    isError?: boolean;
    tools?: McpTool[];
    capabilities?: Record<string, unknown>;
    protocolVersion?: string;
    serverInfo?: { name: string; version: string };
  };
  error?: {
    code: number;
    message: string;
  };
}

export interface ParsedSecurityDecision {
  decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL" | "PROTOCOL_ERROR";
  reason: string;
  requestId?: string;
  riskLevel?: string;
  riskFactors?: string[];
  rawContent?: string;
  isError: boolean;
  gateBlocked?: number;
}

export interface OperatorConfig {
  key: string;
  operatorId: string;
}

export const DEFAULT_OPERATOR_CONFIG: OperatorConfig = {
  key: "intentguard-control-plane-secret-key",
  operatorId: "operator-admin",
};

function getOperatorHeaders(config: OperatorConfig = DEFAULT_OPERATOR_CONFIG): HeadersInit {
  return {
    "Content-Type": "application/json",
    "X-IntentGuard-Operator-Key": config.key,
    "X-Operator-Id": config.operatorId,
  };
}

/* ==================== SYSTEM & HEALTH ==================== */

export async function fetchHealth(): Promise<SystemHealth> {
  const res = await fetch("/api/backend/health");
  if (!res.ok) throw new Error(`Health check failed: ${res.status}`);
  return res.json();
}

export async function fetchActuator(): Promise<ActuatorHealth> {
  const res = await fetch("/actuator/health");
  if (!res.ok) throw new Error(`Actuator health failed: ${res.status}`);
  return res.json();
}

/* ==================== TASKS & SESSIONS ==================== */

export async function listTasks(): Promise<Task[]> {
  const res = await fetch("/api/backend/tasks");
  if (!res.ok) throw new Error(`Failed to list tasks: ${res.status}`);
  return res.json();
}

export async function createTask(data: {
  actorId: string;
  objective: string;
  allowedTools: string[];
  allowedResources: string[];
  forbiddenActions: string[];
}): Promise<Task> {
  const res = await fetch("/api/backend/tasks", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error(`Failed to create task: ${res.status}`);
  return res.json();
}

export async function listSessions(): Promise<AgentSession[]> {
  const res = await fetch("/api/backend/sessions");
  if (!res.ok) throw new Error(`Failed to list sessions: ${res.status}`);
  return res.json();
}

export async function createSession(data: {
  agentId: string;
  agentVersion: string;
  taskId: string;
}): Promise<AgentSession> {
  const res = await fetch("/api/backend/sessions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error(`Failed to create session: ${res.status}`);
  return res.json();
}

/* ==================== CAPABILITIES ==================== */

export async function issueCapability(
  data: {
    taskId: string;
    toolName: string;
    resourceScope: string;
    ttlSeconds?: number;
  },
  config: OperatorConfig = DEFAULT_OPERATOR_CONFIG
): Promise<IssueResponse> {
  const res = await fetch("/api/backend/control-plane/capabilities", {
    method: "POST",
    headers: getOperatorHeaders(config),
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Failed to issue capability (${res.status}): ${err}`);
  }
  return res.json();
}

export async function rotateCapability(
  capabilityId: string,
  ttlSeconds?: number,
  config: OperatorConfig = DEFAULT_OPERATOR_CONFIG
): Promise<RotateResponse> {
  const res = await fetch(`/api/backend/control-plane/capabilities/${capabilityId}/rotate`, {
    method: "POST",
    headers: getOperatorHeaders(config),
    body: JSON.stringify(ttlSeconds ? { ttlSeconds } : {}),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Failed to rotate capability (${res.status}): ${err}`);
  }
  return res.json();
}

export async function revokeCapability(
  capabilityId: string,
  config: OperatorConfig = DEFAULT_OPERATOR_CONFIG
): Promise<{ capabilityId: string; status: string; revokedAt: string }> {
  const res = await fetch(`/api/backend/control-plane/capabilities/${capabilityId}/revoke`, {
    method: "POST",
    headers: getOperatorHeaders(config),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Failed to revoke capability (${res.status}): ${err}`);
  }
  return res.json();
}

export async function listCapabilitiesByTask(
  taskId: string,
  config: OperatorConfig = DEFAULT_OPERATOR_CONFIG
): Promise<CapabilityMetadata[]> {
  const res = await fetch(`/api/backend/control-plane/capabilities?taskId=${encodeURIComponent(taskId)}`, {
    headers: getOperatorHeaders(config),
  });
  if (!res.ok) {
    throw new Error(`Failed to list capabilities (${res.status})`);
  }
  return res.json();
}

/* ==================== QUARANTINE ==================== */

export async function quarantineSession(
  sessionId: string,
  reason: string = "MANUAL_OPERATOR_QUARANTINE",
  config: OperatorConfig = DEFAULT_OPERATOR_CONFIG
): Promise<QuarantineRecord> {
  const res = await fetch(`/api/backend/sessions/${sessionId}/quarantine`, {
    method: "POST",
    headers: getOperatorHeaders(config),
    body: JSON.stringify({ reason }),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Failed to quarantine session (${res.status}): ${err}`);
  }
  return res.json();
}

export async function unquarantineSession(
  sessionId: string,
  config: OperatorConfig = DEFAULT_OPERATOR_CONFIG
): Promise<void> {
  const res = await fetch(`/api/backend/sessions/${sessionId}/unquarantine`, {
    method: "POST",
    headers: getOperatorHeaders(config),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Failed to unquarantine session (${res.status}): ${err}`);
  }
}

export async function getQuarantineStatus(
  sessionId: string,
  config: OperatorConfig = DEFAULT_OPERATOR_CONFIG
): Promise<QuarantineRecord | null> {
  const res = await fetch(`/api/backend/sessions/${sessionId}/quarantine`, {
    headers: getOperatorHeaders(config),
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`Failed to check quarantine status (${res.status})`);
  return res.json();
}

/* ==================== APPROVALS ==================== */

export async function approveRequest(
  requestId: string,
  config: OperatorConfig = DEFAULT_OPERATOR_CONFIG
): Promise<Approval> {
  const res = await fetch(`/api/backend/approvals/${requestId}/approve`, {
    method: "POST",
    headers: getOperatorHeaders(config),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Failed to approve request (${res.status}): ${err}`);
  }
  return res.json();
}

export async function denyRequest(
  requestId: string,
  config: OperatorConfig = DEFAULT_OPERATOR_CONFIG
): Promise<Approval> {
  const res = await fetch(`/api/backend/approvals/${requestId}/deny`, {
    method: "POST",
    headers: getOperatorHeaders(config),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Failed to deny request (${res.status}): ${err}`);
  }
  return res.json();
}

export async function getApproval(
  requestId: string,
  config: OperatorConfig = DEFAULT_OPERATOR_CONFIG
): Promise<Approval> {
  const res = await fetch(`/api/backend/approvals/${requestId}`, {
    headers: getOperatorHeaders(config),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Failed to get approval (${res.status}): ${err}`);
  }
  return res.json();
}

/* ==================== AUDIT & EVENTS ==================== */

export async function getAuditDecision(
  requestId: string,
  config: OperatorConfig = DEFAULT_OPERATOR_CONFIG
): Promise<SecurityDecision> {
  const res = await fetch(`/api/backend/audit/${requestId}`, {
    headers: getOperatorHeaders(config),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Failed to get audit decision (${res.status}): ${err}`);
  }
  return res.json();
}

export async function listSecurityEvents(
  limit: number = 50,
  config: OperatorConfig = DEFAULT_OPERATOR_CONFIG
): Promise<SecurityEvent[]> {
  const res = await fetch(`/api/backend/security-events?limit=${limit}`, {
    headers: getOperatorHeaders(config),
  });
  if (!res.ok) throw new Error(`Failed to list security events (${res.status})`);
  return res.json();
}

export async function fetchSecuritySummary(
  config: OperatorConfig = DEFAULT_OPERATOR_CONFIG
): Promise<SecuritySummary> {
  const res = await fetch("/api/backend/security-summary", {
    headers: getOperatorHeaders(config),
  });
  if (!res.ok) throw new Error(`Failed to fetch security summary (${res.status})`);
  return res.json();
}

export async function listActivity(): Promise<ActivityEvent[]> {
  const res = await fetch("/api/backend/activity");
  if (!res.ok) throw new Error(`Failed to list activity (${res.status})`);
  return res.json();
}

/* ==================== MCP GATEWAY ==================== */

export async function callMcp(params: {
  sessionId?: string;
  capabilityToken?: string;
  approvalRequestId?: string;
  body: Record<string, unknown>;
}): Promise<McpCallResult> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (params.sessionId) {
    headers["Mcp-Session-Id"] = params.sessionId;
  }
  if (params.capabilityToken) {
    headers["X-IntentGuard-Capability"] = params.capabilityToken;
  }
  if (params.approvalRequestId) {
    headers["X-IntentGuard-Approval"] = params.approvalRequestId;
  }

  const res = await fetch("/mcp", {
    method: "POST",
    headers,
    body: JSON.stringify(params.body),
  });

  return res.json();
}

export function parseMcpDecision(resp: McpCallResult): ParsedSecurityDecision {
  if (resp.error) {
    return {
      decision: "PROTOCOL_ERROR",
      reason: `${resp.error.code}: ${resp.error.message}`,
      isError: true,
      gateBlocked: 0,
    };
  }

  const result = resp.result;
  if (!result) {
    return {
      decision: "PROTOCOL_ERROR",
      reason: "Empty MCP result",
      isError: true,
      gateBlocked: 0,
    };
  }

  if (result.isError) {
    const text = result.content?.[0]?.text;
    if (text) {
      try {
        const parsed = JSON.parse(text);
        if (parsed.decision === "REQUIRE_APPROVAL") {
          return {
            decision: "REQUIRE_APPROVAL",
            reason: parsed.reason || "AWAITING_APPROVAL",
            requestId: parsed.requestId,
            riskLevel: parsed.riskLevel,
            riskFactors: parsed.riskFactors,
            rawContent: text,
            isError: true,
            gateBlocked: 6,
          };
        }
        if (parsed.reason === "REQUEST_DENIED") {
          const code = parsed.decision || "DENY";
          let gate = 2;
          if (code === "SESSION_QUARANTINED" || code === "INACTIVE_SESSION") gate = 1;
          else if (code.startsWith("CAPABILITY_") || code === "MISSING_CAPABILITY" || code === "INVALID_TOKEN") gate = 2;
          else if (code === "UNREGISTERED_TOOL") gate = 3;
          else if (code.includes("PROVENANCE")) gate = 4;
          else if (code.includes("POLICY") || code === "TOOL_OUTSIDE_TASK_SCOPE" || code === "RESOURCE_OUTSIDE_TASK_SCOPE") gate = 5;
          else if (code.startsWith("APPROVAL_")) gate = 6;
          return {
            decision: "DENY",
            reason: code,
            rawContent: text,
            isError: true,
            gateBlocked: gate,
          };
        }
      } catch {
        // Fallback if not JSON
      }
    }
    return {
      decision: "DENY",
      reason: text || "Tool execution error",
      rawContent: text,
      isError: true,
      gateBlocked: 2,
    };
  }

  // Execution succeeded!
  const text = result.content?.[0]?.text || "Success";
  return {
    decision: "ALLOW",
    reason: "ALLOW - All 8 Gates Succeeded",
    rawContent: text,
    isError: false,
    gateBlocked: undefined,
  };
}
