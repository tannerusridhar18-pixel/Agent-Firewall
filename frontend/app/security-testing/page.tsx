"use client";

import { useCallback, useEffect, useState } from "react";
import { Header } from "../../components/Header";
import {
  ActivityEvent,
  ActuatorHealth,
  DEFAULT_OPERATOR_CONFIG,
  OperatorConfig,
  ParsedSecurityDecision,
  SystemHealth,
  fetchActuator,
  fetchHealth,
  listActivity,
  parseMcpDecision,
} from "../../lib/api";

type AuthMode = "valid" | "invalid" | "none";

interface TestCase {
  id: string;
  title: string;
  description: string;
  expected: string;
  authMode: AuthMode;
  target: string;
  expectedDecision: ParsedSecurityDecision["decision"];
  expectedReason?: string;
  expectsExecution: boolean;
  checksAudit?: boolean;
}

interface TestResult {
  id: string;
  title: string;
  expected: string;
  actual: string;
  decision: string;
  reason: string;
  executed: boolean;
  status: "PASS" | "FAIL";
  timestamp: string;
  error?: string;
}

const TEST_CASES: TestCase[] = [
  {
    id: "valid-authentication",
    title: "Valid authentication",
    description: "A valid server-side MCP credential reaches the gateway.",
    expected: "Authenticated request is accepted by the MCP gateway.",
    authMode: "valid",
    target: "workspace/src/App.java",
    expectedDecision: "ALLOW",
    expectsExecution: true,
  },
  {
    id: "missing-authentication",
    title: "Missing authentication",
    description: "No authorization header is sent to the gateway.",
    expected: "The gateway returns an unauthorized protocol error.",
    authMode: "none",
    target: "workspace/src/App.java",
    expectedDecision: "PROTOCOL_ERROR",
    expectsExecution: false,
  },
  {
    id: "invalid-authentication",
    title: "Invalid authentication",
    description: "A deliberately invalid credential is rejected.",
    expected: "The gateway returns an unauthorized protocol error.",
    authMode: "invalid",
    target: "workspace/src/App.java",
    expectedDecision: "PROTOCOL_ERROR",
    expectsExecution: false,
  },
  {
    id: "resource-scope-denial",
    title: "Resource-scope denial",
    description: "A validly authenticated request targets a resource outside the default task scope.",
    expected: "The request is denied before protected-tool execution.",
    authMode: "valid",
    target: "secrets/passwords.txt",
    expectedDecision: "DENY",
    expectedReason: "CAPABILITY_SCOPE_DENIED",
    expectsExecution: false,
  },
  {
    id: "mock-tool-execution",
    title: "Successful mock tool execution",
    description: "An in-scope workspace resource reaches the protected mock read_file handler.",
    expected: "The mock tool returns content and reports downstream execution.",
    authMode: "valid",
    target: "workspace/src/App.java",
    expectedDecision: "ALLOW",
    expectsExecution: true,
  },
  {
    id: "audit-logging",
    title: "Audit logging",
    description: "A scope denial is followed by a read of the existing activity API.",
    expected: "The denial appears once with target, reason, DENY decision, and DENY execution status.",
    authMode: "valid",
    target: "secrets/audit-validation.txt",
    expectedDecision: "DENY",
    expectedReason: "CAPABILITY_SCOPE_DENIED",
    expectsExecution: false,
    checksAudit: true,
  },
];

function requestFor(test: TestCase) {
  return {
    jsonrpc: "2.0",
    id: `${test.id}-${Date.now()}`,
    method: "tools/call",
    params: {
      name: "read_file",
      arguments: { target: test.target },
    },
  };
}

export default function SecurityTestingPage() {
  const [operatorConfig, setOperatorConfig] = useState<OperatorConfig>(DEFAULT_OPERATOR_CONFIG);
  const [systemHealth, setSystemHealth] = useState<SystemHealth | null>(null);
  const [actuatorHealth, setActuatorHealth] = useState<ActuatorHealth | null>(null);
  const [results, setResults] = useState<TestResult[]>([]);
  const [running, setRunning] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refreshHealth = useCallback(async () => {
    const [system, actuator] = await Promise.allSettled([fetchHealth(), fetchActuator()]);
    setSystemHealth(system.status === "fulfilled" ? system.value : null);
    setActuatorHealth(actuator.status === "fulfilled" ? actuator.value : null);
  }, []);

  useEffect(() => {
    refreshHealth().finally(() => setLoading(false));
  }, [refreshHealth]);

  useEffect(() => {
    const stored = window.localStorage.getItem("agent-firewall-security-test-history");
    if (stored) {
      try {
        setResults(JSON.parse(stored) as TestResult[]);
      } catch {
        window.localStorage.removeItem("agent-firewall-security-test-history");
      }
    }
  }, []);

  useEffect(() => {
    if (results.length > 0) {
      window.localStorage.setItem("agent-firewall-security-test-history", JSON.stringify(results));
    }
  }, [results]);

  const runTest = async (test: TestCase) => {
    setRunning(test.id);
    setError(null);
    const startedAt = Date.now();
    try {
      const response = await fetch("/api/mcp-test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ authMode: test.authMode, mcpRequest: requestFor(test) }),
      });
      if (!response.ok) throw new Error(`MCP proxy returned ${response.status}`);

      const raw = await response.json();
      const parsed = parseMcpDecision(raw);
      const executed = parsed.decision === "ALLOW" && parsed.rawContent?.includes("DOWNSTREAM_TOOL_EXECUTED") === true;
      let auditMatches = true;

      if (test.checksAudit) {
        const events = await listActivity();
        const matching = events.filter((event: ActivityEvent) =>
          event.tool === "read_file" &&
          event.target === test.target &&
          event.reason === "CAPABILITY_SCOPE_DENIED"
        );
        auditMatches = matching.length === 1 && matching[0].decision === "DENY" && matching[0].executionStatus === "DENY";
      }

      const decisionMatches = parsed.decision === test.expectedDecision;
      const reasonMatches = !test.expectedReason || parsed.reason === test.expectedReason;
      const executionMatches = executed === test.expectsExecution;
      const passed = decisionMatches && reasonMatches && executionMatches && auditMatches;
      const actual = `${parsed.decision}${parsed.reason ? ` (${parsed.reason})` : ""}`;

      const result: TestResult = {
        id: test.id,
        title: test.title,
        expected: test.expected,
        actual,
        decision: parsed.decision,
        reason: parsed.reason,
        executed,
        status: passed ? "PASS" : "FAIL",
        timestamp: new Date().toISOString(),
      };
      setResults((current) => [result, ...current.filter((item) => item.id !== test.id)]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Test request failed");
      setResults((current) => [{
        id: test.id,
        title: test.title,
        expected: test.expected,
        actual: "No usable gateway response",
        decision: "ERROR",
        reason: "REQUEST_FAILED",
        executed: false,
        status: "FAIL",
        timestamp: new Date(startedAt).toISOString(),
        error: err instanceof Error ? err.message : "Test request failed",
      }, ...current.filter((item) => item.id !== test.id)]);
    } finally {
      setRunning(null);
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <Header
        systemHealth={systemHealth}
        actuatorHealth={actuatorHealth}
        operatorConfig={operatorConfig}
        onUpdateOperatorConfig={setOperatorConfig}
        onRefreshHealth={refreshHealth}
        loading={loading || running !== null}
      />
      <main className="mx-auto w-full max-w-7xl space-y-6 px-4 py-6 sm:px-6 lg:px-8">
        <div>
          <p className="text-xs font-mono uppercase tracking-widest text-indigo-400">Evaluator workspace</p>
          <h1 className="mt-1 text-2xl font-semibold">Security Testing</h1>
          <p className="mt-2 max-w-3xl text-sm text-zinc-400">
            These checks use the live Agent Firewall MCP gateway and only the protected mock read_file tool.
            Credentials stay server-side; results are marked PASS only when the gateway response matches the expected policy behavior.
          </p>
        </div>

        {error && <div className="rounded-lg border border-rose-800 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">{error}</div>}

        <section className="grid gap-4 md:grid-cols-2">
          {TEST_CASES.map((test) => (
            <article key={test.id} className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-5">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <h2 className="font-semibold">{test.title}</h2>
                  <p className="mt-2 text-sm text-zinc-400">{test.description}</p>
                </div>
                <span className="rounded border border-zinc-700 px-2 py-1 text-[10px] font-mono uppercase text-zinc-400">
                  {test.authMode} auth
                </span>
              </div>
              <div className="mt-4 space-y-1 text-xs text-zinc-500">
                <p>Target: <span className="font-mono text-zinc-300">{test.target}</span></p>
                <p>Expected: <span className="text-zinc-300">{test.expected}</span></p>
              </div>
              <button
                onClick={() => runTest(test)}
                disabled={running !== null}
                className="mt-5 rounded-md bg-indigo-600 px-3 py-2 text-xs font-semibold text-white transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {running === test.id ? "Running..." : "Run Test"}
              </button>
            </article>
          ))}
        </section>

        <section className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-5">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="font-semibold">Test Results</h2>
              <p className="mt-1 text-xs text-zinc-500">Latest result per test case. Results are not fabricated before execution.</p>
            </div>
            <span className="text-xs text-zinc-500">{results.length} recorded</span>
          </div>
          {results.length === 0 ? (
            <p className="mt-5 rounded-lg border border-dashed border-zinc-800 p-6 text-center text-sm text-zinc-500">No tests have been run yet.</p>
          ) : (
            <div className="mt-4 space-y-3">
              {results.map((result) => (
                <div key={`${result.id}-${result.timestamp}`} className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-medium">{result.title}</span>
                    <span className={`rounded border px-2 py-0.5 text-[10px] font-bold ${result.status === "PASS" ? "border-emerald-800 bg-emerald-950 text-emerald-300" : "border-rose-800 bg-rose-950 text-rose-300"}`}>
                      {result.status}
                    </span>
                  </div>
                  <div className="mt-3 grid gap-2 text-xs text-zinc-400 sm:grid-cols-2">
                    <p>Expected: <span className="text-zinc-200">{result.expected}</span></p>
                    <p>Actual: <span className="text-zinc-200">{result.actual}</span></p>
                    <p>Decision: <span className="font-mono text-zinc-200">{result.decision}</span></p>
                    <p>Reason: <span className="font-mono text-zinc-200">{result.reason}</span></p>
                    <p>Downstream executed: <span className={result.executed ? "text-emerald-300" : "text-zinc-200"}>{result.executed ? "YES" : "NO"}</span></p>
                    <p>Timestamp: <span className="font-mono text-zinc-200">{new Date(result.timestamp).toLocaleString()}</span></p>
                  </div>
                  {result.error && <p className="mt-2 text-xs text-rose-300">{result.error}</p>}
                </div>
              ))}
            </div>
          )}
        </section>
      </main>
    </div>
  );
}
