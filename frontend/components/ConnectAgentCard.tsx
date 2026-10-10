"use client";

import React, { useState } from "react";
import { AgentSession, CapabilityMetadata, McpCallResult, callMcp } from "../lib/api";

interface ConnectAgentCardProps {
  currentSession: AgentSession | null;
  currentCapability: CapabilityMetadata | null;
  currentToken: string | null;
  onProvisionContext: () => void;
  loading: boolean;
}

interface TestStepResult {
  step: string;
  status: "idle" | "running" | "success" | "error";
  message?: string;
  latencyMs?: number;
}

export function ConnectAgentCard({
  currentSession,
  currentCapability,
  currentToken,
  onProvisionContext,
  loading,
}: ConnectAgentCardProps) {
  const [activeTab, setActiveTab] = useState<"json" | "curl" | "python">("json");
  const [copied, setCopied] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResults, setTestResults] = useState<TestStepResult[]>([
    { step: "initialize", status: "idle", message: "Checks MCP server capability handshake" },
    { step: "ping", status: "idle", message: "Checks gateway protocol liveness" },
    { step: "tools/list", status: "idle", message: "Discovers available protected tools" },
  ]);

  const endpointUrl = typeof window !== "undefined" ? `${window.location.origin}/mcp` : "http://localhost:8080/mcp";
  const directBackendUrl = "http://localhost:8080/mcp";
  const protocolVersion = "2026-07-28";

  const sessionId = currentSession?.sessionId || "<NO_ACTIVE_SESSION>";
  const token = currentToken || "<NO_ACTIVE_CAPABILITY_TOKEN>";

  const jsonConfig = JSON.stringify(
    {
      mcpServers: {
        intentguard: {
          url: directBackendUrl,
          headers: {
            "Mcp-Session-Id": sessionId,
            "X-IntentGuard-Capability": token,
          },
        },
      },
    },
    null,
    2
  );

  const curlConfig = `curl -X POST ${directBackendUrl} \\
  -H "Content-Type: application/json" \\
  -H "Mcp-Session-Id: ${sessionId}" \\
  -H "X-IntentGuard-Capability: ${token}" \\
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"target":"workspace/src/App.java"}}}'`;

  const pythonConfig = `import requests

url = "${directBackendUrl}"
headers = {
    "Content-Type": "application/json",
    "Mcp-Session-Id": "${sessionId}",
    "X-IntentGuard-Capability": "${token}",
}
payload = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "read_file",
        "arguments": {"target": "workspace/src/App.java"}
    }
}
response = requests.post(url, json=payload, headers=headers)
print("Decision / Content:", response.json())`;

  const handleCopy = () => {
    const textToCopy =
      activeTab === "json" ? jsonConfig : activeTab === "curl" ? curlConfig : pythonConfig;
    navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  const handleTestConnection = async () => {
    setTesting(true);
    const newResults: TestStepResult[] = [
      { step: "initialize", status: "running" },
      { step: "ping", status: "idle" },
      { step: "tools/list", status: "idle" },
    ];
    setTestResults([...newResults]);

    // Step 1: initialize
    const t0 = performance.now();
    try {
      const initResp: McpCallResult = await callMcp({
        body: { jsonrpc: "2.0", id: 1, method: "initialize" },
      });
      const t1 = performance.now();
      if (initResp.error) {
        newResults[0] = {
          step: "initialize",
          status: "error",
          message: `${initResp.error.code}: ${initResp.error.message}`,
          latencyMs: Math.round(t1 - t0),
        };
      } else {
        const srv = initResp.result?.serverInfo?.name || "intentguard-mcp-gateway";
        const ver = initResp.result?.serverInfo?.version || "0.3.0";
        newResults[0] = {
          step: "initialize",
          status: "success",
          message: `${srv} v${ver} (proto ${initResp.result?.protocolVersion})`,
          latencyMs: Math.round(t1 - t0),
        };
      }
    } catch (err: unknown) {
      newResults[0] = {
        step: "initialize",
        status: "error",
        message: err instanceof Error ? err.message : String(err),
      };
    }
    setTestResults([...newResults]);

    // Step 2: ping
    newResults[1] = { step: "ping", status: "running" };
    setTestResults([...newResults]);
    const t2 = performance.now();
    try {
      const pingResp: McpCallResult = await callMcp({
        body: { jsonrpc: "2.0", id: 2, method: "ping" },
      });
      const t3 = performance.now();
      if (pingResp.error) {
        newResults[1] = {
          step: "ping",
          status: "error",
          message: `${pingResp.error.code}: ${pingResp.error.message}`,
          latencyMs: Math.round(t3 - t2),
        };
      } else {
        newResults[1] = {
          step: "ping",
          status: "success",
          message: "Gateway responsive (JSON-RPC OK)",
          latencyMs: Math.round(t3 - t2),
        };
      }
    } catch (err: unknown) {
      newResults[1] = {
        step: "ping",
        status: "error",
        message: err instanceof Error ? err.message : String(err),
      };
    }
    setTestResults([...newResults]);

    // Step 3: tools/list
    newResults[2] = { step: "tools/list", status: "running" };
    setTestResults([...newResults]);
    const t4 = performance.now();
    try {
      const toolsResp: McpCallResult = await callMcp({
        body: { jsonrpc: "2.0", id: 3, method: "tools/list" },
      });
      const t5 = performance.now();
      if (toolsResp.error) {
        newResults[2] = {
          step: "tools/list",
          status: "error",
          message: `${toolsResp.error.code}: ${toolsResp.error.message}`,
          latencyMs: Math.round(t5 - t4),
        };
      } else {
        const toolsList = toolsResp.result?.tools || [];
        newResults[2] = {
          step: "tools/list",
          status: "success",
          message: `${toolsList.length} enabled tool(s): ${toolsList.map((t) => t.name).join(", ")}`,
          latencyMs: Math.round(t5 - t4),
        };
      }
    } catch (err: unknown) {
      newResults[2] = {
        step: "tools/list",
        status: "error",
        message: err instanceof Error ? err.message : String(err),
      };
    }
    setTestResults([...newResults]);
    setTesting(false);
  };

  const hasActiveSession = !!currentSession;
  const hasActiveCapability = !!currentCapability && currentCapability.status === "ACTIVE";

  return (
    <div className="rounded-xl border border-indigo-900/40 bg-zinc-900/60 p-5 shadow-sm space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
            <span>Connect AI Agent</span>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-indigo-950 text-indigo-300 border border-indigo-800">
              Model Context Protocol (MCP)
            </span>
          </h2>
          <p className="text-xs text-zinc-400 mt-0.5">
            Connect autonomous agent orchestrators (Claude Code, Cursor, LangChain) through the IntentGuard enforcement gateway.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {!hasActiveSession && (
            <button
              onClick={onProvisionContext}
              disabled={loading}
              className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-xs shadow-sm transition disabled:opacity-50"
            >
              Provision Fresh Session & Capability
            </button>
          )}
          <button
            onClick={handleTestConnection}
            disabled={testing || loading}
            className="px-3.5 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-100 font-medium text-xs border border-zinc-700 transition disabled:opacity-50 flex items-center gap-1.5"
          >
            <svg
              className={`w-3.5 h-3.5 ${testing ? "animate-spin text-indigo-400" : "text-emerald-400"}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            {testing ? "Testing..." : "Test Connection"}
          </button>
        </div>
      </div>

      {/* Runtime Connection Coordinates Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
        {/* Endpoint */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
          <span className="text-[10px] uppercase text-zinc-400 block font-sans">MCP Gateway Endpoint</span>
          <span className="text-emerald-400 font-semibold block mt-1 truncate" title={endpointUrl}>
            /mcp
          </span>
          <span className="text-[10px] text-zinc-400 block mt-0.5">POST JSON-RPC 2.0</span>
        </div>

        {/* Protocol Version */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
          <span className="text-[10px] uppercase text-zinc-400 block font-sans">MCP Protocol Version</span>
          <span className="text-zinc-200 font-semibold block mt-1">{protocolVersion}</span>
          <span className="text-[10px] text-zinc-400 block mt-0.5">Header: Mcp-Protocol-Version</span>
        </div>

        {/* Current Session */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
          <span className="text-[10px] uppercase text-zinc-400 block font-sans">Current Session ID</span>
          <span
            className={`font-semibold block mt-1 truncate ${
              hasActiveSession ? "text-indigo-300" : "text-zinc-400 italic"
            }`}
            title={sessionId}
          >
            {sessionId}
          </span>
          <span className="text-[10px] text-zinc-400 block mt-0.5">
            {hasActiveSession ? "ACTIVE (Gate 1 verified)" : "No active session"}
          </span>
        </div>

        {/* Current Capability */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
          <span className="text-[10px] uppercase text-zinc-400 block font-sans">Current Capability</span>
          <span
            className={`font-semibold block mt-1 truncate ${
              hasActiveCapability ? "text-emerald-300" : "text-zinc-400 italic"
            }`}
            title={currentCapability ? `${currentCapability.toolName} (${currentCapability.resourceScope})` : "None"}
          >
            {currentCapability ? `${currentCapability.toolName} (${currentCapability.resourceScope})` : "No active capability"}
          </span>
          <span className="text-[10px] text-zinc-400 block mt-0.5 font-mono">
            {currentToken ? `${currentToken.substring(0, 10)}...` : "Missing token"}
          </span>
        </div>
      </div>

      {/* Test Connection Results Bar */}
      <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/90 p-3 space-y-2">
        <div className="text-xs font-semibold text-zinc-300 flex items-center justify-between">
          <span>Gateway Verification Handshake:</span>
          <span className="text-[11px] text-zinc-400 font-normal">Real endpoint evaluation</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs">
          {testResults.map((tr) => (
            <div
              key={tr.step}
              className={`p-2.5 rounded-md border flex items-center justify-between ${
                tr.status === "success"
                  ? "border-emerald-800/60 bg-emerald-950/20 text-emerald-300"
                  : tr.status === "error"
                  ? "border-rose-800/60 bg-rose-950/20 text-rose-300"
                  : tr.status === "running"
                  ? "border-indigo-800/60 bg-indigo-950/20 text-indigo-300 animate-pulse"
                  : "border-zinc-800 bg-zinc-900/40 text-zinc-400"
              }`}
            >
              <div className="truncate mr-2">
                <span className="font-mono font-semibold block uppercase text-[10px]">{tr.step}</span>
                <span className="text-[11px] block truncate">{tr.message}</span>
              </div>
              <div className="text-right shrink-0">
                {tr.status === "success" && <span className="text-emerald-400 text-sm">✓</span>}
                {tr.status === "error" && <span className="text-rose-400 text-sm">✗</span>}
                {tr.status === "running" && <span className="text-indigo-400 text-xs">...</span>}
                {tr.status === "idle" && <span className="text-zinc-400 text-xs">-</span>}
                {tr.latencyMs !== undefined && (
                  <span className="block text-[9px] font-mono text-zinc-400">{tr.latencyMs}ms</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Copyable MCP Configuration Section */}
      <div className="border border-zinc-800 rounded-lg overflow-hidden bg-zinc-950">
        <div className="flex items-center justify-between px-3 py-2 bg-zinc-900/90 border-b border-zinc-800 text-xs">
          <div className="flex items-center gap-1.5 font-medium">
            <span className="text-zinc-400">Export Config:</span>
            <button
              onClick={() => setActiveTab("json")}
              className={`px-2 py-0.5 rounded transition ${
                activeTab === "json" ? "bg-zinc-800 text-zinc-100 font-semibold" : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              claude_desktop_config.json
            </button>
            <button
              onClick={() => setActiveTab("curl")}
              className={`px-2 py-0.5 rounded transition ${
                activeTab === "curl" ? "bg-zinc-800 text-zinc-100 font-semibold" : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              cURL (Terminal)
            </button>
            <button
              onClick={() => setActiveTab("python")}
              className={`px-2 py-0.5 rounded transition ${
                activeTab === "python" ? "bg-zinc-800 text-zinc-100 font-semibold" : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Python Client
            </button>
          </div>

          <button
            onClick={handleCopy}
            className="px-2.5 py-1 rounded bg-indigo-600 hover:bg-indigo-500 text-white text-[11px] font-medium transition flex items-center gap-1 shadow-sm"
          >
            {copied ? (
              <>
                <span className="text-xs">✓</span> Copied!
              </>
            ) : (
              <>
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                </svg>
                Copy Config
              </>
            )}
          </button>
        </div>

        <pre className="p-3 text-[11px] font-mono text-zinc-300 overflow-x-auto whitespace-pre leading-relaxed">
          {activeTab === "json" && jsonConfig}
          {activeTab === "curl" && curlConfig}
          {activeTab === "python" && pythonConfig}
        </pre>
      </div>
    </div>
  );
}
