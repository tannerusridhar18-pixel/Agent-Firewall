"use client";

import React, { useState } from "react";

interface SecurityScenariosCardProps {
  onRunScenario: (scenarioId: string) => void;
  onCallMcpCustom: (method: string, params: Record<string, unknown>, useCapability: boolean, approvalId?: string) => void;
  pendingApprovalRequestId: string | null;
  loading: boolean;
}

const SCENARIOS = [
  {
    id: "A",
    title: "A. Valid Request",
    expected: "ALLOW",
    expectedBadge: "bg-emerald-950 text-emerald-300 border-emerald-800",
    desc: "Valid capability token + session + within task scope workspace/*",
  },
  {
    id: "B",
    title: "B. Missing/Invalid Capability",
    expected: "DENY",
    expectedBadge: "bg-rose-950 text-rose-300 border-rose-800",
    desc: "Protected call without valid token fails closed at Gate 2",
  },
  {
    id: "C",
    title: "C. Invalid Provenance",
    expected: "DENY",
    expectedBadge: "bg-rose-950 text-rose-300 border-rose-800",
    desc: "Unknown provenance ref fails closed at Gate 4 before policy evaluation",
  },
  {
    id: "D",
    title: "D. High-Risk Action",
    expected: "REQUIRE_APPROVAL",
    expectedBadge: "bg-amber-950 text-amber-300 border-amber-800",
    desc: "Elevated session denials trigger Gate 5 policy requiring operator approval",
  },
  {
    id: "E",
    title: "E. Approved Request",
    expected: "ALLOW / EXECUTE",
    expectedBadge: "bg-emerald-950 text-emerald-300 border-emerald-800",
    desc: "Validates and consumes approval token atomically at Gate 6",
  },
  {
    id: "F",
    title: "F. Approval Replay",
    expected: "DENY",
    expectedBadge: "bg-rose-950 text-rose-300 border-rose-800",
    desc: "Reusing consumed approval token is blocked at Gate 6",
  },
  {
    id: "G",
    title: "G. Quarantined Session",
    expected: "DENY",
    expectedBadge: "bg-rose-950 text-rose-300 border-rose-800",
    desc: "Active quarantine blocks request at Gate 1 before capability lookup",
  },
  {
    id: "H",
    title: "H. Revoked Capability",
    expected: "DENY",
    expectedBadge: "bg-rose-950 text-rose-300 border-rose-800",
    desc: "Revoked token is rejected immediately at Gate 2",
  },
  {
    id: "I",
    title: "I. Expired Capability",
    expected: "DENY",
    expectedBadge: "bg-rose-950 text-rose-300 border-rose-800",
    desc: "Expired capability is rejected immediately at Gate 2",
  },
  {
    id: "J",
    title: "J. AI Security: Normal Request",
    expected: "ALLOW",
    expectedBadge: "bg-emerald-950 text-emerald-300 border-emerald-800",
    desc: "AI Security Agent verifies benign intent; executes protected tool exactly once",
  },
  {
    id: "K",
    title: "K. AI Security: Prompt Injection",
    expected: "BLOCK",
    expectedBadge: "bg-rose-950 text-rose-300 border-rose-800",
    desc: "Adversarial prompt injection detected; 0 executions, critical security event logged",
  },
  {
    id: "L",
    title: "L. AI Security: Suspicious Intent",
    expected: "FLAG / APPROVE",
    expectedBadge: "bg-amber-950 text-amber-300 border-amber-800",
    desc: "Ambiguous egress intent paused for operator review; requires approval to resume",
  },
];

export function SecurityScenariosCard({
  onRunScenario,
  onCallMcpCustom,
  pendingApprovalRequestId,
  loading,
}: SecurityScenariosCardProps) {
  const [customMethod, setCustomMethod] = useState("tools/call");
  const [customToolName, setCustomToolName] = useState("read_file");
  const [customTarget, setCustomTarget] = useState("workspace/src/App.java");
  const [useCap, setUseCap] = useState(true);

  const handleCustomSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (customMethod === "tools/call") {
      onCallMcpCustom("tools/call", { name: customToolName, arguments: { target: customTarget } }, useCap);
    } else {
      onCallMcpCustom(customMethod, {}, useCap);
    }
  };

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 shadow-sm space-y-5">
      {/* Header */}
      <div>
        <h2 className="text-sm font-semibold text-zinc-100 flex items-center justify-between">
          <span className="flex items-center gap-2">
            <span>Security Test Scenarios</span>
            <span className="text-[11px] font-mono text-indigo-400 bg-indigo-950/60 px-2 py-0.5 rounded border border-indigo-900/60">
              V0.4 Invariants
            </span>
          </span>
          {pendingApprovalRequestId && (
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 animate-pulse">
              Pending Approval: {pendingApprovalRequestId.substring(0, 16)}...
            </span>
          )}
        </h2>
        <p className="text-xs text-zinc-400 mt-0.5">
          Execute concrete deterministic security scenarios directly against the live gateway.
        </p>
      </div>

      {/* Scenarios Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {SCENARIOS.map((s) => {
          const isApprovalScenario = s.id === "E" || s.id === "F";
          const needsApprovalReq = isApprovalScenario && !pendingApprovalRequestId;

          return (
            <div
              key={s.id}
              className="rounded-lg border border-zinc-800/80 bg-zinc-950/60 p-3 flex flex-col justify-between hover:border-zinc-700 transition"
            >
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-semibold text-xs text-zinc-200">{s.title}</span>
                  <span className={`text-[10px] font-mono font-medium px-1.5 py-0.5 rounded border ${s.expectedBadge}`}>
                    {s.expected}
                  </span>
                </div>
                <p className="text-[11px] text-zinc-400 leading-normal">{s.desc}</p>
              </div>

              <div className="pt-3 mt-1">
                <button
                  onClick={() => onRunScenario(s.id)}
                  disabled={loading}
                  className="w-full py-1.5 px-3 rounded bg-zinc-800 hover:bg-indigo-600 hover:text-white text-zinc-200 font-medium text-xs transition disabled:opacity-50 flex items-center justify-center gap-1.5"
                >
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  Execute Scenario
                </button>
                {needsApprovalReq && (
                  <span className="block text-[10px] text-zinc-400 text-center mt-1">
                    Tip: Run Scenario D first to generate approval request
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* MCP Protocol Controls & Custom Request Form */}
      <div className="border-t border-zinc-800/80 pt-4">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-zinc-300">MCP Protocol Tests:</span>
            <button
              onClick={() => onCallMcpCustom("initialize", {}, false)}
              disabled={loading}
              className="px-2.5 py-1 rounded border border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-mono transition disabled:opacity-50"
            >
              initialize
            </button>
            <button
              onClick={() => onCallMcpCustom("ping", {}, false)}
              disabled={loading}
              className="px-2.5 py-1 rounded border border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-mono transition disabled:opacity-50"
            >
              ping
            </button>
            <button
              onClick={() => onCallMcpCustom("tools/list", {}, false)}
              disabled={loading}
              className="px-2.5 py-1 rounded border border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-mono transition disabled:opacity-50"
            >
              tools/list
            </button>
          </div>
        </div>

        {/* Custom Request Form */}
        <form onSubmit={handleCustomSubmit} className="flex flex-wrap items-center gap-2.5 text-xs">
          <span className="text-zinc-400 font-medium">Custom Tool Call:</span>
          <select
            value={customToolName}
            onChange={(e) => setCustomToolName(e.target.value)}
            className="bg-zinc-950 border border-zinc-700 rounded px-2.5 py-1 text-zinc-200 font-mono text-xs focus:outline-none focus:border-indigo-500"
          >
            <option value="read_file">read_file (Protected)</option>
            <option value="unregistered_tool">unregistered_tool (Invalid)</option>
          </select>
          <input
            type="text"
            value={customTarget}
            onChange={(e) => setCustomTarget(e.target.value)}
            placeholder="workspace/..."
            className="bg-zinc-950 border border-zinc-700 rounded px-2.5 py-1 text-zinc-200 font-mono text-xs w-48 focus:outline-none focus:border-indigo-500"
          />
          <label className="flex items-center gap-1.5 text-zinc-300 cursor-pointer">
            <input
              type="checkbox"
              checked={useCap}
              onChange={(e) => setUseCap(e.target.checked)}
              className="rounded border-zinc-700 bg-zinc-900 text-indigo-600 focus:ring-0"
            />
            Send Token
          </label>
          <button
            type="submit"
            disabled={loading}
            className="px-3 py-1 rounded bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-xs transition disabled:opacity-50 ml-auto"
          >
            Send /mcp
          </button>
        </form>
      </div>
    </div>
  );
}
