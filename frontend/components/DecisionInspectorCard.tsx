"use client";

import React, { useState } from "react";
import { ParsedSecurityDecision, McpCallResult, SecurityDecision } from "../lib/api";

interface DecisionInspectorCardProps {
  lastDecision: ParsedSecurityDecision | null;
  lastRawResult: McpCallResult | null;
  auditDecision: SecurityDecision | null;
  onFetchAuditRecord: (requestId: string) => void;
  loading: boolean;
}

export function DecisionInspectorCard({
  lastDecision,
  lastRawResult,
  auditDecision,
  onFetchAuditRecord,
  loading,
}: DecisionInspectorCardProps) {
  const [showRaw, setShowRaw] = useState(false);

  if (!lastDecision) {
    return (
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 shadow-sm text-center">
        <h2 className="text-sm font-semibold text-zinc-100 mb-1">Live Decision Inspector</h2>
        <p className="text-xs text-zinc-400">
          No requests executed yet. Run a scenario or test an MCP tool call to observe real-time gateway decisions.
        </p>
      </div>
    );
  }

  const isAllow = lastDecision.decision === "ALLOW";
  const isRequireApproval = lastDecision.decision === "REQUIRE_APPROVAL";
  const isDeny = lastDecision.decision === "DENY";

  let badgeColor = "bg-zinc-800 text-zinc-300 border-zinc-700";
  let bannerBorder = "border-zinc-800 bg-zinc-950/60";
  if (isAllow) {
    badgeColor = "bg-emerald-950 text-emerald-300 border-emerald-700 font-bold";
    bannerBorder = "border-emerald-800/60 bg-emerald-950/20";
  } else if (isRequireApproval) {
    badgeColor = "bg-amber-950 text-amber-300 border-amber-700 font-bold animate-pulse";
    bannerBorder = "border-amber-800/60 bg-amber-950/20";
  } else if (isDeny) {
    badgeColor = "bg-rose-950 text-rose-200 border-rose-700 font-bold";
    bannerBorder = "border-rose-800/60 bg-rose-950/20";
  }

  return (
    <div className={`rounded-xl border p-5 shadow-sm space-y-4 ${bannerBorder}`}>
      {/* Top Banner */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <span className={`text-xs font-mono px-3 py-1 rounded-md border ${badgeColor}`}>
            {lastDecision.decision}
          </span>
          <div>
            <h2 className="text-sm font-semibold text-zinc-100">
              Reason: <span className="font-mono text-zinc-300">{lastDecision.reason}</span>
            </h2>
            <p className="text-xs text-zinc-400">
              {isAllow
                ? "Protected action executed through downstream tool handler."
                : isRequireApproval
                ? "Execution paused at Gate 6. Requires explicit operator approval to resume."
                : `Blocked at Gate ${lastDecision.gateBlocked ?? 2}. Protected execution prevented.`}
            </p>
          </div>
        </div>

        {lastDecision.requestId && (
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-zinc-400">Req: {lastDecision.requestId}</span>
            <button
              onClick={() => onFetchAuditRecord(lastDecision.requestId!)}
              disabled={loading}
              className="px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-medium transition disabled:opacity-50"
            >
              Fetch Audit Record
            </button>
          </div>
        )}
      </div>

      {/* Decision Metadata Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
        {/* Gate Blocked */}
        <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/80 p-2.5">
          <span className="text-[10px] uppercase text-zinc-400 block font-sans">Enforcement Point</span>
          <span className="text-zinc-200 block mt-0.5">
            {lastDecision.gateBlocked ? `Gate ${lastDecision.gateBlocked}` : "Gate 8 (Executed)"}
          </span>
        </div>

        {/* Risk Level */}
        <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/80 p-2.5">
          <span className="text-[10px] uppercase text-zinc-400 block font-sans">Risk Level</span>
          <span
            className={`block mt-0.5 font-bold ${
              lastDecision.riskLevel === "CRITICAL" || lastDecision.riskLevel === "HIGH"
                ? "text-rose-400"
                : lastDecision.riskLevel === "MEDIUM"
                ? "text-amber-400"
                : "text-emerald-400"
            }`}
          >
            {lastDecision.riskLevel || auditDecision?.riskLevel || "LOW"}
          </span>
        </div>

        {/* Risk Factors */}
        <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/80 p-2.5">
          <span className="text-[10px] uppercase text-zinc-400 block font-sans">Risk Factors</span>
          <span className="text-zinc-300 block mt-0.5 truncate" title={lastDecision.riskFactors?.join(", ")}>
            {lastDecision.riskFactors?.length ? lastDecision.riskFactors.join(", ") : "NONE"}
          </span>
        </div>

        {/* Audit Evidence State */}
        <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/80 p-2.5">
          <span className="text-[10px] uppercase text-zinc-400 block font-sans">Audit Recorded</span>
          <span className="text-emerald-400 block mt-0.5">
            {auditDecision ? `DECISION RECORDED (${auditDecision.decisionId})` : "PERSISTED (GATE 7)"}
          </span>
        </div>
      </div>

      {/* Execution Content / Evidence View */}
      {lastDecision.rawContent && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-950/90 p-3 space-y-1">
          <span className="text-[10px] uppercase tracking-wider text-zinc-400 font-mono block">
            {isAllow ? "Tool Execution Content (Protected Result)" : "Error / Decision Payload"}
          </span>
          <pre className="text-xs font-mono text-zinc-200 overflow-x-auto whitespace-pre-wrap break-all p-2 rounded bg-zinc-900/60 border border-zinc-800/60">
            {lastDecision.rawContent}
          </pre>
        </div>
      )}

      {/* Collapsible Full JSON-RPC Payload */}
      <div>
        <button
          onClick={() => setShowRaw(!showRaw)}
          className="text-xs text-indigo-400 hover:text-indigo-300 font-mono flex items-center gap-1"
        >
          <span>{showRaw ? "▼ Hide" : "▶ Show"} Raw MCP Response (JSON-RPC 2.0)</span>
        </button>
        {showRaw && lastRawResult && (
          <pre className="mt-2 text-[11px] font-mono text-zinc-400 bg-zinc-950 p-3 rounded-lg border border-zinc-800 overflow-x-auto">
            {JSON.stringify(lastRawResult, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}
