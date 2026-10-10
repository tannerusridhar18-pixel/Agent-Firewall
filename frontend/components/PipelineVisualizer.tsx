"use client";

import React from "react";
import { ParsedSecurityDecision } from "../lib/api";

interface PipelineVisualizerProps {
  lastDecision: ParsedSecurityDecision | null;
  executing: boolean;
}

const GATES = [
  { id: 1, name: "Gate 1", title: "Session & Quarantine", desc: "Blocked if quarantined or inactive session" },
  { id: 2, name: "Gate 2", title: "Capability Token", desc: "Fail-closed token validation before manifest lookup" },
  { id: 3, name: "Gate 3", title: "Tool Manifest", desc: "Schema, side-effects & argument normalization" },
  { id: 4, name: "Gate 4", title: "Provenance", desc: "Trust & sensitivity propagation; unknown fails closed" },
  { id: 5, name: "Gate 5", title: "Risk & Policy", desc: "Deterministic categorical evaluation (LOW-CRITICAL)" },
  { id: 6, name: "Gate 6", title: "Approval Gate", desc: "Atomic single-use token consumption on high-risk" },
  { id: 7, name: "Gate 7", title: "Fail-Closed Audit", desc: "Synchronous hash & decision evidence logging" },
  { id: 8, name: "Gate 8", title: "Protected Tool", desc: "Isolated downstream execution (MOCK / REAL)" },
];

export function PipelineVisualizer({ lastDecision, executing }: PipelineVisualizerProps) {
  const blockedGate = lastDecision?.gateBlocked;
  const isAllow = lastDecision?.decision === "ALLOW";
  const isPendingApproval = lastDecision?.decision === "REQUIRE_APPROVAL";

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-5 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
            <span>Enforcement Pipeline</span>
            <span className="text-[11px] font-mono text-zinc-400 bg-zinc-800/80 px-2 py-0.5 rounded border border-zinc-700/60">
              8-Gate Architecture
            </span>
          </h2>
          <p className="text-xs text-zinc-400 mt-0.5">
            Strict sequential enforcement: Protected tool is reachable only after every prior gate succeeds.
          </p>
        </div>
        {executing && (
          <div className="flex items-center gap-2 text-xs font-mono text-indigo-400 animate-pulse">
            <span className="h-2 w-2 rounded-full bg-indigo-500 animate-ping" />
            Traversing Gateway...
          </div>
        )}
      </div>

      {/* Grid of 8 Gates */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-2.5">
        {GATES.map((gate) => {
          let statusStyle = "border-zinc-800 bg-zinc-950/60 text-zinc-400";
          let badgeText = "READY";
          let badgeStyle = "bg-zinc-800 text-zinc-400";

          if (executing) {
            statusStyle = "border-indigo-500/40 bg-indigo-950/20 text-indigo-300";
            badgeText = "EVAL";
            badgeStyle = "bg-indigo-900/60 text-indigo-300";
          } else if (isAllow) {
            statusStyle = "border-emerald-600/50 bg-emerald-950/20 text-emerald-300";
            badgeText = "PASS";
            badgeStyle = "bg-emerald-900/60 text-emerald-300";
          } else if (blockedGate === gate.id) {
            if (isPendingApproval) {
              statusStyle = "border-amber-500/60 bg-amber-950/30 text-amber-300 shadow-[0_0_12px_rgba(245,158,11,0.15)]";
              badgeText = "PAUSED";
              badgeStyle = "bg-amber-800 text-amber-200 font-bold";
            } else {
              statusStyle = "border-rose-600/60 bg-rose-950/30 text-rose-300 shadow-[0_0_12px_rgba(244,63,94,0.15)]";
              badgeText = "BLOCKED";
              badgeStyle = "bg-rose-800 text-rose-100 font-bold";
            }
          } else if (blockedGate && gate.id > blockedGate) {
            statusStyle = "border-zinc-850 bg-zinc-950/40 text-zinc-600 opacity-60";
            badgeText = "UNREACHED";
            badgeStyle = "bg-zinc-900 text-zinc-600";
          } else if (blockedGate && gate.id < blockedGate) {
            statusStyle = "border-emerald-800/40 bg-emerald-950/10 text-emerald-400";
            badgeText = "PASS";
            badgeStyle = "bg-emerald-900/40 text-emerald-300";
          }

          return (
            <div
              key={gate.id}
              className={`rounded-lg border p-3 flex flex-col justify-between transition-all duration-200 ${statusStyle}`}
            >
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[10px] font-mono font-semibold tracking-wider uppercase text-zinc-400">
                    {gate.name}
                  </span>
                  <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded ${badgeStyle}`}>
                    {badgeText}
                  </span>
                </div>
                <h3 className="text-xs font-medium text-zinc-200 leading-snug">{gate.title}</h3>
              </div>
              <p className="text-[10px] text-zinc-400 mt-2 leading-tight">{gate.desc}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
}
