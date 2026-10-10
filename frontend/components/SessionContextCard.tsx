"use client";

import React from "react";
import { Task, AgentSession, QuarantineRecord } from "../lib/api";

interface SessionContextCardProps {
  currentTask: Task | null;
  currentSession: AgentSession | null;
  quarantineRecord: QuarantineRecord | null;
  onInitializeDemoContext: () => void;
  onQuarantine: () => void;
  onUnquarantine: () => void;
  loading: boolean;
}

export function SessionContextCard({
  currentTask,
  currentSession,
  quarantineRecord,
  onInitializeDemoContext,
  onQuarantine,
  onUnquarantine,
  loading,
}: SessionContextCardProps) {
  const isQuarantined = !!quarantineRecord?.active;

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
            <span>Task & Session Context</span>
            {currentSession && (
              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-semibold border ${
                  isQuarantined
                    ? "bg-rose-950 text-rose-300 border-rose-700 animate-pulse"
                    : "bg-emerald-950 text-emerald-300 border-emerald-800"
                }`}
              >
                {isQuarantined ? "SESSION QUARANTINED" : "SESSION ACTIVE"}
              </span>
            )}
          </h2>
          <p className="text-xs text-zinc-400 mt-0.5">
            Gateway boundary enforces task authorization and quarantine state before capability evaluation.
          </p>
        </div>

        <button
          onClick={onInitializeDemoContext}
          disabled={loading}
          className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-xs shadow-sm transition disabled:opacity-50 flex items-center gap-1.5"
        >
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
          </svg>
          New Demo Context
        </button>
      </div>

      {currentSession && currentTask ? (
        <div className="space-y-3.5">
          {/* Metadata Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            {/* Task Box */}
            <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/60 p-3 space-y-1.5 font-mono">
              <div className="flex items-center justify-between text-zinc-400">
                <span className="text-[11px] uppercase tracking-wider text-zinc-400 font-sans font-semibold">Active Task</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300">{currentTask.status}</span>
              </div>
              <div className="text-zinc-100 font-medium truncate" title={currentTask.id}>
                {currentTask.id}
              </div>
              <div className="text-[11px] text-zinc-400 font-sans">
                Objective: <span className="text-zinc-200">{currentTask.objective}</span>
              </div>
              <div className="text-[11px] text-zinc-400 font-sans flex flex-wrap gap-1 pt-1">
                <span className="text-zinc-400">Tools:</span>
                {currentTask.allowedTools.map((t) => (
                  <span key={t} className="px-1.5 py-0.2 rounded bg-indigo-950/80 text-indigo-300 text-[10px]">
                    {t}
                  </span>
                ))}
                <span className="text-zinc-400 ml-1">Scope:</span>
                {currentTask.allowedResources.map((r) => (
                  <span key={r} className="px-1.5 py-0.2 rounded bg-zinc-800 text-zinc-300 text-[10px]">
                    {r}
                  </span>
                ))}
              </div>
            </div>

            {/* Session Box */}
            <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/60 p-3 space-y-1.5 font-mono">
              <div className="flex items-center justify-between text-zinc-400">
                <span className="text-[11px] uppercase tracking-wider text-zinc-400 font-sans font-semibold">
                  Mcp-Session-Id
                </span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300">
                  Agent {currentSession.agentVersion}
                </span>
              </div>
              <div className="text-zinc-100 font-medium truncate text-indigo-300" title={currentSession.sessionId}>
                {currentSession.sessionId}
              </div>
              <div className="text-[11px] text-zinc-400 font-sans">
                Agent ID: <span className="text-zinc-200">{currentSession.agentId}</span>
              </div>
              <div className="text-[11px] text-zinc-400 font-sans pt-1">
                Header: <code className="text-[10px] text-zinc-300 bg-zinc-900 px-1 py-0.5 rounded">Mcp-Session-Id: {currentSession.sessionId.substring(0, 16)}...</code>
              </div>
            </div>
          </div>

          {/* Quarantine Control Bar */}
          <div className="flex items-center justify-between pt-2 border-t border-zinc-800/60">
            <div className="text-xs text-zinc-400">
              {isQuarantined ? (
                <span className="text-rose-400">
                  ⚠️ Quarantined by <code className="text-zinc-300">{quarantineRecord?.quarantinedBy}</code>: {quarantineRecord?.reason}
                </span>
              ) : (
                <span className="text-zinc-400">
                  Quarantine immediately blocks all requests at Gate 1 before capability validation.
                </span>
              )}
            </div>

            <div className="flex items-center gap-2">
              {isQuarantined ? (
                <button
                  onClick={onUnquarantine}
                  disabled={loading}
                  className="px-3 py-1 rounded bg-emerald-700 hover:bg-emerald-600 text-white text-xs font-medium transition disabled:opacity-50"
                >
                  Unquarantine Session
                </button>
              ) : (
                <button
                  onClick={onQuarantine}
                  disabled={loading}
                  className="px-3 py-1 rounded bg-rose-900/80 hover:bg-rose-800 text-rose-100 border border-rose-700 text-xs font-medium transition disabled:opacity-50"
                >
                  Quarantine Session
                </button>
              )}
            </div>
          </div>
        </div>
      ) : (
        <div className="rounded-lg border border-dashed border-zinc-800 p-6 text-center text-xs text-zinc-400">
          <div className="font-semibold text-zinc-300 text-sm">No active session</div>
          <p className="text-zinc-500 mt-1">Click &quot;New Demo Context&quot; to provision an authorized task and session.</p>
        </div>
      )}
    </div>
  );
}
