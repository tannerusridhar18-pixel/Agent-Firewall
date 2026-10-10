"use client";

import React from "react";
import { SecuritySummary } from "../lib/api";

interface SecurityMetricsCardProps {
  summary: SecuritySummary | null;
  loading: boolean;
  onRefresh: () => void;
}

export function SecurityMetricsCard({ summary, loading, onRefresh }: SecurityMetricsCardProps) {
  const total = summary?.totalAnalyzed ?? 0;
  const allowed = summary?.allowedRequests ?? 0;
  const flagged = summary?.flaggedRequests ?? 0;
  const blocked = summary?.blockedRequests ?? 0;

  const threatCategories = summary?.threatCategories ?? {};
  const riskLevels = summary?.riskLevels ?? {};

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 shadow-sm space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
            <span>AI Security Intelligence & Metrics</span>
            <span className="text-[11px] font-mono text-indigo-400 bg-indigo-950/60 px-2 py-0.5 rounded border border-indigo-900/60">
              Live Gateway Telemetry
            </span>
          </h2>
        </div>

        <button
          onClick={onRefresh}
          disabled={loading}
          className="p-1.5 rounded-md border border-zinc-800 bg-zinc-900 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 text-xs transition disabled:opacity-50"
          title="Refresh Metrics"
        >
          <svg className={`w-3.5 h-3.5 ${loading ? "animate-spin text-indigo-400" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {/* Total Analyzed */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3.5 flex flex-col justify-between">
          <span className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider">Total Analyzed</span>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-bold font-mono text-zinc-100">{total}</span>
            <span className="text-[10px] text-zinc-500">requests</span>
          </div>
        </div>

        {/* Allowed */}
        <div className="rounded-lg border border-emerald-900/40 bg-emerald-950/20 p-3.5 flex flex-col justify-between">
          <span className="text-[11px] font-mono text-emerald-400 uppercase tracking-wider">Allowed</span>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-bold font-mono text-emerald-300">{allowed}</span>
            <span className="text-[10px] text-emerald-500">
              {total > 0 ? `${Math.round((allowed / total) * 100)}%` : "0%"}
            </span>
          </div>
        </div>

        {/* Flagged */}
        <div className="rounded-lg border border-amber-900/40 bg-amber-950/20 p-3.5 flex flex-col justify-between">
          <span className="text-[11px] font-mono text-amber-400 uppercase tracking-wider">Flagged (Paused)</span>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-bold font-mono text-amber-300">{flagged}</span>
            <span className="text-[10px] text-amber-500">requires approval</span>
          </div>
        </div>

        {/* Blocked */}
        <div className="rounded-lg border border-rose-900/40 bg-rose-950/20 p-3.5 flex flex-col justify-between">
          <span className="text-[11px] font-mono text-rose-400 uppercase tracking-wider">Blocked (Denied)</span>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-bold font-mono text-rose-300">{blocked}</span>
            <span className="text-[10px] text-rose-500">0 executions</span>
          </div>
        </div>
      </div>

      {/* Breakdown: Threat Categories & Risk Levels */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
        {/* Threat Categories */}
        <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/40 p-3 space-y-2">
          <div className="text-[11px] font-mono text-zinc-400 font-medium uppercase tracking-wider">
            Threat Categories Detected
          </div>
          {Object.keys(threatCategories).length === 0 ? (
            <div className="text-xs text-zinc-500 italic py-1">No threat categories logged yet</div>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(threatCategories).map(([cat, count]) => (
                <span
                  key={cat}
                  className="text-[11px] font-mono px-2 py-0.5 rounded border border-zinc-800 bg-zinc-900 text-zinc-300 flex items-center gap-1.5"
                >
                  <span className="text-zinc-200">{cat}</span>
                  <span className="bg-zinc-800 text-indigo-300 text-[10px] px-1.5 rounded-full font-bold">
                    {count}
                  </span>
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Risk Distribution */}
        <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/40 p-3 space-y-2">
          <div className="text-[11px] font-mono text-zinc-400 font-medium uppercase tracking-wider">
            Risk Distribution
          </div>
          {Object.keys(riskLevels).length === 0 ? (
            <div className="text-xs text-zinc-500 italic py-1">No evaluated risk levels yet</div>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(riskLevels).map(([level, count]) => {
                let badgeStyle = "border-zinc-800 bg-zinc-900 text-zinc-300";
                if (level === "LOW") badgeStyle = "border-emerald-800/60 bg-emerald-950/40 text-emerald-300";
                else if (level === "MEDIUM") badgeStyle = "border-sky-800/60 bg-sky-950/40 text-sky-300";
                else if (level === "HIGH") badgeStyle = "border-amber-800/60 bg-amber-950/40 text-amber-300";
                else if (level === "CRITICAL") badgeStyle = "border-rose-800/60 bg-rose-950/40 text-rose-300";

                return (
                  <span
                    key={level}
                    className={`text-[11px] font-mono px-2 py-0.5 rounded border flex items-center gap-1.5 ${badgeStyle}`}
                  >
                    <span>{level}</span>
                    <span className="bg-zinc-950/60 text-[10px] px-1.5 rounded-full font-bold">
                      {count}
                    </span>
                  </span>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
