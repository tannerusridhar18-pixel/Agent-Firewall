"use client";

import React, { useState } from "react";
import { SecurityEvent, ActivityEvent } from "../lib/api";

interface AuditEventsTableProps {
  securityEvents: SecurityEvent[];
  activityEvents: ActivityEvent[];
  onRefresh: () => void;
  loading: boolean;
  error?: string | null;
}

export function AuditEventsTable({
  securityEvents,
  activityEvents,
  onRefresh,
  loading,
  error,
}: AuditEventsTableProps) {
  const [activeTab, setActiveTab] = useState<"security" | "activity">("security");

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 shadow-sm space-y-3.5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h2 className="text-sm font-semibold text-zinc-100">Audit & Observability Stream</h2>
          {/* Tabs */}
          <div className="flex items-center rounded-lg bg-zinc-950 p-0.5 border border-zinc-800 text-xs">
            <button
              onClick={() => setActiveTab("security")}
              className={`px-3 py-1 rounded-md transition font-medium ${
                activeTab === "security"
                  ? "bg-zinc-800 text-zinc-100 shadow-sm"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Security Events ({securityEvents.length})
            </button>
            <button
              onClick={() => setActiveTab("activity")}
              className={`px-3 py-1 rounded-md transition font-medium ${
                activeTab === "activity"
                  ? "bg-zinc-800 text-zinc-100 shadow-sm"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Activity Log ({activityEvents.length})
            </button>
          </div>
        </div>

        <button
          onClick={onRefresh}
          disabled={loading}
          className="p-1.5 rounded-md border border-zinc-800 bg-zinc-900 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 text-xs transition disabled:opacity-50"
          title="Refresh Events"
        >
          <svg className={`w-3.5 h-3.5 ${loading ? "animate-spin text-indigo-400" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
        </button>
      </div>

      {/* Table Content */}
      <div className="overflow-x-auto rounded-lg border border-zinc-800/80 bg-zinc-950/60 max-h-72 overflow-y-auto">
        {activeTab === "security" ? (
          securityEvents.length > 0 ? (
            <table className="w-full text-left text-xs text-zinc-300 font-mono">
              <thead className="bg-zinc-900/90 text-[11px] text-zinc-400 uppercase tracking-wider sticky top-0 border-b border-zinc-800 font-sans">
                <tr>
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Session</th>
                  <th className="py-2.5 px-3">Message</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {securityEvents.map((ev) => (
                  <tr key={ev.eventId} className="hover:bg-zinc-900/40 transition">
                    <td className="py-2 px-3 text-zinc-400 text-[11px] whitespace-nowrap">
                      {new Date(ev.createdAt).toLocaleTimeString()}
                    </td>
                    <td className="py-2 px-3">
                      <span
                        className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${
                          ev.severity === "CRITICAL" || ev.severity === "HIGH"
                            ? "bg-rose-950 text-rose-300 border border-rose-800"
                            : ev.severity === "MEDIUM"
                            ? "bg-amber-950 text-amber-300 border border-amber-800"
                            : "bg-zinc-800 text-zinc-300"
                        }`}
                      >
                        {ev.severity}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-indigo-300 whitespace-nowrap">{ev.eventType}</td>
                    <td className="py-2 px-3 text-zinc-400 truncate max-w-[120px]" title={ev.sessionId}>
                      {ev.sessionId.substring(0, 10)}...
                    </td>
                    <td className="py-2 px-3 text-zinc-200">{ev.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="p-6 text-center text-xs text-zinc-400">
              <div className="font-semibold text-zinc-300 text-sm">No security events</div>
              <p className="text-zinc-500 mt-1">No security decisions or policy enforcement alerts recorded yet.</p>
            </div>
          )
        ) : (
          activityEvents.length > 0 ? (
            <table className="w-full text-left text-xs text-zinc-300 font-mono">
              <thead className="bg-zinc-900/90 text-[11px] text-zinc-400 uppercase tracking-wider sticky top-0 border-b border-zinc-800 font-sans">
                <tr>
                  <th className="py-2.5 px-3">Time</th>
                  <th className="py-2.5 px-3">Tool</th>
                  <th className="py-2.5 px-3">Target</th>
                  <th className="py-2.5 px-3">Risk</th>
                  <th className="py-2.5 px-3">Decision</th>
                  <th className="py-2.5 px-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {activityEvents.map((act) => (
                  <tr key={act.eventId} className="hover:bg-zinc-900/40 transition">
                    <td className="py-2 px-3 text-zinc-400 text-[11px] whitespace-nowrap">
                      {new Date(act.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2 px-3 text-indigo-300">{act.tool}</td>
                    <td className="py-2 px-3 text-zinc-400">{act.target || "-"}</td>
                    <td className="py-2 px-3 text-amber-300">{act.riskLevel}</td>
                    <td className="py-2 px-3">
                      <span
                        className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${
                          act.decision === "ALLOW"
                            ? "bg-emerald-950 text-emerald-300 border border-emerald-800"
                            : "bg-rose-950 text-rose-300 border border-rose-800"
                        }`}
                      >
                        {act.decision}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-zinc-300">{act.executionStatus}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="p-6 text-center text-xs text-zinc-400">
                {error ? (
                  <>
                    <div className="font-semibold text-rose-300">Activity log unavailable</div>
                    <p className="text-zinc-500 mt-1">{error}</p>
                  </>
                ) : loading ? (
                  "Loading activity logs..."
                ) : (
                  "No activity logs recorded yet."
                )}
              </div>
            )
        )}
      </div>
    </div>
  );
}
