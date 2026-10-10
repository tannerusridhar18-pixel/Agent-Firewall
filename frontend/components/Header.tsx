"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { OperatorConfig, SystemHealth, ActuatorHealth } from "../lib/api";

interface HeaderProps {
  systemHealth: SystemHealth | null;
  actuatorHealth: ActuatorHealth | null;
  operatorConfig: OperatorConfig;
  onUpdateOperatorConfig: (config: OperatorConfig) => void;
  onRefreshHealth: () => void;
  loading: boolean;
}

export function Header({
  systemHealth,
  actuatorHealth,
  operatorConfig,
  onUpdateOperatorConfig,
  onRefreshHealth,
  loading,
}: HeaderProps) {
  const pathname = usePathname();
  const [showConfig, setShowConfig] = useState(false);
  const [tempKey, setTempKey] = useState(operatorConfig.key);
  const [tempId, setTempId] = useState(operatorConfig.operatorId);

  const isOnline = systemHealth?.status === "UP";
  const isDbReady = actuatorHealth?.status === "UP";

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    onUpdateOperatorConfig({ key: tempKey, operatorId: tempId });
    setShowConfig(false);
  };

  return (
    <header className="border-b border-zinc-800 bg-zinc-950/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3.5 flex flex-wrap items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center space-x-3">
          <div className="h-8 w-8 rounded-lg bg-indigo-600/20 border border-indigo-500/40 flex items-center justify-center text-indigo-400 font-bold text-base shadow-inner">
            🛡️
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-zinc-100 tracking-tight text-base">
                IntentGuard / AgentFirewall
              </span>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-indigo-950/80 text-indigo-300 border border-indigo-800/60 font-medium">
                V0.4 Prototype
              </span>
            </div>
            <p className="text-xs text-zinc-400">
              Deterministic Runtime Security Gateway for MCP Agents
            </p>
          </div>
        </div>

        {/* Status Indicators & Controls */}
        <div className="flex items-center gap-3">
          <nav className="flex items-center gap-1 rounded-lg border border-zinc-800 bg-zinc-900/60 p-1 text-xs">
            <Link href="/" className={`rounded-md px-3 py-1.5 font-medium transition ${pathname === "/" ? "bg-zinc-800 text-zinc-100" : "text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100"}`}>
              Dashboard
            </Link>
            <Link href="/security-testing" className={`rounded-md px-3 py-1.5 font-medium transition ${pathname === "/security-testing" ? "bg-zinc-800 text-zinc-100" : "text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100"}`}>
              Security Testing
            </Link>
          </nav>

          {/* Gateway Status Badge */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md border border-zinc-800 bg-zinc-900/60 text-xs">
            <span
              className={`h-2 w-2 rounded-full ${
                isOnline ? "bg-emerald-500 shadow-[0_0_8px_#10b981]" : "bg-rose-500"
              }`}
            />
            <span className="text-zinc-400">Gateway:</span>
            <span className={`font-mono font-medium ${isOnline ? "text-emerald-400" : "text-rose-400"}`}>
              {isOnline ? "ONLINE (8080)" : "OFFLINE"}
            </span>
          </div>

          {/* DB Health Badge */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md border border-zinc-800 bg-zinc-900/60 text-xs">
            <span
              className={`h-2 w-2 rounded-full ${
                isDbReady ? "bg-emerald-500 shadow-[0_0_8px_#10b981]" : "bg-amber-500"
              }`}
            />
            <span className="text-zinc-400">DB / Schema:</span>
            <span className="font-mono text-zinc-200">
              {isDbReady ? "MySQL 8.4 (V4)" : "CHECKING"}
            </span>
          </div>

          {/* Refresh Health */}
          <button
            onClick={onRefreshHealth}
            disabled={loading}
            className="p-1.5 rounded-md border border-zinc-800 bg-zinc-900 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 text-xs transition disabled:opacity-50"
            title="Refresh Health"
          >
            <svg
              className={`w-4 h-4 ${loading ? "animate-spin text-indigo-400" : ""}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
              />
            </svg>
          </button>

          {/* Operator Config Button */}
          <button
            onClick={() => setShowConfig(!showConfig)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-zinc-700 bg-zinc-800/80 hover:bg-zinc-700 text-zinc-200 text-xs font-medium transition"
          >
            <svg className="w-3.5 h-3.5 text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
              />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
            Operator Auth
          </button>
        </div>
      </div>

      {/* Collapsible Operator Key Config Drawer */}
      {showConfig && (
        <div className="border-t border-zinc-800 bg-zinc-900/95 px-4 sm:px-6 lg:px-8 py-3">
          <form onSubmit={handleSave} className="max-w-7xl mx-auto flex flex-wrap items-center gap-4 text-xs">
            <span className="text-zinc-400 font-medium">Control-Plane Credentials:</span>
            <div className="flex items-center gap-2">
              <label className="text-zinc-400">Operator ID:</label>
              <input
                type="text"
                value={tempId}
                onChange={(e) => setTempId(e.target.value)}
                className="bg-zinc-950 border border-zinc-700 rounded px-2.5 py-1 text-zinc-100 font-mono text-xs w-36 focus:outline-none focus:border-indigo-500"
                placeholder="operator-admin"
              />
            </div>
            <div className="flex items-center gap-2">
              <label className="text-zinc-400">Operator Key:</label>
              <input
                type="password"
                value={tempKey}
                onChange={(e) => setTempKey(e.target.value)}
                className="bg-zinc-950 border border-zinc-700 rounded px-2.5 py-1 text-zinc-100 font-mono text-xs w-64 focus:outline-none focus:border-indigo-500"
                placeholder="intentguard-control-plane-secret-key"
              />
            </div>
            <div className="flex items-center gap-2 ml-auto">
              <button
                type="submit"
                className="px-3 py-1 rounded bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-xs transition"
              >
                Apply
              </button>
              <button
                type="button"
                onClick={() => setShowConfig(false)}
                className="px-3 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs transition"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}
    </header>
  );
}
