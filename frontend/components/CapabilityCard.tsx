"use client";

import React from "react";
import { CapabilityMetadata } from "../lib/api";

interface CapabilityCardProps {
  currentCapability: CapabilityMetadata | null;
  currentToken: string | null;
  onIssueValid: () => void;
  onIssueExpiring: () => void;
  onRotate: () => void;
  onRevoke: () => void;
  loading: boolean;
}

export function CapabilityCard({
  currentCapability,
  currentToken,
  onIssueValid,
  onIssueExpiring,
  onRotate,
  onRevoke,
  loading,
}: CapabilityCardProps) {
  const isRevoked = currentCapability?.status === "REVOKED";
  const isExpired = currentCapability && new Date(currentCapability.expiresAt).getTime() < Date.now();
  const isActive = currentCapability?.status === "ACTIVE" && !isExpired;

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
            <span>Capability Token Lifecycle</span>
            {currentCapability && (
              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-semibold border ${
                  isRevoked
                    ? "bg-rose-950 text-rose-300 border-rose-800"
                    : isExpired
                    ? "bg-amber-950 text-amber-300 border-amber-800"
                    : "bg-emerald-950 text-emerald-300 border-emerald-800"
                }`}
              >
                {isRevoked ? "REVOKED" : isExpired ? "EXPIRED" : "ACTIVE"}
              </span>
            )}
          </h2>
          <p className="text-xs text-zinc-400 mt-0.5">
            Cryptographic single-session delegation token. Validated at Gate 2 before tool manifest lookup.
          </p>
        </div>

        {/* Issuance Action Buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={onIssueValid}
            disabled={loading}
            className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-xs shadow-sm transition disabled:opacity-50"
          >
            Issue Valid (1h)
          </button>
          <button
            onClick={onIssueExpiring}
            disabled={loading}
            className="px-3 py-1.5 rounded-lg border border-amber-700/80 bg-amber-950/60 hover:bg-amber-900 text-amber-200 font-medium text-xs transition disabled:opacity-50"
            title="Issues a capability with 2s TTL to observe expiry"
          >
            Issue Expiring (2s)
          </button>
        </div>
      </div>

      {currentCapability ? (
        <div className="space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
            {/* Capability ID */}
            <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-2.5">
              <span className="text-[10px] uppercase text-zinc-400 block font-sans">Capability ID</span>
              <span className="text-zinc-200 truncate block mt-0.5" title={currentCapability.capabilityId}>
                {currentCapability.capabilityId}
              </span>
            </div>

            {/* Tool & Scope */}
            <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-2.5">
              <span className="text-[10px] uppercase text-zinc-400 block font-sans">Tool & Scope</span>
              <span className="text-indigo-300 truncate block mt-0.5">
                {currentCapability.toolName} ({currentCapability.resourceScope})
              </span>
            </div>

            {/* Expiration */}
            <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-2.5">
              <span className="text-[10px] uppercase text-zinc-400 block font-sans">Expires At</span>
              <span className={`truncate block mt-0.5 ${isExpired ? "text-amber-400" : "text-zinc-300"}`}>
                {new Date(currentCapability.expiresAt).toLocaleTimeString()}
              </span>
            </div>

            {/* Token Masked State */}
            <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-2.5">
              <span className="text-[10px] uppercase text-zinc-400 block font-sans">Active Token (Header)</span>
              <span className="text-zinc-400 truncate block mt-0.5 font-mono text-[11px]">
                {currentToken ? `${currentToken.substring(0, 14)}••••••••` : "NONE"}
              </span>
            </div>
          </div>

          {/* Action Row */}
          <div className="flex items-center justify-between pt-2 border-t border-zinc-800/60">
            <div className="text-[11px] text-zinc-400">
              Header: <code className="text-zinc-300 bg-zinc-950 px-1.5 py-0.5 rounded border border-zinc-800 text-[10px]">
                X-IntentGuard-Capability: ig_cap_...
              </code>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={onRotate}
                disabled={loading || !isActive}
                className="px-3 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-medium transition disabled:opacity-40"
              >
                Rotate Token
              </button>
              <button
                onClick={onRevoke}
                disabled={loading || isRevoked}
                className="px-3 py-1 rounded bg-rose-950 hover:bg-rose-900 border border-rose-800 text-rose-200 text-xs font-medium transition disabled:opacity-40"
              >
                Revoke Capability
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="rounded-lg border border-dashed border-zinc-800 p-6 text-center text-xs text-zinc-400">
          <div className="font-semibold text-zinc-300 text-sm">No active capability</div>
          <p className="text-zinc-500 mt-1">No capability issued for current task. Click &quot;Issue Valid (1h)&quot; to mint an authorization token.</p>
        </div>
      )}
    </div>
  );
}
