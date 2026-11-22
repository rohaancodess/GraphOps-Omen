import React, { useMemo, useState } from 'react';
import {
  ShieldAlert,
  Route,
  KeyRound,
  Scissors,
  CheckCircle2,
  AlertTriangle,
  Zap,
  Lock,
} from 'lucide-react';
import { GraphEdge, GraphNode } from '../data/mockTopology';
import {
  AttackPathResult,
  BlastRadiusResult,
  ChokePointAnalysis,
  evaluateDpdpRegulatoryAlert,
  findShortestAttackPaths,
} from '../utils/graphAlgorithms';
import { WorkbenchMode } from './GraphCanvas';
import { MAX_BLAST_HOPS } from '../utils/hopStyle';

interface LeftControlPanelProps {
  mode: WorkbenchMode;
  onModeChange: (mode: WorkbenchMode) => void;
  nodes: GraphNode[];
  edges: GraphEdge[];
  blastRootId: string;
  blastHops: number;
  blastResult: BlastRadiusResult | null;
  onBlastRootChange: (nodeId: string) => void;
  onBlastHopsChange: (hops: number) => void;
  chokePoints: ChokePointAnalysis;
  shortestPaths: AttackPathResult[];
  severedEdgesCount: number;
  onRemediateChokePoint: (edgeId?: string) => void;
  onRevokeDormantPrivileges: () => void;
  onHighlightPath: (nodeIds: string[], edgeIds: string[]) => void;
}

const HOP_PRESETS: number[] = [1, 2, 3, 5, 10, MAX_BLAST_HOPS];

export const LeftControlPanel: React.FC<LeftControlPanelProps> = ({
  mode,
  onModeChange,
  nodes,
  edges,
  blastRootId,
  blastHops,
  blastResult,
  onBlastRootChange,
  onBlastHopsChange,
  chokePoints,
  shortestPaths,
  severedEdgesCount,
  onRemediateChokePoint,
  onRevokeDormantPrivileges,
  onHighlightPath,
}) => {
  const selectableNodes = nodes.filter((n) => n.type !== 'Vulnerability');
  const dormantEdges = edges.filter((e) => (e.last_used_days ?? 0) > 90);
  const topEdge = chokePoints.topEdges[0];

  // Counterfactual "What-If" Simulation: Preview impact of severing #1 Choke Edge
  const chokeWhatIf = useMemo(() => {
    if (!topEdge) return null;
    const simGraph = {
      nodes,
      edges: edges.filter((e) => e.id !== topEdge.edgeId),
    };
    const simPaths = findShortestAttackPaths(simGraph, 'ANY', 8);
    const curDpdp = evaluateDpdpRegulatoryAlert({ nodes, edges });
    const simDpdp = evaluateDpdpRegulatoryAlert(simGraph);
    const reductionPct =
      shortestPaths.length > 0
        ? Math.round(
            ((shortestPaths.length - simPaths.length) / shortestPaths.length) *
              100
          )
        : 0;
    return {
      beforePaths: shortestPaths.length,
      afterPaths: simPaths.length,
      reductionPct,
      beforePiiRisk: curDpdp.totalRecordsAtRisk,
      afterPiiRisk: simDpdp.totalRecordsAtRisk,
      dpdpContained: !simDpdp.triggered,
    };
  }, [nodes, edges, topEdge, shortestPaths.length]);

  // Counterfactual "What-If" Simulation: Preview impact of revoking all >90d dormant privileges
  const zeroTrustWhatIf = useMemo(() => {
    if (dormantEdges.length === 0) return null;
    const simGraph = {
      nodes,
      edges: edges.filter((e) => (e.last_used_days ?? 0) <= 90),
    };
    const simPaths = findShortestAttackPaths(simGraph, 'ANY', 8);
    const simDpdp = evaluateDpdpRegulatoryAlert(simGraph);
    const reductionPct =
      shortestPaths.length > 0
        ? Math.round(
            ((shortestPaths.length - simPaths.length) / shortestPaths.length) *
              100
          )
        : 0;
    return {
      beforePaths: shortestPaths.length,
      afterPaths: simPaths.length,
      reductionPct,
      dpdpContained: !simDpdp.triggered,
    };
  }, [nodes, edges, dormantEdges.length, shortestPaths.length]);

  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  const toggleSection = (key: string) => {
    setCollapsed((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const isCollapsed = (key: string) => Boolean(collapsed[key]);

  const showBlastRadius = mode === 'incident' || mode === 'attack-path';
  const showChokePoint = mode === 'incident' || mode === 'attack-path';
  const showAttackPaths = mode === 'attack-path';
  const showStaleAccess = mode === 'zero-trust';

  return (
    <aside className="w-80 shrink-0 h-full bg-[#0a0a0c] border-r-2 border-[#fff318]/40 flex flex-col overflow-y-auto select-none">
      {/* 1. MODE SWITCHER (compact 3-button) */}
      <div className="p-3.5 border-b border-[#fff318]/25">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[11px] font-extrabold uppercase tracking-wider text-[#fff318]">
            Mode
          </span>
          <span
            title="Switch analytical lens between incident response, attack-path analysis, and zero-trust entitlement drift."
            className="text-[10px] px-1.5 py-0.2 rounded bg-[#fff318]/15 text-[#fff318] font-mono cursor-help"
          >
            3 Modes
          </span>
        </div>

        <div className="grid grid-cols-3 gap-1">
          <button
            onClick={() => onModeChange('incident')}
            title="Focus on active SIEM alert correlation, live compromised hosts, and multi-hop breach containment."
            className={`flex flex-col items-center gap-1 px-2 py-2 rounded-lg border transition cursor-pointer ${mode === 'incident'
                ? 'bg-[#fff318] border-[#fff318] text-[#0a0a0c] shadow-md'
                : 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:border-[#fff318]/50'
              }`}
          >
            <ShieldAlert className={`w-4 h-4 shrink-0 ${mode === 'incident' ? 'text-[#0a0a0c]' : 'text-red-400'
              }`} />
            <span className="text-[10px] font-extrabold leading-tight">
              Incident
            </span>
          </button>
          <button
            onClick={() => onModeChange('attack-path')}
            title="Proactive posture analysis using Dijkstra shortest paths and path-frequency choke points."
            className={`flex flex-col items-center gap-1 px-2 py-2 rounded-lg border transition cursor-pointer ${mode === 'attack-path'
                ? 'bg-[#fff318] border-[#fff318] text-[#0a0a0c] shadow-md'
                : 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:border-[#fff318]/50'
              }`}
          >
            <Route className={`w-4 h-4 shrink-0 ${mode === 'attack-path' ? 'text-[#0a0a0c]' : 'text-red-400'
              }`} />
            <span className="text-[10px] font-extrabold leading-tight">
              Attack Path
            </span>
          </button>
          <button
            onClick={() => onModeChange('zero-trust')}
            title="Enforce least-privilege by revoking dormant standing entitlements unused >90 days."
            className={`flex flex-col items-center gap-1 px-2 py-2 rounded-lg border transition cursor-pointer ${mode === 'zero-trust'
                ? 'bg-[#fff318] border-[#fff318] text-[#0a0a0c] shadow-md'
                : 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:border-[#fff318]/50'
              }`}
          >
            <Lock className={`w-4 h-4 shrink-0 ${mode === 'zero-trust' ? 'text-[#0a0a0c]' : 'text-red-400'
              }`} />
            <span className="text-[10px] font-extrabold leading-tight">
              Zero-Trust
            </span>
          </button>
        </div>
      </div>

      {showBlastRadius && (
        <div className="p-3.5 border-b border-[#fff318]/25">
          <div
            onClick={() => toggleSection('blast')}
            className="flex items-center justify-between cursor-pointer"
          >
            <span className="text-[11px] font-extrabold uppercase tracking-wider text-[#fff318] flex items-center gap-1.5">
              <Scissors className="w-3.5 h-3.5 text-[#fff318]" />
              <span>Blast Radius</span>
            </span>
            <span className="text-[10px] text-[#fff318]">{isCollapsed('blast') ? '▾' : '▴'}</span>
          </div>
          {!isCollapsed('blast') && (
            <div className="mt-2 space-y-2.5">
              <div>
                <label className="text-[10px] uppercase tracking-wider text-zinc-400 font-semibold mb-1.5 block">
                  Start Node
                </label>
                <select
                  value={blastRootId}
                  onChange={(e) => onBlastRootChange(e.target.value)}
                  className="w-full bg-zinc-950 border border-[#fff318]/40 rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-[#fff318]"
                >
                  {selectableNodes.map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.compromised ? '🔴 ' : (n.criticality ?? 0) >= 9 ? '🛡 ' : '• '}
                      {n.label} ({n.type === 'Identity' ? `IAM T${n.tier}` : n.zone})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] uppercase tracking-wider text-zinc-400 font-semibold">
                    Max Hops
                  </span>
                  <span className="text-[10px] font-mono text-[#fff318]">
                    {blastHops === MAX_BLAST_HOPS ? 'Max' : blastHops}
                  </span>
                </div>
                <input
                  type="range"
                  min="0"
                  max={MAX_BLAST_HOPS}
                  value={blastHops}
                  onChange={(e) => onBlastHopsChange(Number(e.target.value))}
                  className="w-full accent-[#fff318] h-1.5 bg-zinc-800 rounded-lg cursor-pointer"
                />
                <div className="flex gap-1 mt-1.5">
                  {HOP_PRESETS.map((p) => (
                    <button
                      key={p}
                      onClick={() => onBlastHopsChange(p)}
                      className={`flex-1 py-1 rounded text-[10px] font-extrabold border transition cursor-pointer ${blastHops === p
                          ? 'bg-[#fff318] border-[#fff318] text-[#0a0a0c]'
                          : 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:border-[#fff318]/50'
                        }`}
                    >
                      {p === MAX_BLAST_HOPS ? 'Max' : p}
                    </button>
                  ))}
                </div>
              </div>

              {blastHops > 0 && blastResult && (
                <div className="bg-zinc-950 border border-[#fff318]/30 rounded-lg p-2 space-y-1.5">
                  <div className="text-[10px] uppercase tracking-wider text-zinc-400 font-semibold mb-1">
                    Per-Hop Reachability
                  </div>
                  {blastResult.countsByHop
                    .slice(1)
                    .map((count, idx) => {
                      const hop = idx + 1;
                      if (count === undefined || count === 0) return null;
                      return (
                        <div key={hop} className="flex items-center gap-2">
                          <span className="w-10 text-[10px] font-mono text-zinc-400">
                            Hop {hop}
                          </span>
                          <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
                            <div
                              className={`h-full ${hop === 1 ? 'bg-orange-500' : hop === 2 ? 'bg-amber-400' : hop === 3 ? 'bg-sky-400' : hop <= 5 ? 'bg-indigo-500' : 'bg-slate-400'
                                }`}
                              style={{
                                width: Math.min(100, (count / 22) * 100),
                              }}
                            />
                          </div>
                          <span className="w-8 text-[10px] font-mono font-bold text-white">
                            {count}
                          </span>
                        </div>
                      );
                    })}
                  {blastResult.exhausted && (
                    <div className="text-[10px] text-emerald-400 mt-1">
                      Nothing further reachable after hop {blastResult.maxReachedDepth}
                    </div>
                  )}
                  <div className="flex items-center justify-between text-[11px] pt-1 border-t border-zinc-800">
                    <span className="text-zinc-400">PII Vaults Reached:</span>
                    <span
                      className={`font-bold ${blastResult.piiExposedCount > 0
                          ? 'text-[#fff318]'
                          : 'text-emerald-400'
                        }`}
                    >
                      {blastResult.piiExposedCount} ({(blastResult.piiRecordsExposed / 1000000).toFixed(2)}M records)
                    </span>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {showChokePoint && (
        <div className="p-3.5 border-b border-[#fff318]/25">
          <div
            onClick={() => toggleSection('choke')}
            className="flex items-center justify-between cursor-pointer"
          >
            <span className="text-[11px] font-extrabold uppercase tracking-wider text-[#fff318] flex items-center gap-1.5">
              <Scissors className="w-3.5 h-3.5 text-[#fff318]" />
              <span>Choke Point</span>
            </span>
            <span className="text-[10px] text-[#fff318]">
              {isCollapsed('choke') ? '▾' : '▴'}
            </span>
          </div>
          {!isCollapsed('choke') && (
            <div className="mt-2 space-y-2.5">
              {topEdge ? (
                <div className="space-y-2.5">
                  <div className="bg-zinc-950 border border-[#fff318]/40 rounded-lg p-2.5">
                    <div className="flex items-center justify-between text-[10px] text-[#fff318] font-bold uppercase mb-1">
                      <span>Highest-Betweenness Bridge</span>
                      <span>Score: {topEdge.centralityScore}</span>
                    </div>
                    <div className="text-xs font-mono font-bold text-white truncate">
                      {topEdge.source} → {topEdge.target}
                    </div>
                    <div className="text-[10px] text-zinc-400 mt-1">
                      Intercepts{' '}
                      <strong className="text-white">{topEdge.pathsIntercepted}</strong>{' '}
                      attack vectors • Shields{' '}
                      <strong className="text-[#fff318]">{topEdge.crownJewelsProtected.length}</strong> Crown Jewels
                    </div>
                  </div>

                  {chokeWhatIf && (
                    <div className="bg-zinc-950/90 border border-emerald-500/40 rounded-lg p-2 space-y-1">
                      <div className="flex items-center justify-between text-[10px] font-extrabold uppercase tracking-wider text-emerald-400">
                        <span>⚡ What-If Simulation Preview</span>
                        <span>-{chokeWhatIf.reductionPct}% Paths</span>
                      </div>
                      <div className="flex items-center justify-between text-[11px] font-mono">
                        <span className="text-zinc-400">Dijkstra Paths:</span>
                        <span>
                          <span className="text-red-400">{chokeWhatIf.beforePaths}</span>
                          {' → '}
                          <span className="text-emerald-400 font-bold">{chokeWhatIf.afterPaths}</span>
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-[11px] font-mono">
                        <span className="text-zinc-400">2-Hop PII Risk:</span>
                        <span>
                          <span className="text-red-400">
                            {(chokeWhatIf.beforePiiRisk / 1000000).toFixed(2)}M
                          </span>
                          {' → '}
                          <span className="text-emerald-400 font-bold">
                            {(chokeWhatIf.afterPiiRisk / 1000000).toFixed(2)}M
                          </span>
                        </span>
                      </div>
                    </div>
                  )}

                  <button
                    onClick={() => onRemediateChokePoint(topEdge.edgeId)}
                    title="Sever the highest-path-frequency bridge edge to break lateral paths to Crown Jewels."
                    className="w-full py-2 px-3 rounded-lg bg-[#fff318] hover:opacity-90 text-[#0a0a0c] font-extrabold text-xs flex items-center justify-center gap-2 shadow-lg transition cursor-pointer"
                  >
                    <Scissors className="w-4 h-4" />
                    <span>Remediate Choke Point</span>
                  </button>
                </div>
              ) : (
                <div className="bg-emerald-950/40 border border-emerald-500/40 rounded-lg p-3 text-center">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400 mx-auto mb-1" />
                  <div className="text-xs font-bold text-emerald-200">
                    All Critical Choke Points Severed
                  </div>
                  <div className="text-[10px] text-emerald-400/80">
                    Zero lateral paths remain to Crown Jewels.
                  </div>
                </div>
              )}

              {mode === 'attack-path' && chokePoints.topNodes.length > 0 && (
                <div className="mt-3 space-y-1.5">
                  <div className="text-[10px] uppercase tracking-wider text-zinc-400 font-semibold">
                    Top Path-Frequency Choke Nodes
                  </div>
                  {chokePoints.topNodes.map((cn) => (
                    <div key={cn.nodeId} className="bg-zinc-950 border border-zinc-800 rounded-lg p-2">
                      <div className="flex items-center justify-between text-[10px] mb-1">
                        <span className="font-bold text-white">{cn.label}</span>
                        <span className="text-[#fff318] font-mono">{cn.pathsIntercepted} paths</span>
                      </div>
                      <div className="text-[10px] text-zinc-400">
                        {cn.crownJewelsProtected.length} crown jewels protected
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {showAttackPaths && (
        <div className="p-3.5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-extrabold uppercase tracking-wider text-[#fff318] flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-[#fff318]" />
              <span>Dijkstra Least-Cost Paths</span>
            </span>
            <span
              title="Edge weight = 1 / (target.criticality × target.vuln_cvss). Lower cost indicates higher exploitability towards Crown Jewels."
              className="text-[10px] text-[#fff318] font-mono cursor-help"
            >
              {shortestPaths.length} Paths
            </span>
          </div>

          <div className="space-y-1.5 max-h-44 overflow-y-auto pr-0.5">
            {shortestPaths.slice(0, 4).map((p) => (
              <button
                key={p.id}
                onClick={() => onHighlightPath(p.nodeIds, p.edgeIds)}
                className="w-full text-left bg-zinc-950 hover:border-[#fff318] border border-zinc-800 rounded-md p-2 transition cursor-pointer"
              >
                <div className="flex items-center justify-between text-[11px] font-semibold text-white">
                  <span className="truncate">{p.sourceId} → {p.targetId}</span>
                  <span className="text-[10px] font-mono text-[#fff318] shrink-0 ml-1">
                    cost={p.totalCost}
                  </span>
                </div>
                <div className="text-[10px] text-zinc-400 truncate mt-0.5">
                  {p.nodeIds.join(' → ')}
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      {showStaleAccess && (
        <div className="p-3.5 border-b border-[#fff318]/25">
          <div
            onClick={() => toggleSection('stale')}
            className="flex items-center justify-between cursor-pointer"
          >
            <span className="text-[11px] font-extrabold uppercase tracking-wider text-[#fff318] flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-[#fff318]" />
              <span>Stale Access</span>
            </span>
            <span className="text-[10px] text-[#fff318]">
              {isCollapsed('stale') ? '▾' : '▴'}
            </span>
          </div>
          {!isCollapsed('stale') && (
            <div className="mt-2 space-y-2.5">
              <div className="flex items-center justify-between text-[11px] mb-1.5">
                <span className="text-zinc-400 flex items-center gap-1">
                  <Lock className="w-3 h-3 text-[#fff318]" />
                  Dormant Standing Policies (&gt;90d)
                </span>
                <span className="font-mono font-bold text-[#fff318]">{dormantEdges.length} Active</span>
              </div>
              {zeroTrustWhatIf && (
                <div className="bg-zinc-950 border border-emerald-500/40 rounded-lg p-2 space-y-1 mb-2">
                  <div className="flex items-center justify-between text-[10px] font-extrabold uppercase tracking-wider text-emerald-400">
                    <span>⚡ What-If Purge Impact</span>
                    <span>-{zeroTrustWhatIf.reductionPct}% Paths</span>
                  </div>
                  <div className="flex items-center justify-between text-[11px] font-mono">
                    <span className="text-zinc-400">Attack Paths:</span>
                    <span>
                      <span className="text-red-400">{zeroTrustWhatIf.beforePaths}</span>
                      {' → '}
                      <span className="text-emerald-400 font-bold">{zeroTrustWhatIf.afterPaths}</span>
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-[11px] font-mono">
                    <span className="text-zinc-400">DPDP 2-Hop Alert:</span>
                    <span className="text-emerald-400 font-bold">
                      {zeroTrustWhatIf.dpdpContained ? 'CONTAINED' : 'ACTIVE'}
                    </span>
                  </div>
                </div>
              )}
              <button
                onClick={onRevokeDormantPrivileges}
                disabled={dormantEdges.length === 0}
                title="Enforce least-privilege Zero-Trust by revoking all CAN_ACCESS entitlements unused for >90 days."
                className={`w-full py-1.5 px-3 rounded-lg text-xs font-extrabold border transition flex items-center justify-center gap-1.5 ${dormantEdges.length > 0
                    ? 'bg-[#fff318]/15 hover:bg-[#fff318] hover:text-[#0a0a0c] border-[#fff318] text-[#fff318] cursor-pointer'
                    : 'bg-zinc-950 border-zinc-800 text-zinc-600 cursor-not-allowed'
                  }`}
              >
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>
                  {dormantEdges.length > 0
                    ? `Revoke ${dormantEdges.length} Dormant Privileges (>90d)`
                    : 'Zero-Trust Drift Remediated'}
                </span>
              </button>
              {severedEdgesCount > 0 && (
                <div className="text-[10px] text-[#fff318] text-center mt-1.5 font-bold">
                  ✓ {severedEdgesCount} high-risk edge(s) severed in this session
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </aside>
  );
};
