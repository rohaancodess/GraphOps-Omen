import React, { useEffect, useMemo, useState } from 'react';
import {
  GraphEdge,
  GraphNode,
  INITIAL_TOPOLOGY,
  RawSiemAlert,
} from './data/mockTopology';
import {
  containNodeApi,
  fetchTopology,
  resetAndSeedApi,
  revokeDormantApi,
  severEdgeApi,
} from './api/topologyClient';
import { MAX_BLAST_HOPS } from './utils/hopStyle';
import {
  calculateBlastRadius,
  calculateChokePoints,
  CorrelatedIncident,
  evaluateDpdpRegulatoryAlert,
  findShortestAttackPaths,
  mergeAlerts,
} from './utils/graphAlgorithms';
import { GraphCanvas, WorkbenchMode } from './components/GraphCanvas';
import { TopKpiBar } from './components/TopKpiBar';
import { LeftControlPanel } from './components/LeftControlPanel';
import { RightInspectorDrawer } from './components/RightInspectorDrawer';
import { BottomAlertTray } from './components/BottomAlertTray';
import { CsvImportButton } from './components/CsvImportButton';
import { CsvImportDialog } from './components/CsvImportDialog';
import { AiCopilotModal } from './components/AiCopilotModal';

export const App: React.FC = () => {
  const [nodes, setNodes] = useState<GraphNode[]>(() =>
    INITIAL_TOPOLOGY.nodes.map((n) => ({ ...n }))
  );
  const [edges, setEdges] = useState<GraphEdge[]>(() =>
    INITIAL_TOPOLOGY.edges.map((e) => ({ ...e }))
  );
  const [rawAlerts, setRawAlerts] = useState<RawSiemAlert[]>(() =>
    INITIAL_TOPOLOGY.rawAlerts.map((a) => ({ ...a }))
  );
  const [initialEdgeCount, setInitialEdgeCount] = useState<number>(
    INITIAL_TOPOLOGY.edges.length
  );
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isOfflineFallback, setIsOfflineFallback] = useState<boolean>(false);
  const [isCsvImportOpen, setIsCsvImportOpen] = useState<boolean>(false);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);

    fetchTopology()
      .then((data) => {
        if (cancelled) return;
        setNodes(data.nodes);
        setEdges(data.edges);
        setRawAlerts(data.rawAlerts);
        setInitialEdgeCount(data.edges.length);
        setIsOfflineFallback(false);
      })
      .catch(() => {
        if (cancelled) return;
        setNodes(INITIAL_TOPOLOGY.nodes.map((n) => ({ ...n })));
        setEdges(INITIAL_TOPOLOGY.edges.map((e) => ({ ...e })));
        setRawAlerts(INITIAL_TOPOLOGY.rawAlerts.map((a) => ({ ...a })));
        setInitialEdgeCount(INITIAL_TOPOLOGY.edges.length);
        setIsOfflineFallback(true);
      })
      .finally(() => {
        if (!cancelled) {
          setIsLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const [mode, setMode] = useState<WorkbenchMode>('incident');
  const [blastRootId, setBlastRootId] = useState<string>('JumpHost-Corp');
  const [blastHops, setBlastHops] = useState<number>(2);

  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(
    'JumpHost-Corp'
  );
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);

  const [highlightedNodeIds, setHighlightedNodeIds] = useState<Set<string>>(
    new Set()
  );
  const [highlightedEdgeIds, setHighlightedEdgeIds] = useState<Set<string>>(
    new Set()
  );

  const [auditLog, setAuditLog] = useState<string[]>([]);

  const graphModel = useMemo(() => ({ nodes, edges }), [nodes, edges]);

  // 1. Blast Radius Calculation (BFS 1-3 Hops)
  const blastResult = useMemo(() => {
    if (blastHops === 0) return null;
    return calculateBlastRadius(graphModel, blastRootId, blastHops);
  }, [graphModel, blastRootId, blastHops]);

  // 2. Dijkstra Shortest Attack Paths
  const shortestPaths = useMemo(
    () => findShortestAttackPaths(graphModel, 'ANY', 8),
    [graphModel]
  );

  // 3. Betweenness Centrality Choke Points
  const chokePoints = useMemo(
    () => calculateChokePoints(graphModel),
    [graphModel]
  );

  // 4. WCC Alert Collapser
  const correlatedIncidents = useMemo(
    () => mergeAlerts(rawAlerts, graphModel),
    [rawAlerts, graphModel]
  );

  // 5. CERT-In / DPDP 2-Hop PII Reachability Check
  const dpdpAlert = useMemo(
    () => evaluateDpdpRegulatoryAlert(graphModel),
    [graphModel]
  );

  // KPI Counts
  const totalIdentities = nodes.filter((n) => n.type === 'Identity').length;
  const totalAssets = nodes.filter((n) => n.type === 'Asset').length;
  const totalVulns = nodes.filter((n) => n.type === 'Vulnerability').length;

  const crownJewels = nodes.filter(
    (n) => n.type === 'Asset' && ((n.criticality ?? 0) >= 9 || n.pii_data)
  );

  // Count how many Crown Jewels are reachable from any compromised node (full-depth BFS)
  const crownJewelsExposedCount = useMemo(() => {
    const exposedSet = new Set<string>();
    const compNodes = nodes.filter((n) => n.compromised);
    for (const c of compNodes) {
      const b = calculateBlastRadius(graphModel, c.id, MAX_BLAST_HOPS);
      b.crownJewelsExposed.forEach((label) => exposedSet.add(label));
    }
    return exposedSet.size;
  }, [graphModel, nodes]);

  const severedEdgesCount = initialEdgeCount - edges.length;

  const selectedNode = useMemo(
    () => nodes.find((n) => n.id === selectedNodeId) ?? null,
    [nodes, selectedNodeId]
  );

  const selectedEdge = useMemo(
    () => edges.find((e) => e.id === selectedEdgeId) ?? null,
    [edges, selectedEdgeId]
  );

  // Action: One-Click Remediate Choke Point (Severs highest-betweenness edge)
  const handleRemediateChokePoint = (targetEdgeId?: string) => {
    const edgeIdToSever =
      targetEdgeId || chokePoints.topEdges[0]?.edgeId || 'edge-attack-3';
    const edgeObj = edges.find((e) => e.id === edgeIdToSever);
    if (!edgeObj) return;

    setEdges((prev) => prev.filter((e) => e.id !== edgeIdToSever));
    const now = new Date().toLocaleTimeString();
    const baseMsg = `[${now}] SOAR REMEDIATION: Severed choke-point edge ${edgeObj.source} → ${edgeObj.target} (${edgeObj.relationship}).`;

    if (isOfflineFallback) {
      setAuditLog((prev) => [`${baseMsg} (local only)`, ...prev]);
      return;
    }

    severEdgeApi(edgeIdToSever)
      .then(() => {
        setAuditLog((prev) => [baseMsg, ...prev]);
      })
      .catch(() => {
        setAuditLog((prev) => [`${baseMsg} (local only)`, ...prev]);
      });
  };

  // Action: Contain System (Isolate node by removing all outgoing edges)
  const handleContainNode = (nodeId: string) => {
    const outCount = edges.filter((e) => e.source === nodeId).length;
    if (outCount === 0) return;

    setEdges((prev) => prev.filter((e) => e.source !== nodeId));
    setNodes((prev) =>
      prev.map((n) => (n.id === nodeId ? { ...n, compromised: false } : n))
    );
    const now = new Date().toLocaleTimeString();
    const baseMsg = `[${now}] HOST CONTAINMENT: Isolated ${nodeId} — severed ${outCount} outgoing lateral vectors.`;

    if (isOfflineFallback) {
      setAuditLog((prev) => [`${baseMsg} (local only)`, ...prev]);
      return;
    }

    containNodeApi(nodeId)
      .then(() => {
        setAuditLog((prev) => [baseMsg, ...prev]);
      })
      .catch(() => {
        setAuditLog((prev) => [`${baseMsg} (local only)`, ...prev]);
      });
  };

  // Action: Sever single edge
  const handleSeverEdge = (edgeId: string) => {
    const edgeObj = edges.find((e) => e.id === edgeId);
    if (!edgeObj) return;
    setEdges((prev) => prev.filter((e) => e.id !== edgeId));
    setSelectedEdgeId(null);
    const now = new Date().toLocaleTimeString();
    const baseMsg = `[${now}] POLICY REVOKED: Removed vector ${edgeObj.source} → ${edgeObj.target}.`;

    if (isOfflineFallback) {
      setAuditLog((prev) => [`${baseMsg} (local only)`, ...prev]);
      return;
    }

    severEdgeApi(edgeId)
      .then(() => {
        setAuditLog((prev) => [baseMsg, ...prev]);
      })
      .catch(() => {
        setAuditLog((prev) => [`${baseMsg} (local only)`, ...prev]);
      });
  };

  // Action: Revoke all dormant standing privileges (>90 days unused)
  const handleRevokeDormantPrivileges = () => {
    const dormant = edges.filter((e) => (e.last_used_days ?? 0) > 90);
    if (dormant.length === 0) return;
    setEdges((prev) => prev.filter((e) => (e.last_used_days ?? 0) <= 90));
    const now = new Date().toLocaleTimeString();
    const baseMsg = `[${now}] ZERO-TRUST DRIFT PURGE: Revoked ${dormant.length} standing privileges unused >90 days (including 120d JumpHost SSH key).`;

    if (isOfflineFallback) {
      setAuditLog((prev) => [`${baseMsg} (local only)`, ...prev]);
      return;
    }

    revokeDormantApi()
      .then(() => {
        setAuditLog((prev) => [baseMsg, ...prev]);
      })
      .catch(() => {
        setAuditLog((prev) => [`${baseMsg} (local only)`, ...prev]);
      });
  };

  // Action: Highlight correlated incident narrative or Dijkstra path
  const handleHighlightIncident = (incident: CorrelatedIncident) => {
    setHighlightedNodeIds(new Set(incident.involvedNodes));
    setHighlightedEdgeIds(new Set(incident.involvedEdges));
  };

  const handleHighlightPath = (nodeIds: string[], edgeIds: string[]) => {
    setHighlightedNodeIds(new Set(nodeIds));
    setHighlightedEdgeIds(new Set(edgeIds));
  };

  const handleClearHighlight = () => {
    setHighlightedNodeIds(new Set());
    setHighlightedEdgeIds(new Set());
  };

  // Action: Reset Graph Topology
  const handleResetTopology = () => {
    setNodes(INITIAL_TOPOLOGY.nodes.map((n) => ({ ...n })));
    setEdges(INITIAL_TOPOLOGY.edges.map((e) => ({ ...e })));
    setRawAlerts(INITIAL_TOPOLOGY.rawAlerts.map((a) => ({ ...a })));
    setInitialEdgeCount(INITIAL_TOPOLOGY.edges.length);
    setHighlightedNodeIds(new Set());
    setHighlightedEdgeIds(new Set());
    setBlastRootId('JumpHost-Corp');
    setBlastHops(2);
    const now = new Date().toLocaleTimeString();
    const baseMsg = `[${now}] TOPOLOGY RESET: Restored full 44-node synthetic enterprise topology and active breach state.`;

    if (isOfflineFallback) {
      setAuditLog((prev) => [`${baseMsg} (local only)`, ...prev]);
      return;
    }

    resetAndSeedApi()
      .then(() => {
        setAuditLog((prev) => [baseMsg, ...prev]);
      })
      .catch(() => {
        setAuditLog((prev) => [`${baseMsg} (local only)`, ...prev]);
      });
  };

  return (
    <div className="relative w-full h-screen bg-slate-950 text-slate-100 flex flex-col overflow-hidden font-sans">
      {/* Status Banner for Loading or Offline Fallback */}
      {isLoading && (
        <div className="w-full bg-zinc-900 border-b border-[#fff318]/40 px-4 py-1 text-xs text-[#fff318] flex items-center justify-center gap-2 z-30">
          <span className="inline-block w-2 h-2 rounded-full bg-[#fff318] animate-ping" />
          <span>Loading live graph topology from Neo4j AuraDB...</span>
        </div>
      )}
      {!isLoading && isOfflineFallback && (
        <div className="w-full bg-amber-950/90 border-b border-amber-500/60 px-4 py-1 text-xs text-amber-200 flex items-center justify-center gap-2 z-30">
          <span className="px-1.5 py-0.5 rounded bg-amber-500 text-slate-950 font-bold uppercase tracking-wider text-[10px]">
            offline demo data
          </span>
          <span>Backend unreachable — falling back to local mockTopology.ts</span>
        </div>
      )}

      {/* 1. Top KPI & Regulatory Impact Bar */}
      <TopKpiBar
        totalIdentities={totalIdentities}
        totalAssets={totalAssets}
        totalVulns={totalVulns}
        rawAlertCount={rawAlerts.length}
        mergedIncidentCount={correlatedIncidents.length}
        crownJewelsExposedCount={crownJewelsExposedCount}
        totalCrownJewels={crownJewels.length}
        dpdpAlert={dpdpAlert}
        onResetTopology={handleResetTopology}
      />

      {/* 2. Middle Main Workbench: Left Control Panel + Central Cytoscape Canvas + Right Inspector Drawer */}
      <div className="flex-1 flex min-h-0 overflow-hidden">
        <LeftControlPanel
          mode={mode}
          onModeChange={(m) => {
            setMode(m);
            handleClearHighlight();
          }}
          nodes={nodes}
          edges={edges}
          blastRootId={blastRootId}
          blastHops={blastHops}
          blastResult={blastResult}
          onBlastRootChange={(id) => {
            setBlastRootId(id);
            setSelectedNodeId(id);
            if (blastHops === 0) setBlastHops(2);
          }}
          onBlastHopsChange={setBlastHops}
          chokePoints={chokePoints}
          shortestPaths={shortestPaths}
          severedEdgesCount={severedEdgesCount}
          onRemediateChokePoint={handleRemediateChokePoint}
          onRevokeDormantPrivileges={handleRevokeDormantPrivileges}
          onHighlightPath={handleHighlightPath}
        />

        <main className="flex-1 h-full relative min-w-0">
          <GraphCanvas
            nodes={nodes}
            edges={edges}
            mode={mode}
            blastRadius={blastResult}
            highlightedNodeIds={highlightedNodeIds}
            highlightedEdgeIds={highlightedEdgeIds}
            selectedNodeId={selectedNodeId}
            selectedEdgeId={selectedEdgeId}
            chokePoints={chokePoints}
            shortestPaths={shortestPaths}
            onSelectNode={(id) => {
              setSelectedNodeId(id);
              if (id && id !== blastRootId) {
                const clicked = nodes.find((n) => n.id === id);
                if (clicked && clicked.type !== 'Vulnerability') {
                  setBlastRootId(id);
                }
              }
            }}
            onSelectEdge={setSelectedEdgeId}
          />
        </main>

        <RightInspectorDrawer
          selectedNode={selectedNode}
          selectedEdge={selectedEdge}
          allNodes={nodes}
          allEdges={edges}
          onContainNode={handleContainNode}
          onSeverEdge={handleSeverEdge}
          onSelectNode={(id) => {
            setSelectedNodeId(id);
            setBlastRootId(id);
          }}
          auditLog={auditLog}
        />
      </div>

      {/* 3. Bottom "Alert Collapser" Tray */}
      <BottomAlertTray
        rawAlerts={rawAlerts}
        correlatedIncidents={correlatedIncidents}
        isNarrativeHighlighted={highlightedNodeIds.size > 0}
        onHighlightIncident={handleHighlightIncident}
        onClearHighlight={handleClearHighlight}
        onSelectNode={(id) => {
          setSelectedNodeId(id);
        }}
      />

      <AiCopilotModal
        nodes={nodes}
        edges={edges}
        chokePoints={chokePoints}
        shortestPaths={shortestPaths}
        dpdpAlert={dpdpAlert}
        onRemediateChokePoint={handleRemediateChokePoint}
        onContainNode={handleContainNode}
        onRevokeDormantPrivileges={handleRevokeDormantPrivileges}
      />
      <CsvImportButton onClick={() => setIsCsvImportOpen(true)} />
      <CsvImportDialog
        isOpen={isCsvImportOpen}
        onClose={() => setIsCsvImportOpen(false)}
        existingNodes={nodes}
        onImportComplete={(newTopology, localFallbackPayload, summaryMsg) => {
          const now = new Date().toLocaleTimeString();
          if (newTopology) {
            setNodes(newTopology.nodes);
            setEdges(newTopology.edges);
            setRawAlerts(newTopology.rawAlerts);
            setInitialEdgeCount(newTopology.edges.length);
            setIsOfflineFallback(false);
          } else if (localFallbackPayload) {
            if (localFallbackPayload.mode === 'replace') {
              setNodes(localFallbackPayload.nodes);
              setEdges(localFallbackPayload.edges);
              setRawAlerts(localFallbackPayload.alerts);
              setInitialEdgeCount(localFallbackPayload.edges.length);
            } else {
              setNodes((prev) => {
                const map = new Map(prev.map((n) => [n.id, n]));
                localFallbackPayload.nodes.forEach((n) =>
                  map.set(n.id, { ...map.get(n.id), ...n })
                );
                return Array.from(map.values());
              });
              setEdges((prev) => {
                const map = new Map(prev.map((e) => [e.id, e]));
                localFallbackPayload.edges.forEach((e) =>
                  map.set(e.id, { ...map.get(e.id), ...e })
                );
                const next = Array.from(map.values());
                setInitialEdgeCount(next.length);
                return next;
              });
              if (localFallbackPayload.alerts.length > 0) {
                setRawAlerts((prev) => {
                  const map = new Map(prev.map((a) => [a.id, a]));
                  localFallbackPayload.alerts.forEach((a) =>
                    map.set(a.id, { ...map.get(a.id), ...a })
                  );
                  return Array.from(map.values());
                });
              }
            }
          }
          setAuditLog((prev) => [`[${now}] ${summaryMsg}`, ...prev]);
        }}
      />
    </div>
  );
};

