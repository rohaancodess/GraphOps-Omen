import React, { useEffect, useMemo, useState } from 'react';
import {
  Bot,
  BrainCircuit,
  Check,
  Copy,
  Download,
  Globe,
  Scissors,
  ShieldCheck,
  Sparkles,
  X,
} from 'lucide-react';
import { GraphEdge, GraphNode } from '../data/mockTopology';
import {
  AttackPathResult,
  ChokePointAnalysis,
  evaluateDpdpRegulatoryAlert,
  findShortestAttackPaths,
} from '../utils/graphAlgorithms';
import { generateAiIncidentBriefApi } from '../api/topologyClient';

interface AiCopilotModalProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  chokePoints: ChokePointAnalysis;
  shortestPaths: AttackPathResult[];
  dpdpAlert: {
    triggered: boolean;
    exposedPiiNodes: GraphNode[];
    totalRecordsAtRisk: number;
    shortestBreachHops: number | null;
    triggeringCompromisedNode: string | null;
  };
  onRemediateChokePoint: (edgeId?: string) => void;
  onContainNode: (nodeId: string) => void;
  onRevokeDormantPrivileges: () => void;
}

export const AiCopilotModal: React.FC<AiCopilotModalProps> = ({
  nodes,
  edges,
  chokePoints,
  shortestPaths,
  dpdpAlert,
  onRemediateChokePoint,
  onContainNode,
  onRevokeDormantPrivileges,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [language, setLanguage] = useState<'en' | 'hi'>('en');
  const [isLoading, setIsLoading] = useState(false);
  const [brief, setBrief] = useState<string>('');
  const [reasoning, setReasoning] = useState<string>('');
  const [showReasoning, setShowReasoning] = useState<boolean>(false);
  const [isOfflineBrief, setIsOfflineBrief] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);

  const topNode = chokePoints.topNodes[0] ?? null;
  const topEdge = chokePoints.topEdges[0] ?? null;
  const dormantEdges = useMemo(
    () => edges.filter((e) => (e.last_used_days ?? 0) > 90),
    [edges]
  );

  // Counterfactual Simulation 1: Sever #1 Choke Edge
  const simChokeEdge = useMemo(() => {
    if (!topEdge) {
      return {
        pathsAfter: shortestPaths.length,
        dpdpAfter: dpdpAlert.triggered,
        piiAfter: dpdpAlert.totalRecordsAtRisk,
      };
    }
    const g = { nodes, edges: edges.filter((e) => e.id !== topEdge.edgeId) };
    const p = findShortestAttackPaths(g, 'ANY', 8);
    const d = evaluateDpdpRegulatoryAlert(g);
    return {
      pathsAfter: p.length,
      dpdpAfter: d.triggered,
      piiAfter: d.totalRecordsAtRisk,
    };
  }, [nodes, edges, topEdge, shortestPaths.length, dpdpAlert]);

  // Counterfactual Simulation 2: Contain #1 Choke Node (JumpHost-Corp)
  const simContainNode = useMemo(() => {
    const targetId = topNode?.nodeId || 'JumpHost-Corp';
    const g = {
      nodes: nodes.map((n) =>
        n.id === targetId ? { ...n, compromised: false } : n
      ),
      edges: edges.filter((e) => e.source !== targetId),
    };
    const p = findShortestAttackPaths(g, 'ANY', 8);
    const d = evaluateDpdpRegulatoryAlert(g);
    return {
      targetId,
      pathsAfter: p.length,
      dpdpAfter: d.triggered,
      piiAfter: d.totalRecordsAtRisk,
    };
  }, [nodes, edges, topNode]);

  // Counterfactual Simulation 3: Revoke all >90d Dormant Privileges
  const simZeroTrust = useMemo(() => {
    const g = {
      nodes,
      edges: edges.filter((e) => (e.last_used_days ?? 0) <= 90),
    };
    const p = findShortestAttackPaths(g, 'ANY', 8);
    const d = evaluateDpdpRegulatoryAlert(g);
    return {
      pathsAfter: p.length,
      dpdpAfter: d.triggered,
      piiAfter: d.totalRecordsAtRisk,
    };
  }, [nodes, edges]);

  useEffect(() => {
    if (!isOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setIsOpen(false);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [isOpen]);

  const buildFallbackBrief = (lang: 'en' | 'hi') => {
    const compList =
      nodes
        .filter((n) => n.compromised)
        .map((n) => n.label)
        .join(', ') || 'None';
    if (lang === 'hi') {
      return `1. [CERT-In / DPDP Act 6-Hour Regulatory Disclosure Status]
• स्थिति: ${dpdpAlert.triggered ? 'सक्रिय उल्लंघन (ACTIVE BREACH - 6 घंटे की अनिवार्य रिपोर्टिंग विंडो चालू)' : 'नियंत्रित (CONTAINED)'}
• प्रभावित PII रिकॉर्ड्स: ${dpdpAlert.totalRecordsAtRisk.toLocaleString()} (${dpdpAlert.triggeringCompromisedNode ?? 'N/A'} से ${dpdpAlert.shortestBreachHops ?? 0} हॉप की दूरी पर)

2. [Multi-Hop Kill-Chain & Choke-Point Root Cause]
• संक्रमित होस्ट: ${compList}
• प्रमुख चोक-पॉइंट (Choke Node): ${topNode?.nodeId ?? 'JumpHost-Corp'} (Centrality Score: ${topNode?.centralityScore ?? 0.99})
• प्रमुख ब्रिज एज: ${topEdge ? `${topEdge.source} → ${topEdge.target} (${topEdge.relationship})` : 'N/A'}

3. [Counterfactual What-If Remediation Impact]
• Choke Edge हटाने पर: Dijkstra अटैक पाथ ${shortestPaths.length} से घटकर ${simChokeEdge.pathsAfter} हो जाएंगे।
• ${simContainNode.targetId} को आइसोलेट करने पर: अटैक पाथ ${shortestPaths.length} → ${simContainNode.pathsAfter}, और PII जोखिम ${(dpdpAlert.totalRecordsAtRisk / 1000000).toFixed(2)}M → ${(simContainNode.piiAfter / 1000000).toFixed(2)}M।
• ${dormantEdges.length} निष्क्रिय (>90 दिन) विशेषाधिकार रद्द करने पर: अटैक पाथ ${shortestPaths.length} → ${simZeroTrust.pathsAfter}।

4. [Immediate 3-Step SOAR Containment Playbook]
1. तुरंत ${topEdge?.edgeId ?? 'edge-attack-2-static'} ब्रिज को काटें या ${simContainNode.targetId} को कंटेन करें।
2. >90 दिनों से अप्रयुक्त सभी ${dormantEdges.length} स्थायी SSH/IAM विशेषाधिकारों को रद्द करें।
3. CERT-In और DPDP अनुपालन लॉग निर्यात करें और टियर-1 सेवा खातों के JWT टोकन रोटेट करें।`;
    }

    return `1. [CERT-In / DPDP Act 6-Hour Regulatory Disclosure Status]
• Mandate Status: ${dpdpAlert.triggered ? 'TRIGGERED — Active 6-Hour CERT-In & India DPDP Act 2023 Disclosure Clock' : 'CONTAINED — All PII Vaults Isolated from 2-Hop Blast Cone'}
• Regulated PII Exposure: ${dpdpAlert.totalRecordsAtRisk.toLocaleString()} records at risk (${dpdpAlert.shortestBreachHops ?? 0}-hop reachability from ${dpdpAlert.triggeringCompromisedNode ?? 'N/A'}).

2. [Multi-Hop Kill-Chain & Choke-Point Root Cause]
• Compromised Entities: ${compList}
• Primary Transit Choke Hub: ${topNode?.nodeId ?? 'JumpHost-Corp'} (Betweenness Centrality: ${topNode?.centralityScore ?? 0.99}, intercepting ${topNode?.pathsIntercepted ?? 0} paths across ${topNode?.crownJewelsProtected.length ?? 0} Crown Jewels).
• Critical Lateral Bridge Vector: ${topEdge ? `${topEdge.source} → ${topEdge.target} (${topEdge.relationship}, ID: ${topEdge.edgeId})` : 'None'}.

3. [Counterfactual What-If Remediation Impact (Before vs. After)]
• Severing #1 Choke Edge (${topEdge?.edgeId ?? 'N/A'}): Reduces Dijkstra attack paths from ${shortestPaths.length} → ${simChokeEdge.pathsAfter}.
• Full Host Containment (${simContainNode.targetId}): Collapses attack paths from ${shortestPaths.length} → ${simContainNode.pathsAfter} and drops 2-hop PII exposure from ${(dpdpAlert.totalRecordsAtRisk / 1000000).toFixed(2)}M → ${(simContainNode.piiAfter / 1000000).toFixed(2)}M (${simContainNode.dpdpAfter ? 'Active' : 'DPDP Contained'}).
• Zero-Trust Drift Purge (${dormantEdges.length} edges >90d): Reduces attack paths from ${shortestPaths.length} → ${simZeroTrust.pathsAfter}.

4. [Immediate 3-Step SOAR Containment Playbook]
1. Execute immediate containment on ${simContainNode.targetId} and sever ${topEdge?.edgeId ?? 'primary choke edge'} to break lateral transit to svc-cicd-runner.
2. Purge all ${dormantEdges.length} dormant standing privileges unused >90 days (eliminating the 120-day stale SSH key vector).
3. Rotate Tier-1 CI/CD OIDC/JWT credentials and file this automated CERT-In 6-hour regulatory artifact.`;
  };

  const handleGenerateBrief = async (targetLang: 'en' | 'hi' = language) => {
    setIsLoading(true);
    setCopied(false);

    try {
      const res = await generateAiIncidentBriefApi({
        language: targetLang,
        graphSummary: {
          totalNodes: nodes.length,
          totalEdges: edges.length,
          compromisedNodes: nodes
            .filter((n) => n.compromised)
            .map((n) => n.label),
          topChokeNode: topNode
            ? {
              nodeId: topNode.nodeId,
              centralityScore: topNode.centralityScore,
              pathsIntercepted: topNode.pathsIntercepted,
              crownJewelsProtected: topNode.crownJewelsProtected,
            }
            : null,
          topChokeEdge: topEdge
            ? {
              edgeId: topEdge.edgeId,
              source: topEdge.source,
              target: topEdge.target,
              relationship: topEdge.relationship,
              centralityScore: topEdge.centralityScore,
              pathsIntercepted: topEdge.pathsIntercepted,
            }
            : null,
          attackPathsCount: shortestPaths.length,
          simAttackPathsAfterChoke: simChokeEdge.pathsAfter,
          simAttackPathsAfterZeroTrust: simZeroTrust.pathsAfter,
          dormantEdgesCount: dormantEdges.length,
          dpdpTriggered: dpdpAlert.triggered,
          simDpdpAfterChoke: simChokeEdge.dpdpAfter,
          piiRecordsAtRisk: dpdpAlert.totalRecordsAtRisk,
          triggeringNode: dpdpAlert.triggeringCompromisedNode,
          shortestBreachHops: dpdpAlert.shortestBreachHops,
        },
      });

      if (res.ok && res.brief) {
        setBrief(res.brief);
        setReasoning(res.reasoning || '');
        setIsOfflineBrief(false);
      } else {
        setBrief(buildFallbackBrief(targetLang));
        setReasoning('');
        setIsOfflineBrief(true);
      }
    } catch {
      setBrief(buildFallbackBrief(targetLang));
      setReasoning('');
      setIsOfflineBrief(true);
    } finally {
      setIsLoading(false);
    }
  };

  const handleOpen = () => {
    setIsOpen(true);
    if (!brief) {
      handleGenerateBrief(language);
    }
  };

  const handleCopy = () => {
    if (!brief) return;
    navigator.clipboard?.writeText(brief);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadMd = () => {
    if (!brief) return;
    const blob = new Blob([`# GraphOps Omen — CERT-In / DPDP Incident Brief\n\n${brief}\n`], {
      type: 'text/markdown;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CERT-In-DPDP-Incident-Brief-${language}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <button
        type="button"
        onClick={handleOpen}
        title="Launch Sarvam AI (GLM-5.3 Flash) SOC Copilot & Counterfactual What-If Simulator"
        className="absolute bottom-16 right-36 z-[46] flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-extrabold bg-[#fff318] text-[#0a0a0c] border-2 border-[#0a0a0c] hover:opacity-95 shadow-lg transition cursor-pointer"
      >
        <Sparkles className="w-3.5 h-3.5" />
        <span>Sarvam AI</span>
      </button>

      {isOpen && (
        <div
          data-lenis-prevent
          onWheel={(e) => e.stopPropagation()}
          className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-2 sm:p-4"
        >
          <div
            data-lenis-prevent
            className="w-full max-w-4xl max-h-[92vh] bg-[#0a0a0c] border-2 border-[#fff318] rounded-xl shadow-2xl flex flex-col overflow-hidden text-slate-100"
          >
            {/* Header */}
            <div className="px-4 py-3 border-b border-[#fff318]/30 flex flex-wrap items-center justify-between gap-2 bg-zinc-950">
              <div className="flex items-center gap-2.5">
                <div className="p-1.5 rounded-lg bg-[#fff318] text-[#0a0a0c]">
                  <Bot className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-sm font-extrabold text-white tracking-tight">
                      Sarvam AI SOC Copilot &amp; Counterfactual Simulator
                    </h2>
                    <span className="px-1.5 py-0.5 rounded bg-[#fff318]/20 border border-[#fff318]/50 text-[#fff318] font-mono text-[10px] font-bold">
                      glm5.3-flash
                    </span>
                    {isOfflineBrief && (
                      <span className="px-1.5 py-0.5 rounded bg-amber-500 text-slate-950 font-bold uppercase text-[10px]">
                        local graph engine
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-zinc-400">
                    Real-time What-If blast simulation &amp; automated CERT-In / India DPDP Act 6-Hour compliance brief
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <div className="flex items-center rounded-lg bg-zinc-900 border border-zinc-700 p-0.5">
                  <button
                    type="button"
                    onClick={() => {
                      setLanguage('en');
                      handleGenerateBrief('en');
                    }}
                    className={`px-2.5 py-1 rounded-md text-[11px] font-extrabold transition cursor-pointer ${language === 'en'
                        ? 'bg-[#fff318] text-[#0a0a0c]'
                        : 'text-zinc-400 hover:text-white'
                      }`}
                  >
                    English
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setLanguage('hi');
                      handleGenerateBrief('hi');
                    }}
                    className={`flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-extrabold transition cursor-pointer ${language === 'hi'
                        ? 'bg-[#fff318] text-[#0a0a0c]'
                        : 'text-zinc-400 hover:text-white'
                      }`}
                  >
                    <Globe className="w-3 h-3" />
                    <span>हिन्दी (Indic)</span>
                  </button>
                </div>

                <button
                  type="button"
                  onClick={() => setIsOpen(false)}
                  className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800 transition cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto p-3 sm:p-4 space-y-4">
              {/* 1. Counterfactual What-If Comparison Matrix */}
              <div>
                <div className="text-xs font-extrabold uppercase tracking-wider text-[#fff318] mb-2 flex items-center gap-1.5">
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Counterfactual &quot;What-If&quot; Remediation Simulator (Live In-Memory Delta)</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
                  {/* Card 1: Sever Top Choke Edge */}
                  <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-3 flex flex-col justify-between space-y-2">
                    <div>
                      <div className="text-[10px] font-bold uppercase text-amber-400">
                        Option A • Sever #1 Choke Edge
                      </div>
                      <div className="text-xs font-mono font-bold text-white truncate mt-0.5">
                        {topEdge
                          ? `${topEdge.source} → ${topEdge.target}`
                          : 'No active choke edge'}
                      </div>
                      <div className="mt-2 space-y-1 text-[11px] font-mono">
                        <div className="flex justify-between">
                          <span className="text-zinc-400">Attack Paths:</span>
                          <span>
                            <span className="text-red-400">{shortestPaths.length}</span>
                            {' → '}
                            <span className="text-emerald-400 font-bold">
                              {simChokeEdge.pathsAfter}
                            </span>
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-zinc-400">2-Hop PII Risk:</span>
                          <span>
                            <span className="text-red-400">
                              {(dpdpAlert.totalRecordsAtRisk / 1000000).toFixed(2)}M
                            </span>
                            {' → '}
                            <span className="text-emerald-400 font-bold">
                              {(simChokeEdge.piiAfter / 1000000).toFixed(2)}M
                            </span>
                          </span>
                        </div>
                      </div>
                    </div>
                    {topEdge && (
                      <button
                        type="button"
                        onClick={() => {
                          onRemediateChokePoint(topEdge.edgeId);
                          setTimeout(() => handleGenerateBrief(language), 100);
                        }}
                        className="w-full py-1.5 px-2.5 rounded bg-zinc-900 hover:bg-[#fff318] hover:text-[#0a0a0c] text-[#fff318] border border-[#fff318]/40 text-[11px] font-extrabold flex items-center justify-center gap-1.5 transition cursor-pointer"
                      >
                        <Scissors className="w-3 h-3" />
                        <span>Execute Edge Sever</span>
                      </button>
                    )}
                  </div>

                  {/* Card 2: Full Host Containment */}
                  <div className="bg-zinc-950 border border-[#fff318]/50 rounded-lg p-3 flex flex-col justify-between space-y-2">
                    <div>
                      <div className="text-[10px] font-bold uppercase text-[#fff318]">
                        Option B • Isolate Choke Host (Recommended)
                      </div>
                      <div className="text-xs font-mono font-bold text-white truncate mt-0.5">
                        Contain {simContainNode.targetId}
                      </div>
                      <div className="mt-2 space-y-1 text-[11px] font-mono">
                        <div className="flex justify-between">
                          <span className="text-zinc-400">Attack Paths:</span>
                          <span>
                            <span className="text-red-400">{shortestPaths.length}</span>
                            {' → '}
                            <span className="text-emerald-400 font-bold">
                              {simContainNode.pathsAfter}
                            </span>
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-zinc-400">DPDP Mandate:</span>
                          <span className="text-emerald-400 font-bold">
                            {simContainNode.dpdpAfter ? 'ACTIVE' : 'CONTAINED ✓'}
                          </span>
                        </div>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        onContainNode(simContainNode.targetId);
                        setTimeout(() => handleGenerateBrief(language), 100);
                      }}
                      className="w-full py-1.5 px-2.5 rounded bg-[#fff318] text-[#0a0a0c] hover:opacity-90 text-[11px] font-extrabold flex items-center justify-center gap-1.5 transition cursor-pointer"
                    >
                      <ShieldCheck className="w-3.5 h-3.5" />
                      <span>Isolate {simContainNode.targetId} Now</span>
                    </button>
                  </div>

                  {/* Card 3: Zero-Trust Dormant Purge */}
                  <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-3 flex flex-col justify-between space-y-2">
                    <div>
                      <div className="text-[10px] font-bold uppercase text-sky-400">
                        Option C • Zero-Trust Drift Purge (&gt;90d)
                      </div>
                      <div className="text-xs font-mono font-bold text-white truncate mt-0.5">
                        Revoke {dormantEdges.length} Stale Entitlements
                      </div>
                      <div className="mt-2 space-y-1 text-[11px] font-mono">
                        <div className="flex justify-between">
                          <span className="text-zinc-400">Attack Paths:</span>
                          <span>
                            <span className="text-red-400">{shortestPaths.length}</span>
                            {' → '}
                            <span className="text-emerald-400 font-bold">
                              {simZeroTrust.pathsAfter}
                            </span>
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-zinc-400">Stale Vectors:</span>
                          <span>
                            <span className="text-red-400">{dormantEdges.length}</span>
                            {' → '}
                            <span className="text-emerald-400 font-bold">0</span>
                          </span>
                        </div>
                      </div>
                    </div>
                    <button
                      type="button"
                      disabled={dormantEdges.length === 0}
                      onClick={() => {
                        onRevokeDormantPrivileges();
                        setTimeout(() => handleGenerateBrief(language), 100);
                      }}
                      className={`w-full py-1.5 px-2.5 rounded text-[11px] font-extrabold flex items-center justify-center gap-1.5 transition ${dormantEdges.length > 0
                          ? 'bg-zinc-900 hover:bg-[#fff318] hover:text-[#0a0a0c] text-[#fff318] border border-[#fff318]/40 cursor-pointer'
                          : 'bg-zinc-900 text-zinc-600 border border-zinc-800 cursor-not-allowed'
                        }`}
                    >
                      <span>Purge {dormantEdges.length} Dormant Edges</span>
                    </button>
                  </div>
                </div>
              </div>

              {/* 2. Collapsible GLM-5.3 Flash Reasoning Trace */}
              {reasoning && (
                <div className="bg-zinc-950 border border-zinc-800 rounded-lg overflow-hidden">
                  <button
                    type="button"
                    onClick={() => setShowReasoning((s) => !s)}
                    className="w-full px-3 py-2 flex items-center justify-between text-xs font-bold text-zinc-300 hover:bg-zinc-900 transition cursor-pointer"
                  >
                    <span className="flex items-center gap-1.5">
                      <BrainCircuit className="w-3.5 h-3.5 text-[#fff318]" />
                      <span>Sarvam GLM-5.3 Flash Chain-of-Thought Reasoning Trace</span>
                    </span>
                    <span className="text-[11px] text-[#fff318]">
                      {showReasoning ? 'Hide ▴' : 'Inspect Reasoning ▾'}
                    </span>
                  </button>
                  {showReasoning && (
                    <pre className="p-3 border-t border-zinc-800 text-[11px] font-mono text-zinc-400 whitespace-pre-wrap leading-relaxed max-h-40 overflow-y-auto bg-black/40">
                      {reasoning}
                    </pre>
                  )}
                </div>
              )}

              {/* 3. Generated CERT-In / DPDP Regulatory & Incident Brief */}
              <div className="bg-zinc-950 border border-[#fff318]/40 rounded-lg overflow-hidden">
                <div className="px-3.5 py-2 bg-zinc-900 border-b border-zinc-800 flex flex-wrap items-center justify-between gap-2">
                  <span className="text-xs font-extrabold text-white">
                    CERT-In 6-Hour Disclosure &amp; Executive SOAR Brief ({language === 'hi' ? 'हिन्दी' : 'English'})
                  </span>
                  <div className="flex items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => handleGenerateBrief(language)}
                      disabled={isLoading}
                      className="px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-[11px] font-bold text-[#fff318] transition cursor-pointer"
                    >
                      {isLoading ? 'Synthesizing...' : 'Regenerate'}
                    </button>
                    <button
                      type="button"
                      onClick={handleCopy}
                      disabled={!brief || isLoading}
                      className="flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-[11px] font-bold text-white transition cursor-pointer"
                    >
                      {copied ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span>Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy</span>
                        </>
                      )}
                    </button>
                    <button
                      type="button"
                      onClick={handleDownloadMd}
                      disabled={!brief || isLoading}
                      className="flex items-center gap-1 px-2.5 py-1 rounded bg-[#fff318] text-[#0a0a0c] text-[11px] font-extrabold hover:opacity-90 transition cursor-pointer"
                    >
                      <Download className="w-3 h-3" />
                      <span>Export .md</span>
                    </button>
                  </div>
                </div>

                <div className="p-4">
                  {isLoading ? (
                    <div className="py-10 flex flex-col items-center justify-center gap-2 text-[#fff318]">
                      <div className="w-6 h-6 border-2 border-[#fff318] border-t-transparent rounded-full animate-spin" />
                      <div className="text-xs font-bold">
                        Sarvam AI (glm5.3-flash) analyzing live graph topology &amp; DPDP compliance...
                      </div>
                    </div>
                  ) : (
                    <pre className="text-xs font-sans text-zinc-200 whitespace-pre-wrap leading-relaxed">
                      {brief}
                    </pre>
                  )}
                </div>
              </div>
            </div>

            {/* Footer */}
            <div className="px-4 py-2.5 border-t border-zinc-800 bg-zinc-950 flex items-center justify-between text-[11px] text-zinc-400">
              <span>
                API Key stays server-side via <code className="text-zinc-200">POST /api/ai/incident-brief</code>
              </span>
              <button
                type="button"
                onClick={() => setIsOpen(false)}
                className="px-3 py-1 rounded bg-zinc-900 text-zinc-200 border border-zinc-700 hover:bg-zinc-800 font-semibold cursor-pointer"
              >
                Close (Esc)
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
