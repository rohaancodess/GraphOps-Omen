import { Request, Response } from 'express';

export interface AiBriefRequestPayload {
  language?: 'en' | 'hi';
  graphSummary: {
    totalNodes: number;
    totalEdges: number;
    compromisedNodes: string[];
    topChokeNode?: {
      nodeId: string;
      centralityScore: number;
      pathsIntercepted: number;
      crownJewelsProtected: string[];
    } | null;
    topChokeEdge?: {
      edgeId: string;
      source: string;
      target: string;
      relationship: string;
      centralityScore: number;
      pathsIntercepted: number;
    } | null;
    attackPathsCount: number;
    simAttackPathsAfterChoke: number;
    simAttackPathsAfterZeroTrust: number;
    dormantEdgesCount: number;
    dpdpTriggered: boolean;
    simDpdpAfterChoke: boolean;
    piiRecordsAtRisk: number;
    triggeringNode?: string | null;
    shortestBreachHops?: number | null;
  };
}

export function createAiIncidentBriefHandler() {
  return async (req: Request, res: Response) => {
    const apiKey = process.env.SARVAM_API_KEY;
    if (!apiKey) {
      return res.status(503).json({
        ok: false,
        error: 'SARVAM_API_KEY is not configured on the server',
      });
    }

    const body = req.body as AiBriefRequestPayload | undefined;
    if (!body || !body.graphSummary) {
      return res.status(400).json({
        ok: false,
        error: 'Missing graphSummary in request body',
      });
    }

    const lang = body.language === 'hi' ? 'hi' : 'en';
    const g = body.graphSummary;

    const systemPrompt =
      lang === 'hi'
        ? 'आप एक वरिष्ठ SOC Incident Commander और CERT-In / India DPDP Act 2023 साइबर सुरक्षा अनुपालन विशेषज्ञ हैं। दिए गए लाइव ग्राफ़ टोपोलॉजी डेटा के आधार पर एक संक्षिप्त, कार्रवाई-योग्य सुरक्षा रिपोर्ट हिन्दी में (तकनीकी होस्टनाम और CVE अंग्रेज़ी में रखते हुए) तैयार करें।'
        : 'You are a Senior SOC Incident Commander and CERT-In / India DPDP Act 2023 Regulatory Compliance Architect. Generate a concise, high-impact executive & technical incident brief based strictly on the live Neo4j graph telemetry provided.';

    const userPrompt = `Live Enterprise Graph Telemetry (GraphOps Omen):
- Topology Inventory: ${g.totalNodes} nodes, ${g.totalEdges} active edges
- Confirmed Compromised Nodes: ${g.compromisedNodes.join(', ') || 'None'}
- Active Dijkstra Attack Paths to Crown Jewels: ${g.attackPathsCount}
- #1 Betweenness Centrality Choke Node: ${g.topChokeNode ? `${g.topChokeNode.nodeId} (score ${g.topChokeNode.centralityScore}, intercepts ${g.topChokeNode.pathsIntercepted} paths, shields ${g.topChokeNode.crownJewelsProtected.join(', ')})` : 'None'}
- #1 Recommended Choke Edge to Sever: ${g.topChokeEdge ? `${g.topChokeEdge.source} -> ${g.topChokeEdge.target} (${g.topChokeEdge.relationship}, id: ${g.topChokeEdge.edgeId}, score ${g.topChokeEdge.centralityScore})` : 'None'}
- Counterfactual What-If Simulation:
  * If #1 Choke Edge is severed: Attack paths drop from ${g.attackPathsCount} -> ${g.simAttackPathsAfterChoke}; DPDP 2-Hop Alert becomes ${g.simDpdpAfterChoke ? 'ACTIVE' : 'CONTAINED'}.
  * If ${g.dormantEdgesCount} Dormant (>90d) Zero-Trust edges are revoked: Attack paths drop from ${g.attackPathsCount} -> ${g.simAttackPathsAfterZeroTrust}.
- CERT-In / India DPDP Act Status: ${g.dpdpTriggered ? `TRIGGERED (6-Hour Mandatory Disclosure Window active — ${g.piiRecordsAtRisk.toLocaleString()} PII records at risk within ${g.shortestBreachHops} hop(s) of ${g.triggeringNode})` : 'CONTAINED (0 PII records within 2 hops)'}

Write a structured 4-section brief (${lang === 'hi' ? 'in Hindi with technical IDs in English' : 'in clear, authoritative English'}):
1. [CERT-In / DPDP Act 6-Hour Regulatory Disclosure Status]
2. [Multi-Hop Kill-Chain & Choke-Point Root Cause]
3. [Counterfactual What-If Remediation Impact (Before vs. After)]
4. [Immediate 3-Step SOAR Containment Playbook]`;

    try {
      const response = await fetch('https://api.sarvam.ai/v2/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'api-subscription-key': apiKey,
        },
        body: JSON.stringify({
          model: 'glm5.3-flash',
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userPrompt },
          ],
          max_tokens: 900,
        }),
      });

      if (!response.ok) {
        return res.status(502).json({
          ok: false,
          error: 'Sarvam AI upstream call failed',
        });
      }

      const data = (await response.json()) as {
        model?: string;
        choices?: {
          message?: {
            content?: string;
            reasoning_content?: string;
          };
        }[];
      };

      const msg = data.choices?.[0]?.message;
      return res.json({
        ok: true,
        model: data.model || 'glm5.3-flash',
        brief: msg?.content || '',
        reasoning: msg?.reasoning_content || '',
      });
    } catch {
      return res.status(500).json({
        ok: false,
        error: 'Failed to generate AI incident brief',
      });
    }
  };
}
