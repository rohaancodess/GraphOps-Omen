import {
  GraphEdge,
  GraphNode,
  RawSiemAlert,
  TopologyData,
} from '../data/mockTopology';

export interface CsvImportPayload {
  mode: 'merge' | 'replace';
  nodes: GraphNode[];
  edges: GraphEdge[];
  alerts: RawSiemAlert[];
  confirmReplace?: string;
}

export interface CsvImportResponse {
  ok: boolean;
  nodesAdded: number;
  nodesUpdated: number;
  edgesAdded: number;
  edgesUpdated: number;
  alertsAdded: number;
  rejected: number;
}

const FETCH_TIMEOUT_MS = 5000;

async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs: number = FETCH_TIMEOUT_MS
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: Request to ${url} failed`);
    }
    return response;
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchTopology(): Promise<TopologyData> {
  const response = await fetchWithTimeout('/api/topology', {
    method: 'GET',
    headers: { Accept: 'application/json' },
  });

  const data: unknown = await response.json();

  if (
    !data ||
    typeof data !== 'object' ||
    !Array.isArray((data as TopologyData).nodes) ||
    !Array.isArray((data as TopologyData).edges) ||
    !Array.isArray((data as TopologyData).rawAlerts) ||
    (data as TopologyData).nodes.length === 0
  ) {
    throw new Error('Invalid topology payload shape');
  }

  return data as TopologyData;
}

export async function severEdgeApi(
  edgeId: string
): Promise<{ ok: boolean; deleted: number }> {
  const response = await fetchWithTimeout(
    `/api/edges/${encodeURIComponent(edgeId)}/sever`,
    { method: 'POST' }
  );
  return response.json();
}

export async function containNodeApi(
  nodeId: string
): Promise<{ ok: boolean; deletedEdges: number }> {
  const response = await fetchWithTimeout(
    `/api/nodes/${encodeURIComponent(nodeId)}/contain`,
    { method: 'POST' }
  );
  return response.json();
}

export async function revokeDormantApi(): Promise<{
  ok: boolean;
  deleted: number;
}> {
  const response = await fetchWithTimeout('/api/revoke-dormant', {
    method: 'POST',
  });
  return response.json();
}

export async function resetAndSeedApi(): Promise<void> {
  await fetchWithTimeout('/api/reset', { method: 'POST' }, 10000);
  await fetchWithTimeout('/api/seed', { method: 'POST' }, 15000);
}

export async function importCsvApi(
  payload: CsvImportPayload
): Promise<CsvImportResponse> {
  const response = await fetchWithTimeout(
    '/api/import',
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
    },
    15000
  );
  return response.json();
}

export interface AiIncidentBriefPayload {
  language: 'en' | 'hi';
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

export interface AiIncidentBriefResponse {
  ok: boolean;
  model: string;
  brief: string;
  reasoning?: string;
}

export async function generateAiIncidentBriefApi(
  payload: AiIncidentBriefPayload
): Promise<AiIncidentBriefResponse> {
  const response = await fetchWithTimeout(
    '/api/ai/incident-brief',
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
    },
    25000
  );
  return response.json();
}
