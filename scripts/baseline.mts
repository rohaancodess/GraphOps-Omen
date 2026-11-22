/**
 * scripts/baseline.mts — Task 1 headless baseline for GraphOps Omen.
 *
 * Loads INITIAL_TOPOLOGY and runs the five analytics functions without any UI:
 *   1. calculateBlastRadius from JumpHost-Corp (3 hops)
 *   2. findShortestAttackPaths (same arguments as the UI: 'ANY', threshold 8)
 *   3. calculateChokePoints
 *   4. mergeAlerts
 *   5. evaluateDpdpRegulatoryAlert
 *
 * Run with:  node --experimental-strip-types scripts/baseline.mts
 * Note: the explicit .ts import extensions are required by Node type stripping.
 * If src/utils/graphAlgorithms.ts fails because of ITS OWN extensionless
 * imports, run this script from a temp copy of src/data and src/utils
 * (see MIGRATION_NOTES.md). Never edit the real source files.
 */
import { INITIAL_TOPOLOGY } from '../src/data/mockTopology.ts';
import {
  calculateBlastRadius,
  calculateChokePoints,
  evaluateDpdpRegulatoryAlert,
  findShortestAttackPaths,
  mergeAlerts,
} from '../src/utils/graphAlgorithms.ts';

const graph = {
  nodes: INITIAL_TOPOLOGY.nodes,
  edges: INITIAL_TOPOLOGY.edges,
};

function countBy<T>(items: T[], key: (item: T) => string): Map<string, number> {
  const map = new Map<string, number>();
  for (const item of items) {
    const k = key(item);
    map.set(k, (map.get(k) ?? 0) + 1);
  }
  return map;
}

// ---------- raw counts ----------
const nodesByType = countBy(graph.nodes, (n) => n.type);
const edgesByRel = countBy(graph.edges, (e) => e.relationship);
const alerts = INITIAL_TOPOLOGY.rawAlerts;
const breachAlerts = alerts.filter((a) => a.isBreachNarrative);
const noiseAlerts = alerts.filter((a) => !a.isBreachNarrative);

console.log('=== GraphOps Omen headless baseline (Task 1) ===');
console.log(
  `Nodes: ${graph.nodes.length} (Identity ${nodesByType.get('Identity') ?? 0}, ` +
    `Asset ${nodesByType.get('Asset') ?? 0}, Vulnerability ${nodesByType.get('Vulnerability') ?? 0})`
);
console.log(
  `Edges: ${graph.edges.length} (CAN_ACCESS ${edgesByRel.get('CAN_ACCESS') ?? 0}, ` +
    `CONNECTED_TO ${edgesByRel.get('CONNECTED_TO') ?? 0}, ` +
    `AUTHENTICATED_TO ${edgesByRel.get('AUTHENTICATED_TO') ?? 0}, ` +
    `HAS_VULN ${edgesByRel.get('HAS_VULN') ?? 0})`
);
console.log(
  `Alerts: ${alerts.length} (breach narrative ${breachAlerts.length}, noise ${noiseAlerts.length})`
);

// ---------- 1. blast radius ----------
const blast = calculateBlastRadius(graph, 'JumpHost-Corp', 3);
console.log(
  `Blast radius from JumpHost-Corp (3 hops): hop1=${blast.hop1Nodes.size}, ` +
    `hop2=${blast.hop2Nodes.size}, hop3=${blast.hop3Nodes.size} ` +
    `(reachableEdges=${blast.reachableEdges.size}, piiRecordsExposed=${blast.piiRecordsExposed})`
);

// ---------- 2. attack paths ----------
const pathsUiArgs = findShortestAttackPaths(graph, 'ANY', 8);
const pathsDefault = findShortestAttackPaths(graph);
console.log(
  `Attack paths (findShortestAttackPaths 'ANY', threshold 8): ${pathsUiArgs.length}`
);
console.log(`Attack paths (default args 'ANY', threshold 9): ${pathsDefault.length}`);

// ---------- 3. choke points ----------
const chokes = calculateChokePoints(graph);
const topNode = chokes.topNodes[0];
const topEdge = chokes.topEdges[0];
console.log(`Choke analysis totalAttackPathsCount: ${chokes.totalAttackPathsCount}`);
console.log(
  topNode
    ? `Top choke node: ${topNode.nodeId} (score ${topNode.centralityScore}, ` +
        `pathsIntercepted ${topNode.pathsIntercepted}, ` +
        `jewelsProtected ${topNode.crownJewelsProtected.length})`
    : 'Top choke node: none'
);
console.log(
  topEdge
    ? `Top choke edge: ${topEdge.edgeId} (score ${topEdge.centralityScore}, ` +
        `pathsIntercepted ${topEdge.pathsIntercepted})`
    : 'Top choke edge: none'
);

// ---------- 4. incident merge ----------
const [incident] = mergeAlerts(alerts, graph);
console.log(
  incident
    ? `Incident: ${incident.id} severity=${incident.severity} ` +
        `(alerts merged ${incident.alertCount}, piiAtRiskRecords ${incident.piiAtRiskRecords})`
    : 'Incident: none'
);

// ---------- 5. DPDP regulatory check ----------
const dpdp = evaluateDpdpRegulatoryAlert(graph);
console.log(
  `DPDP triggered: ${dpdp.triggered} (recordsAtRisk ${dpdp.totalRecordsAtRisk}, ` +
    `shortestBreachHops ${dpdp.shortestBreachHops}, ` +
    `triggeringNode ${dpdp.triggeringCompromisedNode ?? 'n/a'})`
);

// ---------- extra cross-checks ----------
const piiTotal = graph.nodes.reduce(
  (sum, n) => sum + (n.pii_data ? n.pii_records ?? 0 : 0),
  0
);
console.log(`PII records total across PII nodes: ${piiTotal}`);
