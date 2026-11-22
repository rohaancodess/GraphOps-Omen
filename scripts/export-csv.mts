import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { INITIAL_TOPOLOGY } from '../src/data/mockTopology.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.resolve(__dirname, 'out');

const NODE_COLUMNS = [
  'id',
  'label',
  'type',
  'tier',
  'mfa',
  'department',
  'identitySubType',
  'zone',
  'criticality',
  'pii_data',
  'pii_records',
  'compromised',
  'assetSubType',
  'ip',
  'os',
  'cve_id',
  'cvss',
  'exploitable',
  'description',
] as const;

const EDGE_COLUMNS = [
  'id',
  'source',
  'target',
  'relationship',
  'port',
  'last_used_days',
  'is_standing_privilege',
  'timestamp',
  'auth_type',
  'mitre_tactic',
  'bytes',
  'process',
  'is_attack_edge',
  'attack_step_order',
] as const;

const ALERT_COLUMNS = [
  'id',
  'timestamp',
  'severity',
  'title',
  'sourceHost',
  'targetHost',
  'mitreTactic',
  'mitreId',
  'rawLog',
  'isBreachNarrative',
  'narrativeStep',
] as const;

function escapeCsvCell(val: unknown): string {
  if (val === undefined || val === null) return '';
  const str = String(val);
  if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function toCsv<T extends Record<string, unknown>>(
  rows: T[],
  columns: readonly string[]
): string {
  const header = columns.join(',');
  const lines = rows.map((row) =>
    columns.map((col) => escapeCsvCell(row[col])).join(',')
  );
  return [header, ...lines].join('\n') + '\n';
}

fs.mkdirSync(outDir, { recursive: true });

fs.writeFileSync(
  path.join(outDir, 'nodes.csv'),
  toCsv(INITIAL_TOPOLOGY.nodes as unknown as Record<string, unknown>[], NODE_COLUMNS),
  'utf8'
);
fs.writeFileSync(
  path.join(outDir, 'edges.csv'),
  toCsv(INITIAL_TOPOLOGY.edges as unknown as Record<string, unknown>[], EDGE_COLUMNS),
  'utf8'
);
fs.writeFileSync(
  path.join(outDir, 'alerts.csv'),
  toCsv(INITIAL_TOPOLOGY.rawAlerts as unknown as Record<string, unknown>[], ALERT_COLUMNS),
  'utf8'
);

console.log(
  `Exported ${INITIAL_TOPOLOGY.nodes.length} nodes, ${INITIAL_TOPOLOGY.edges.length} edges, ${INITIAL_TOPOLOGY.rawAlerts.length} alerts to ${outDir}`
);
