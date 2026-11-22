import Papa from 'papaparse';
import {
  EdgeRelationship,
  GraphEdge,
  GraphNode,
  NodeType,
  RawSiemAlert,
  ZoneType,
} from '../data/mockTopology';

export const MAX_CSV_FILE_BYTES = 2 * 1024 * 1024; // 2 MB
export const MAX_CSV_ROWS = 5000;

export const NODE_COLUMNS = [
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

export const REQUIRED_NODE_COLUMNS = ['id', 'label', 'type'] as const;

export const EDGE_COLUMNS = [
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

export const REQUIRED_EDGE_COLUMNS = [
  'id',
  'source',
  'target',
  'relationship',
] as const;

export const ALERT_COLUMNS = [
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

export const REQUIRED_ALERT_COLUMNS = [
  'id',
  'timestamp',
  'severity',
  'title',
  'sourceHost',
  'targetHost',
  'mitreTactic',
  'mitreId',
  'rawLog',
] as const;

export const ALLOWED_NODE_TYPES: readonly NodeType[] = [
  'Identity',
  'Asset',
  'Vulnerability',
];
export const ALLOWED_ZONES: readonly ZoneType[] = ['DMZ', 'Corp', 'Prod'];
export const ALLOWED_IDENTITY_SUBTYPES = [
  'User',
  'ServiceAccount',
  'Contractor',
] as const;
export const ALLOWED_ASSET_SUBTYPES = [
  'Endpoint',
  'Server',
  'Database',
  'Cluster',
  'Directory',
] as const;
export const ALLOWED_TIERS = [1, 2, 3] as const;
export const ALLOWED_RELATIONSHIPS: readonly EdgeRelationship[] = [
  'CAN_ACCESS',
  'AUTHENTICATED_TO',
  'CONNECTED_TO',
  'HAS_VULN',
];
export const ALLOWED_ALERT_SEVERITIES = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
] as const;

export interface CsvValidationIssue {
  file: string;
  row: number;
  column: string;
  message: string;
}

export interface CsvFileInput {
  name: string;
  size: number;
  content?: string;
  text?: () => Promise<string>;
}

export interface CsvPreviewFile {
  name: string;
  kind: 'nodes' | 'edges' | 'alerts';
  totalRows: number;
  columns: string[];
  firstFiveRows: Record<string, string>[];
}

export interface CsvParseResult {
  nodes: GraphNode[];
  edges: GraphEdge[];
  alerts: RawSiemAlert[];
  errors: CsvValidationIssue[];
  warnings: CsvValidationIssue[];
  previews: CsvPreviewFile[];
}

function detectFileKind(
  fileName: string,
  headers: string[]
): 'nodes' | 'edges' | 'alerts' {
  const lower = fileName.toLowerCase();
  if (lower.includes('edge')) return 'edges';
  if (lower.includes('alert')) return 'alerts';
  if (lower.includes('node')) return 'nodes';

  const headerSet = new Set(headers);
  if (
    headerSet.has('relationship') ||
    (headerSet.has('source') && headerSet.has('target'))
  ) {
    return 'edges';
  }
  if (
    headerSet.has('sourceHost') ||
    headerSet.has('targetHost') ||
    headerSet.has('rawLog')
  ) {
    return 'alerts';
  }
  return 'nodes';
}

function parseBool(
  raw: string,
  file: string,
  row: number,
  column: string,
  errors: CsvValidationIssue[]
): boolean | undefined {
  const trimmed = raw.trim();
  if (trimmed === '') return undefined;
  const lower = trimmed.toLowerCase();
  if (lower === 'true') return true;
  if (lower === 'false') return false;
  errors.push({
    file,
    row,
    column,
    message: `Invalid boolean '${trimmed}' (expected 'true' or 'false')`,
  });
  return undefined;
}

function parseNum(
  raw: string,
  file: string,
  row: number,
  column: string,
  errors: CsvValidationIssue[],
  opts: { min?: number; max?: number; integer?: boolean } = {}
): number | undefined {
  const trimmed = raw.trim();
  if (trimmed === '') return undefined;
  const val = Number(trimmed);
  if (!Number.isFinite(val)) {
    errors.push({
      file,
      row,
      column,
      message: `Invalid number '${trimmed}'`,
    });
    return undefined;
  }
  if (opts.integer && !Number.isInteger(val)) {
    errors.push({
      file,
      row,
      column,
      message: `Expected integer in '${column}', got '${trimmed}'`,
    });
    return undefined;
  }
  if (opts.min !== undefined && val < opts.min) {
    errors.push({
      file,
      row,
      column,
      message: `Value ${val} out of range (min ${opts.min}${opts.max !== undefined ? `, max ${opts.max}` : ''})`,
    });
    return undefined;
  }
  if (opts.max !== undefined && val > opts.max) {
    errors.push({
      file,
      row,
      column,
      message: `Value ${val} out of range (${opts.min !== undefined ? `min ${opts.min}, ` : ''}max ${opts.max})`,
    });
    return undefined;
  }
  return val;
}

export async function parseAndValidate(
  files: CsvFileInput[],
  existingNodeIds: Iterable<string> = [],
  mode: 'merge' | 'replace' = 'merge'
): Promise<CsvParseResult> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const alerts: RawSiemAlert[] = [];
  const errors: CsvValidationIssue[] = [];
  const warnings: CsvValidationIssue[] = [];
  const previews: CsvPreviewFile[] = [];

  if (!files || files.length === 0) {
    errors.push({
      file: '(none)',
      row: 0,
      column: '',
      message: 'No CSV files provided',
    });
    return { nodes, edges, alerts, errors, warnings, previews };
  }

  if (files.length > 3) {
    errors.push({
      file: '(upload)',
      row: 0,
      column: '',
      message: 'Maximum 3 CSV files allowed (nodes.csv, edges.csv, alerts.csv)',
    });
    return { nodes, edges, alerts, errors, warnings, previews };
  }

  const pendingEdges: { edge: GraphEdge; file: string; row: number }[] = [];
  const uploadedNodeIds = new Set<string>();

  for (const f of files) {
    const fileName = f.name || 'unnamed.csv';

    if (!fileName.toLowerCase().endsWith('.csv')) {
      errors.push({
        file: fileName,
        row: 0,
        column: '',
        message: `Invalid file type '${fileName}': only .csv files are accepted`,
      });
      continue;
    }

    if (f.size > MAX_CSV_FILE_BYTES) {
      errors.push({
        file: fileName,
        row: 0,
        column: '',
        message: `File '${fileName}' exceeds maximum size of 2 MB (${f.size} bytes)`,
      });
      continue;
    }

    const rawText =
      typeof f.content === 'string'
        ? f.content
        : typeof f.text === 'function'
          ? await f.text()
          : '';

    const byteLen = new TextEncoder().encode(rawText).length;
    if (byteLen > MAX_CSV_FILE_BYTES) {
      errors.push({
        file: fileName,
        row: 0,
        column: '',
        message: `File '${fileName}' content exceeds maximum size of 2 MB (${byteLen} bytes)`,
      });
      continue;
    }

    const parsed = Papa.parse<Record<string, string>>(rawText, {
      header: true,
      skipEmptyLines: 'greedy',
    });

    const headers = parsed.meta.fields ?? [];
    if (headers.length === 0) {
      errors.push({
        file: fileName,
        row: 1,
        column: '',
        message: 'CSV file is missing a header row',
      });
      continue;
    }

    for (const pe of parsed.errors) {
      // Ignore trailing delimiter warning if columns are valid
      if (pe.code === 'UndetectableDelimiter') continue;
      errors.push({
        file: fileName,
        row: (pe.row ?? 0) + 2,
        column: '',
        message: `CSV syntax error: ${pe.message}`,
      });
    }

    const rows = parsed.data;
    if (rows.length > MAX_CSV_ROWS) {
      errors.push({
        file: fileName,
        row: MAX_CSV_ROWS + 1,
        column: '',
        message: `File '${fileName}' has ${rows.length} rows, exceeding maximum of ${MAX_CSV_ROWS} rows`,
      });
      continue;
    }

    const kind = detectFileKind(fileName, headers);
    previews.push({
      name: fileName,
      kind,
      totalRows: rows.length,
      columns: headers,
      firstFiveRows: rows.slice(0, 5),
    });

    if (kind === 'nodes') {
      const allowedSet = new Set<string>(NODE_COLUMNS);
      let headerErr = false;
      for (const reqCol of REQUIRED_NODE_COLUMNS) {
        if (!headers.includes(reqCol)) {
          errors.push({
            file: fileName,
            row: 1,
            column: reqCol,
            message: `Missing required column '${reqCol}'`,
          });
          headerErr = true;
        }
      }
      for (const h of headers) {
        if (!allowedSet.has(h)) {
          errors.push({
            file: fileName,
            row: 1,
            column: h,
            message: `Unknown column '${h}' is not allowed in nodes.csv`,
          });
          headerErr = true;
        }
      }
      if (headerErr) continue;

      const seenIds = new Set<string>();
      rows.forEach((r, idx) => {
        const rowNum = idx + 2; // 1-based including header
        const rowErrorsStart = errors.length;

        const id = (r.id ?? '').trim();
        const label = (r.label ?? '').trim();
        const typeRaw = (r.type ?? '').trim();

        if (!id) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'id',
            message: 'Required field "id" is empty',
          });
        } else if (seenIds.has(id)) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'id',
            message: `Duplicate node id '${id}' in file`,
          });
        } else {
          seenIds.add(id);
        }

        if (!label) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'label',
            message: 'Required field "label" is empty',
          });
        }

        if (!ALLOWED_NODE_TYPES.includes(typeRaw as NodeType)) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'type',
            message: `Invalid node type '${typeRaw}' (allowed: ${ALLOWED_NODE_TYPES.join(', ')})`,
          });
        }

        const tierVal = parseNum(r.tier ?? '', fileName, rowNum, 'tier', errors, {
          integer: true,
        });
        if (
          tierVal !== undefined &&
          !ALLOWED_TIERS.includes(tierVal as 1 | 2 | 3)
        ) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'tier',
            message: `Invalid tier '${tierVal}' (allowed: 1, 2, 3)`,
          });
        }

        const mfa = parseBool(r.mfa ?? '', fileName, rowNum, 'mfa', errors);
        const department = (r.department ?? '').trim() || undefined;

        const identitySubTypeRaw = (r.identitySubType ?? '').trim();
        if (
          identitySubTypeRaw &&
          !(ALLOWED_IDENTITY_SUBTYPES as readonly string[]).includes(
            identitySubTypeRaw
          )
        ) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'identitySubType',
            message: `Invalid identitySubType '${identitySubTypeRaw}' (allowed: ${ALLOWED_IDENTITY_SUBTYPES.join(', ')})`,
          });
        }

        const zoneRaw = (r.zone ?? '').trim();
        if (zoneRaw && !ALLOWED_ZONES.includes(zoneRaw as ZoneType)) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'zone',
            message: `Invalid zone '${zoneRaw}' (allowed: ${ALLOWED_ZONES.join(', ')})`,
          });
        }

        const criticality = parseNum(
          r.criticality ?? '',
          fileName,
          rowNum,
          'criticality',
          errors,
          { min: 1, max: 10 }
        );
        const pii_data = parseBool(
          r.pii_data ?? '',
          fileName,
          rowNum,
          'pii_data',
          errors
        );
        const pii_records = parseNum(
          r.pii_records ?? '',
          fileName,
          rowNum,
          'pii_records',
          errors,
          { min: 0, integer: true }
        );
        const compromised = parseBool(
          r.compromised ?? '',
          fileName,
          rowNum,
          'compromised',
          errors
        );

        const assetSubTypeRaw = (r.assetSubType ?? '').trim();
        if (
          assetSubTypeRaw &&
          !(ALLOWED_ASSET_SUBTYPES as readonly string[]).includes(
            assetSubTypeRaw
          )
        ) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'assetSubType',
            message: `Invalid assetSubType '${assetSubTypeRaw}' (allowed: ${ALLOWED_ASSET_SUBTYPES.join(', ')})`,
          });
        }

        const ip = (r.ip ?? '').trim() || undefined;
        const os = (r.os ?? '').trim() || undefined;
        const cve_id = (r.cve_id ?? '').trim() || undefined;
        const cvss = parseNum(r.cvss ?? '', fileName, rowNum, 'cvss', errors, {
          min: 0,
          max: 10,
        });
        const exploitable = parseBool(
          r.exploitable ?? '',
          fileName,
          rowNum,
          'exploitable',
          errors
        );
        const description = (r.description ?? '').trim() || undefined;

        if (errors.length === rowErrorsStart) {
          const node: GraphNode = {
            id,
            label,
            type: typeRaw as NodeType,
          };
          if (tierVal !== undefined) node.tier = tierVal as 1 | 2 | 3;
          if (mfa !== undefined) node.mfa = mfa;
          if (department !== undefined) node.department = department;
          if (identitySubTypeRaw) {
            node.identitySubType =
              identitySubTypeRaw as GraphNode['identitySubType'];
          }
          if (zoneRaw) node.zone = zoneRaw as ZoneType;
          if (criticality !== undefined) node.criticality = criticality;
          if (pii_data !== undefined) node.pii_data = pii_data;
          if (pii_records !== undefined) node.pii_records = pii_records;
          if (compromised !== undefined) node.compromised = compromised;
          if (assetSubTypeRaw) {
            node.assetSubType = assetSubTypeRaw as GraphNode['assetSubType'];
          }
          if (ip !== undefined) node.ip = ip;
          if (os !== undefined) node.os = os;
          if (cve_id !== undefined) node.cve_id = cve_id;
          if (cvss !== undefined) node.cvss = cvss;
          if (exploitable !== undefined) node.exploitable = exploitable;
          if (description !== undefined) node.description = description;

          nodes.push(node);
          uploadedNodeIds.add(id);
        }
      });
    } else if (kind === 'edges') {
      const allowedSet = new Set<string>(EDGE_COLUMNS);
      let headerErr = false;
      for (const reqCol of REQUIRED_EDGE_COLUMNS) {
        if (!headers.includes(reqCol)) {
          errors.push({
            file: fileName,
            row: 1,
            column: reqCol,
            message: `Missing required column '${reqCol}'`,
          });
          headerErr = true;
        }
      }
      for (const h of headers) {
        if (!allowedSet.has(h)) {
          errors.push({
            file: fileName,
            row: 1,
            column: h,
            message: `Unknown column '${h}' is not allowed in edges.csv`,
          });
          headerErr = true;
        }
      }
      if (headerErr) continue;

      const seenIds = new Set<string>();
      rows.forEach((r, idx) => {
        const rowNum = idx + 2;
        const rowErrorsStart = errors.length;

        const id = (r.id ?? '').trim();
        const source = (r.source ?? '').trim();
        const target = (r.target ?? '').trim();
        const relRaw = (r.relationship ?? '').trim();

        if (!id) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'id',
            message: 'Required field "id" is empty',
          });
        } else if (seenIds.has(id)) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'id',
            message: `Duplicate edge id '${id}' in file`,
          });
        } else {
          seenIds.add(id);
        }

        if (!source) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'source',
            message: 'Required field "source" is empty',
          });
        }

        if (!target) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'target',
            message: 'Required field "target" is empty',
          });
        }

        if (source && target && source === target) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'target',
            message: `Self-loop not allowed on edge '${id}' (${source} -> ${target})`,
          });
        }

        if (!ALLOWED_RELATIONSHIPS.includes(relRaw as EdgeRelationship)) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'relationship',
            message: `Invalid relationship '${relRaw}' (allowed: ${ALLOWED_RELATIONSHIPS.join(', ')})`,
          });
        }

        const port = parseNum(r.port ?? '', fileName, rowNum, 'port', errors, {
          min: 0,
          integer: true,
        });
        const last_used_days = parseNum(
          r.last_used_days ?? '',
          fileName,
          rowNum,
          'last_used_days',
          errors,
          { min: 0 }
        );
        const is_standing_privilege = parseBool(
          r.is_standing_privilege ?? '',
          fileName,
          rowNum,
          'is_standing_privilege',
          errors
        );
        const timestamp = (r.timestamp ?? '').trim() || undefined;
        const auth_type = (r.auth_type ?? '').trim() || undefined;
        const mitre_tactic = (r.mitre_tactic ?? '').trim() || undefined;
        const bytes = parseNum(
          r.bytes ?? '',
          fileName,
          rowNum,
          'bytes',
          errors,
          { min: 0 }
        );
        const process = (r.process ?? '').trim() || undefined;
        const is_attack_edge = parseBool(
          r.is_attack_edge ?? '',
          fileName,
          rowNum,
          'is_attack_edge',
          errors
        );
        const attack_step_order = parseNum(
          r.attack_step_order ?? '',
          fileName,
          rowNum,
          'attack_step_order',
          errors,
          { min: 0, integer: true }
        );

        if (errors.length === rowErrorsStart) {
          const edge: GraphEdge = {
            id,
            source,
            target,
            relationship: relRaw as EdgeRelationship,
          };
          if (port !== undefined) edge.port = port;
          if (last_used_days !== undefined) edge.last_used_days = last_used_days;
          if (is_standing_privilege !== undefined) {
            edge.is_standing_privilege = is_standing_privilege;
          }
          if (timestamp !== undefined) edge.timestamp = timestamp;
          if (auth_type !== undefined) edge.auth_type = auth_type;
          if (mitre_tactic !== undefined) edge.mitre_tactic = mitre_tactic;
          if (bytes !== undefined) edge.bytes = bytes;
          if (process !== undefined) edge.process = process;
          if (is_attack_edge !== undefined) edge.is_attack_edge = is_attack_edge;
          if (attack_step_order !== undefined) {
            edge.attack_step_order = attack_step_order;
          }

          pendingEdges.push({ edge, file: fileName, row: rowNum });
        }
      });
    } else if (kind === 'alerts') {
      const allowedSet = new Set<string>(ALERT_COLUMNS);
      let headerErr = false;
      for (const reqCol of REQUIRED_ALERT_COLUMNS) {
        if (!headers.includes(reqCol)) {
          errors.push({
            file: fileName,
            row: 1,
            column: reqCol,
            message: `Missing required column '${reqCol}'`,
          });
          headerErr = true;
        }
      }
      for (const h of headers) {
        if (!allowedSet.has(h)) {
          errors.push({
            file: fileName,
            row: 1,
            column: h,
            message: `Unknown column '${h}' is not allowed in alerts.csv`,
          });
          headerErr = true;
        }
      }
      if (headerErr) continue;

      const seenIds = new Set<string>();
      rows.forEach((r, idx) => {
        const rowNum = idx + 2;
        const rowErrorsStart = errors.length;

        const id = (r.id ?? '').trim();
        const timestamp = (r.timestamp ?? '').trim();
        const severityRaw = (r.severity ?? '').trim();
        const title = (r.title ?? '').trim();
        const sourceHost = (r.sourceHost ?? '').trim();
        const targetHost = (r.targetHost ?? '').trim();
        const mitreTactic = (r.mitreTactic ?? '').trim();
        const mitreId = (r.mitreId ?? '').trim();
        const rawLog = (r.rawLog ?? '').trim();

        if (!id) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'id',
            message: 'Required field "id" is empty',
          });
        } else if (seenIds.has(id)) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'id',
            message: `Duplicate alert id '${id}' in file`,
          });
        } else {
          seenIds.add(id);
        }

        if (!timestamp) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'timestamp',
            message: 'Required field "timestamp" is empty',
          });
        }
        if (
          !(ALLOWED_ALERT_SEVERITIES as readonly string[]).includes(severityRaw)
        ) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'severity',
            message: `Invalid severity '${severityRaw}' (allowed: ${ALLOWED_ALERT_SEVERITIES.join(', ')})`,
          });
        }
        if (!title) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'title',
            message: 'Required field "title" is empty',
          });
        }
        if (!sourceHost) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'sourceHost',
            message: 'Required field "sourceHost" is empty',
          });
        }
        if (!targetHost) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'targetHost',
            message: 'Required field "targetHost" is empty',
          });
        }
        if (!mitreTactic) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'mitreTactic',
            message: 'Required field "mitreTactic" is empty',
          });
        }
        if (!mitreId) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'mitreId',
            message: 'Required field "mitreId" is empty',
          });
        }
        if (!rawLog) {
          errors.push({
            file: fileName,
            row: rowNum,
            column: 'rawLog',
            message: 'Required field "rawLog" is empty',
          });
        }

        const isBreachNarrative = parseBool(
          r.isBreachNarrative ?? '',
          fileName,
          rowNum,
          'isBreachNarrative',
          errors
        );
        const narrativeStep = parseNum(
          r.narrativeStep ?? '',
          fileName,
          rowNum,
          'narrativeStep',
          errors,
          { min: 0, integer: true }
        );

        if (errors.length === rowErrorsStart) {
          const alert: RawSiemAlert = {
            id,
            timestamp,
            severity: severityRaw as RawSiemAlert['severity'],
            title,
            sourceHost,
            targetHost,
            mitreTactic,
            mitreId,
            rawLog,
          };
          if (isBreachNarrative !== undefined) {
            alert.isBreachNarrative = isBreachNarrative;
          }
          if (narrativeStep !== undefined) {
            alert.narrativeStep = narrativeStep;
          }
          alerts.push(alert);
        }
      });
    }
  }

  // Validate edge source and target endpoints against uploaded nodes + existing graph nodes
  const knownNodeIds = new Set<string>(uploadedNodeIds);
  if (mode === 'merge') {
    for (const id of existingNodeIds) {
      knownNodeIds.add(id);
    }
  }

  for (const item of pendingEdges) {
    let endpointMissing = false;
    if (!knownNodeIds.has(item.edge.source)) {
      errors.push({
        file: item.file,
        row: item.row,
        column: 'source',
        message: `Edge source node '${item.edge.source}' does not exist in uploaded nodes${mode === 'merge' ? ' or current graph' : ''}`,
      });
      endpointMissing = true;
    }
    if (!knownNodeIds.has(item.edge.target)) {
      errors.push({
        file: item.file,
        row: item.row,
        column: 'target',
        message: `Edge target node '${item.edge.target}' does not exist in uploaded nodes${mode === 'merge' ? ' or current graph' : ''}`,
      });
      endpointMissing = true;
    }
    if (!endpointMissing) {
      edges.push(item.edge);
    }
  }

  return { nodes, edges, alerts, errors, warnings, previews };
}
