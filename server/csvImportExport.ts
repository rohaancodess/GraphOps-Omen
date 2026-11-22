import { Request, Response } from 'express';
import neo4j, { Driver, Integer } from 'neo4j-driver';

const MAX_ROWS = 5000;

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

const ALLOWED_NODE_TYPES = ['Identity', 'Asset', 'Vulnerability'] as const;
const ALLOWED_ZONES = ['DMZ', 'Corp', 'Prod'] as const;
const ALLOWED_IDENTITY_SUBTYPES = ['User', 'ServiceAccount', 'Contractor'] as const;
const ALLOWED_ASSET_SUBTYPES = [
  'Endpoint',
  'Server',
  'Database',
  'Cluster',
  'Directory',
] as const;
const ALLOWED_TIERS = [1, 2, 3] as const;
const ALLOWED_RELATIONSHIPS = [
  'CAN_ACCESS',
  'AUTHENTICATED_TO',
  'CONNECTED_TO',
  'HAS_VULN',
] as const;
const ALLOWED_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;

interface ServerValidationIssue {
  file: string;
  row: number;
  column: string;
  message: string;
}

function escapeCsvCell(val: unknown): string {
  if (val === undefined || val === null) return '';
  const str = String(val);
  if (
    str.includes(',') ||
    str.includes('"') ||
    str.includes('\n') ||
    str.includes('\r')
  ) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function toCsv(
  rows: Record<string, unknown>[],
  columns: readonly string[]
): string {
  const header = columns.join(',');
  const lines = rows.map((row) =>
    columns.map((col) => escapeCsvCell(row[col])).join(',')
  );
  return [header, ...lines].join('\n') + '\n';
}

export function createImportHandler(driver: Driver, database: string) {
  return async (req: Request, res: Response) => {
    const body = req.body;
    if (!body || typeof body !== 'object') {
      return res.status(400).json({
        ok: false,
        error: 'Invalid request body',
        rejected: 1,
      });
    }

    const mode = body.mode;
    if (mode !== 'merge' && mode !== 'replace') {
      return res.status(400).json({
        ok: false,
        error: 'mode must be "merge" or "replace"',
        rejected: 1,
      });
    }

    if (
      mode === 'replace' &&
      body.confirmReplace !== 'REPLACE' &&
      body.confirm !== 'REPLACE'
    ) {
      return res.status(400).json({
        ok: false,
        error: 'Replace mode requires confirmation string "REPLACE"',
        rejected: 1,
      });
    }

    const rawNodes: unknown[] = Array.isArray(body.nodes) ? body.nodes : [];
    const rawEdges: unknown[] = Array.isArray(body.edges) ? body.edges : [];
    const rawAlerts: unknown[] = Array.isArray(body.alerts) ? body.alerts : [];

    if (
      rawNodes.length === 0 &&
      rawEdges.length === 0 &&
      rawAlerts.length === 0
    ) {
      return res.status(400).json({
        ok: false,
        error: 'Import payload contains no nodes, edges, or alerts',
        rejected: 1,
      });
    }

    const errors: ServerValidationIssue[] = [];

    if (rawNodes.length > MAX_ROWS) {
      errors.push({
        file: 'nodes.csv',
        row: MAX_ROWS + 1,
        column: '',
        message: `nodes exceeds maximum of ${MAX_ROWS} rows`,
      });
    }
    if (rawEdges.length > MAX_ROWS) {
      errors.push({
        file: 'edges.csv',
        row: MAX_ROWS + 1,
        column: '',
        message: `edges exceeds maximum of ${MAX_ROWS} rows`,
      });
    }
    if (rawAlerts.length > MAX_ROWS) {
      errors.push({
        file: 'alerts.csv',
        row: MAX_ROWS + 1,
        column: '',
        message: `alerts exceeds maximum of ${MAX_ROWS} rows`,
      });
    }

    const allowedNodeKeys = new Set<string>(NODE_COLUMNS);
    const allowedEdgeKeys = new Set<string>(EDGE_COLUMNS);
    const allowedAlertKeys = new Set<string>(ALERT_COLUMNS);

    const validNodes: Record<string, unknown>[] = [];
    const validEdges: Record<string, unknown>[] = [];
    const validAlerts: Record<string, unknown>[] = [];

    const seenNodeIds = new Set<string>();
    rawNodes.forEach((item, idx) => {
      const rowNum = idx + 2;
      if (!item || typeof item !== 'object') {
        errors.push({
          file: 'nodes.csv',
          row: rowNum,
          column: '',
          message: 'Invalid node object',
        });
        return;
      }
      const n = item as Record<string, unknown>;
      for (const k of Object.keys(n)) {
        if (!allowedNodeKeys.has(k)) {
          errors.push({
            file: 'nodes.csv',
            row: rowNum,
            column: k,
            message: `Unknown node property '${k}'`,
          });
        }
      }

      const id = typeof n.id === 'string' ? n.id.trim() : '';
      const label = typeof n.label === 'string' ? n.label.trim() : '';
      const type = typeof n.type === 'string' ? n.type.trim() : '';

      if (!id) {
        errors.push({
          file: 'nodes.csv',
          row: rowNum,
          column: 'id',
          message: 'Missing required node id',
        });
      } else if (seenNodeIds.has(id)) {
        errors.push({
          file: 'nodes.csv',
          row: rowNum,
          column: 'id',
          message: `Duplicate node id '${id}'`,
        });
      } else {
        seenNodeIds.add(id);
      }

      if (!label) {
        errors.push({
          file: 'nodes.csv',
          row: rowNum,
          column: 'label',
          message: 'Missing required node label',
        });
      }

      if (!(ALLOWED_NODE_TYPES as readonly string[]).includes(type)) {
        errors.push({
          file: 'nodes.csv',
          row: rowNum,
          column: 'type',
          message: `Invalid node type '${type}'`,
        });
      }

      if (
        n.tier !== undefined &&
        !(ALLOWED_TIERS as readonly number[]).includes(Number(n.tier))
      ) {
        errors.push({
          file: 'nodes.csv',
          row: rowNum,
          column: 'tier',
          message: `Invalid tier '${n.tier}'`,
        });
      }

      if (
        n.zone !== undefined &&
        !(ALLOWED_ZONES as readonly string[]).includes(String(n.zone))
      ) {
        errors.push({
          file: 'nodes.csv',
          row: rowNum,
          column: 'zone',
          message: `Invalid zone '${n.zone}'`,
        });
      }

      if (
        n.identitySubType !== undefined &&
        !(ALLOWED_IDENTITY_SUBTYPES as readonly string[]).includes(
          String(n.identitySubType)
        )
      ) {
        errors.push({
          file: 'nodes.csv',
          row: rowNum,
          column: 'identitySubType',
          message: `Invalid identitySubType '${n.identitySubType}'`,
        });
      }

      if (
        n.assetSubType !== undefined &&
        !(ALLOWED_ASSET_SUBTYPES as readonly string[]).includes(
          String(n.assetSubType)
        )
      ) {
        errors.push({
          file: 'nodes.csv',
          row: rowNum,
          column: 'assetSubType',
          message: `Invalid assetSubType '${n.assetSubType}'`,
        });
      }

      if (n.criticality !== undefined) {
        const c = Number(n.criticality);
        if (!Number.isFinite(c) || c < 1 || c > 10) {
          errors.push({
            file: 'nodes.csv',
            row: rowNum,
            column: 'criticality',
            message: `criticality must be between 1 and 10`,
          });
        }
      }

      if (n.cvss !== undefined) {
        const cv = Number(n.cvss);
        if (!Number.isFinite(cv) || cv < 0 || cv > 10) {
          errors.push({
            file: 'nodes.csv',
            row: rowNum,
            column: 'cvss',
            message: `cvss must be between 0 and 10`,
          });
        }
      }

      if (n.pii_records !== undefined) {
        const pr = Number(n.pii_records);
        if (!Number.isFinite(pr) || pr < 0) {
          errors.push({
            file: 'nodes.csv',
            row: rowNum,
            column: 'pii_records',
            message: `pii_records must be >= 0`,
          });
        }
      }

      const cleanNode: Record<string, unknown> = {};
      for (const col of NODE_COLUMNS) {
        if (n[col] !== undefined && n[col] !== null && n[col] !== '') {
          cleanNode[col] = n[col];
        }
      }
      validNodes.push(cleanNode);
    });

    const seenEdgeIds = new Set<string>();
    rawEdges.forEach((item, idx) => {
      const rowNum = idx + 2;
      if (!item || typeof item !== 'object') {
        errors.push({
          file: 'edges.csv',
          row: rowNum,
          column: '',
          message: 'Invalid edge object',
        });
        return;
      }
      const e = item as Record<string, unknown>;
      for (const k of Object.keys(e)) {
        if (!allowedEdgeKeys.has(k)) {
          errors.push({
            file: 'edges.csv',
            row: rowNum,
            column: k,
            message: `Unknown edge property '${k}'`,
          });
        }
      }

      const id = typeof e.id === 'string' ? e.id.trim() : '';
      const source = typeof e.source === 'string' ? e.source.trim() : '';
      const target = typeof e.target === 'string' ? e.target.trim() : '';
      const rel = typeof e.relationship === 'string' ? e.relationship.trim() : '';

      if (!id) {
        errors.push({
          file: 'edges.csv',
          row: rowNum,
          column: 'id',
          message: 'Missing required edge id',
        });
      } else if (seenEdgeIds.has(id)) {
        errors.push({
          file: 'edges.csv',
          row: rowNum,
          column: 'id',
          message: `Duplicate edge id '${id}'`,
        });
      } else {
        seenEdgeIds.add(id);
      }

      if (!source) {
        errors.push({
          file: 'edges.csv',
          row: rowNum,
          column: 'source',
          message: 'Missing required edge source',
        });
      }
      if (!target) {
        errors.push({
          file: 'edges.csv',
          row: rowNum,
          column: 'target',
          message: 'Missing required edge target',
        });
      }
      if (source && target && source === target) {
        errors.push({
          file: 'edges.csv',
          row: rowNum,
          column: 'target',
          message: `Self-loop not allowed on edge '${id}'`,
        });
      }

      if (!(ALLOWED_RELATIONSHIPS as readonly string[]).includes(rel)) {
        errors.push({
          file: 'edges.csv',
          row: rowNum,
          column: 'relationship',
          message: `Invalid relationship '${rel}'`,
        });
      }

      if (e.last_used_days !== undefined) {
        const lud = Number(e.last_used_days);
        if (!Number.isFinite(lud) || lud < 0) {
          errors.push({
            file: 'edges.csv',
            row: rowNum,
            column: 'last_used_days',
            message: 'last_used_days must be >= 0',
          });
        }
      }

      const cleanEdge: Record<string, unknown> = {};
      for (const col of EDGE_COLUMNS) {
        if (e[col] !== undefined && e[col] !== null && e[col] !== '') {
          cleanEdge[col] = e[col];
        }
      }
      validEdges.push(cleanEdge);
    });

    const seenAlertIds = new Set<string>();
    rawAlerts.forEach((item, idx) => {
      const rowNum = idx + 2;
      if (!item || typeof item !== 'object') {
        errors.push({
          file: 'alerts.csv',
          row: rowNum,
          column: '',
          message: 'Invalid alert object',
        });
        return;
      }
      const a = item as Record<string, unknown>;
      for (const k of Object.keys(a)) {
        if (!allowedAlertKeys.has(k)) {
          errors.push({
            file: 'alerts.csv',
            row: rowNum,
            column: k,
            message: `Unknown alert property '${k}'`,
          });
        }
      }

      const id = typeof a.id === 'string' ? a.id.trim() : '';
      const sev = typeof a.severity === 'string' ? a.severity.trim() : '';
      if (!id) {
        errors.push({
          file: 'alerts.csv',
          row: rowNum,
          column: 'id',
          message: 'Missing required alert id',
        });
      } else if (seenAlertIds.has(id)) {
        errors.push({
          file: 'alerts.csv',
          row: rowNum,
          column: 'id',
          message: `Duplicate alert id '${id}'`,
        });
      } else {
        seenAlertIds.add(id);
      }

      if (!(ALLOWED_SEVERITIES as readonly string[]).includes(sev)) {
        errors.push({
          file: 'alerts.csv',
          row: rowNum,
          column: 'severity',
          message: `Invalid alert severity '${sev}'`,
        });
      }

      const cleanAlert: Record<string, unknown> = {};
      for (const col of ALERT_COLUMNS) {
        if (a[col] !== undefined && a[col] !== null && a[col] !== '') {
          cleanAlert[col] = a[col];
        }
      }
      validAlerts.push(cleanAlert);
    });

    if (errors.length > 0) {
      return res.status(400).json({
        ok: false,
        errors,
        rejected: errors.length,
      });
    }

    const session = driver.session({ database });
    try {
      const counts = await session.executeWrite(async (tx) => {
        const existingNodeIds = new Set<string>();
        const existingEdgeIds = new Set<string>();
        const existingAlertIds = new Set<string>();

        if (mode === 'merge') {
          const nRes = await tx.run(
            'MATCH (n) WHERE n:Identity OR n:Asset OR n:Vulnerability RETURN n.id AS id'
          );
          for (const rec of nRes.records) {
            const id = rec.get('id');
            if (typeof id === 'string') existingNodeIds.add(id);
          }

          const eRes = await tx.run(
            'MATCH (:Identity|Asset|Vulnerability)-[r]->(:Identity|Asset|Vulnerability) RETURN r.id AS id'
          );
          for (const rec of eRes.records) {
            const id = rec.get('id');
            if (typeof id === 'string') existingEdgeIds.add(id);
          }

          const aRes = await tx.run('MATCH (a:Alert) RETURN a.id AS id');
          for (const rec of aRes.records) {
            const id = rec.get('id');
            if (typeof id === 'string') existingAlertIds.add(id);
          }
        }

        // Verify all edge endpoints exist in known nodes (uploaded + existing if merge)
        const knownNodes = new Set<string>(seenNodeIds);
        if (mode === 'merge') {
          for (const id of existingNodeIds) knownNodes.add(id);
        }

        const endpointErrors: ServerValidationIssue[] = [];
        validEdges.forEach((e, idx) => {
          const src = String(e.source);
          const tgt = String(e.target);
          if (!knownNodes.has(src)) {
            endpointErrors.push({
              file: 'edges.csv',
              row: idx + 2,
              column: 'source',
              message: `Edge source node '${src}' does not exist`,
            });
          }
          if (!knownNodes.has(tgt)) {
            endpointErrors.push({
              file: 'edges.csv',
              row: idx + 2,
              column: 'target',
              message: `Edge target node '${tgt}' does not exist`,
            });
          }
        });

        if (endpointErrors.length > 0) {
          const err = new Error('ENDPOINT_VALIDATION_FAILED') as Error & {
            validationErrors?: ServerValidationIssue[];
          };
          err.validationErrors = endpointErrors;
          throw err;
        }

        if (mode === 'replace') {
          await tx.run('MATCH (n) DETACH DELETE n');
        }

        let nodesAdded = 0;
        let nodesUpdated = 0;
        for (const n of validNodes) {
          const id = String(n.id);
          if (mode === 'merge' && existingNodeIds.has(id)) {
            nodesUpdated++;
          } else {
            nodesAdded++;
          }
        }

        let edgesAdded = 0;
        let edgesUpdated = 0;
        for (const e of validEdges) {
          const id = String(e.id);
          if (mode === 'merge' && existingEdgeIds.has(id)) {
            edgesUpdated++;
          } else {
            edgesAdded++;
          }
        }

        let alertsAdded = 0;
        for (const a of validAlerts) {
          const id = String(a.id);
          if (!(mode === 'merge' && existingAlertIds.has(id))) {
            alertsAdded++;
          }
        }

        // One parameterized UNWIND query per node label whitelist
        for (const label of ALLOWED_NODE_TYPES) {
          const group = validNodes
            .filter((n) => n.type === label)
            .map((n) => {
              const { type, ...rest } = n;
              return rest;
            });
          if (group.length === 0) continue;

          await tx.run(
            `UNWIND $items AS item
             MERGE (n:${label} {id: item.id})
             SET n += item`,
            { items: group }
          );
        }

        // Alerts UNWIND query
        if (validAlerts.length > 0) {
          await tx.run(
            `UNWIND $items AS item
             MERGE (n:Alert {id: item.id})
             SET n += item`,
            { items: validAlerts }
          );
        }

        // One parameterized UNWIND query per relationship type whitelist
        for (const relType of ALLOWED_RELATIONSHIPS) {
          const group = validEdges
            .filter((e) => e.relationship === relType)
            .map((e) => {
              const { source, target, relationship, ...props } = e;
              return { source, target, props };
            });
          if (group.length === 0) continue;

          await tx.run(
            `UNWIND $items AS item
             MATCH (a {id: item.source})
             MATCH (b {id: item.target})
             MERGE (a)-[r:${relType} {id: item.props.id}]->(b)
             SET r += item.props`,
            { items: group }
          );
        }

        return {
          nodesAdded,
          nodesUpdated,
          edgesAdded,
          edgesUpdated,
          alertsAdded,
          rejected: 0,
        };
      });

      return res.json({ ok: true, ...counts });
    } catch (err: unknown) {
      const vErr = err as Error & {
        validationErrors?: ServerValidationIssue[];
      };
      if (vErr.validationErrors) {
        return res.status(400).json({
          ok: false,
          errors: vErr.validationErrors,
          rejected: vErr.validationErrors.length,
        });
      }
      return res.status(500).json({
        ok: false,
        error: 'CSV import failed',
      });
    } finally {
      await session.close();
    }
  };
}

export function createExportHandler(driver: Driver, database: string) {
  return async (req: Request, res: Response) => {
    const kind = req.query.kind;
    if (kind !== 'nodes' && kind !== 'edges' && kind !== 'alerts') {
      return res.status(400).json({
        error: 'Query parameter "kind" must be "nodes", "edges", or "alerts"',
      });
    }

    const session = driver.session({ database });
    try {
      if (kind === 'nodes') {
        const result = await session.run(
          'MATCH (n) WHERE n:Identity OR n:Asset OR n:Vulnerability RETURN n, labels(n) AS labels'
        );
        const rows: Record<string, unknown>[] = [];
        for (const record of result.records) {
          const n = record.get('n');
          const labels: string[] = record.get('labels');
          const props: Record<string, unknown> = { ...n.properties };
          for (const [k, v] of Object.entries(props)) {
            if (neo4j.isInt(v)) {
              props[k] = (v as Integer).toNumber();
            }
          }
          const nodeType = labels.find((l) =>
            (ALLOWED_NODE_TYPES as readonly string[]).includes(l)
          );
          if (nodeType) {
            props.type = nodeType;
            rows.push(props);
          }
        }
        const csv = toCsv(rows, NODE_COLUMNS);
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="nodes.csv"');
        return res.send(csv);
      }

      if (kind === 'edges') {
        const result = await session.run(
          `MATCH (a)-[r]->(b)
           WHERE (a:Identity OR a:Asset OR a:Vulnerability)
             AND (b:Identity OR b:Asset OR b:Vulnerability)
           RETURN r, a.id AS sourceId, b.id AS targetId, type(r) AS relType`
        );
        const rows: Record<string, unknown>[] = [];
        for (const record of result.records) {
          const r = record.get('r');
          const props: Record<string, unknown> = { ...r.properties };
          for (const [k, v] of Object.entries(props)) {
            if (neo4j.isInt(v)) {
              props[k] = (v as Integer).toNumber();
            }
          }
          props.source = record.get('sourceId');
          props.target = record.get('targetId');
          props.relationship = record.get('relType');
          rows.push(props);
        }
        const csv = toCsv(rows, EDGE_COLUMNS);
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="edges.csv"');
        return res.send(csv);
      }

      // kind === 'alerts'
      const result = await session.run('MATCH (n:Alert) RETURN n');
      const rows: Record<string, unknown>[] = [];
      for (const record of result.records) {
        const n = record.get('n');
        const props: Record<string, unknown> = { ...n.properties };
        for (const [k, v] of Object.entries(props)) {
          if (neo4j.isInt(v)) {
            props[k] = (v as Integer).toNumber();
          }
        }
        rows.push(props);
      }
      const csv = toCsv(rows, ALERT_COLUMNS);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="alerts.csv"');
      return res.send(csv);
    } catch {
      return res.status(500).json({ error: 'CSV export failed' });
    } finally {
      await session.close();
    }
  };
}
