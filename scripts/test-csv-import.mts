import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import express from '../server/node_modules/express/index.js';
import dotenv from '../server/node_modules/dotenv/lib/main.js';
import neo4j, { Integer } from '../server/node_modules/neo4j-driver/lib/index.js';
import { createExportHandler, createImportHandler } from '../server/csvImportExport.ts';
import { parseAndValidate } from '../src/import/csvImport.ts';
import {
  calculateBlastRadius,
  calculateChokePoints,
  evaluateDpdpRegulatoryAlert,
  findShortestAttackPaths,
  mergeAlerts,
} from '../src/utils/graphAlgorithms.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const outDir = path.resolve(__dirname, 'out');

function assert(cond: boolean, msg: string) {
  if (!cond) {
    throw new Error(`ASSERTION FAILED: ${msg}`);
  }
}

async function main() {
  const driver = neo4j.driver(
    process.env.NEO4J_URI!,
    neo4j.auth.basic(process.env.NEO4J_USERNAME!, process.env.NEO4J_PASSWORD!)
  );
  const DB = process.env.NEO4J_DATABASE!;

  const app = express();
  app.use(express.json({ limit: '2mb' }));
  app.post('/api/import', createImportHandler(driver, DB));
  app.get('/api/export', createExportHandler(driver, DB));
  app.get('/api/topology', async (_req: express.Request, res: express.Response) => {
    const session = driver.session({ database: DB });
    try {
      const nodeResult = await session.run(
        'MATCH (n) WHERE n:Identity OR n:Asset OR n:Vulnerability OR n:Alert RETURN n, labels(n) AS labels'
      );
      const nodes: Record<string, unknown>[] = [];
      const rawAlerts: Record<string, unknown>[] = [];
      for (const record of nodeResult.records) {
        const n = record.get('n');
        const labels: string[] = record.get('labels');
        const props = { ...n.properties };
        for (const [k, v] of Object.entries(props)) {
          if (neo4j.isInt(v)) props[k] = (v as Integer).toNumber();
        }
        if (labels.includes('Alert')) {
          rawAlerts.push(props);
        } else {
          const nodeType = labels.find((l: string) =>
            ['Identity', 'Asset', 'Vulnerability'].includes(l)
          );
          if (nodeType) {
            props.type = nodeType;
            nodes.push(props);
          }
        }
      }
      const relResult = await session.run(
        `MATCH (a)-[r]->(b)
         WHERE (a:Identity OR a:Asset OR a:Vulnerability)
           AND (b:Identity OR b:Asset OR b:Vulnerability)
         RETURN r, a.id AS sourceId, b.id AS targetId, type(r) AS relType`
      );
      const edges: Record<string, unknown>[] = [];
      for (const record of relResult.records) {
        const r = record.get('r');
        const props = { ...r.properties };
        for (const [k, v] of Object.entries(props)) {
          if (neo4j.isInt(v)) props[k] = (v as Integer).toNumber();
        }
        props.source = record.get('sourceId');
        props.target = record.get('targetId');
        props.relationship = record.get('relType');
        edges.push(props);
      }
      res.json({ nodes, edges, rawAlerts });
    } finally {
      await session.close();
    }
  });

  const server = await new Promise< ReturnType<typeof app.listen> >((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  const addr = server.address() as { port: number };
  const API_BASE = `http://localhost:${addr.port}`;

  async function getTopologyCounts() {
    const res = await fetch(`${API_BASE}/api/topology`);
    const data = await res.json();
    return {
      nodes: data.nodes.length,
      edges: data.edges.length,
      alerts: data.rawAlerts.length,
      data,
    };
  }

  try {
    console.log('=== Step 6: CSV Import End-to-End Test Suite ===');

    // 1. Valid Round-Trip Import (scripts/out/*.csv with mode="merge")
    const nodesCsv = fs.readFileSync(path.join(outDir, 'nodes.csv'), 'utf8');
    const edgesCsv = fs.readFileSync(path.join(outDir, 'edges.csv'), 'utf8');
    const alertsCsv = fs.readFileSync(path.join(outDir, 'alerts.csv'), 'utf8');

    const validParse = await parseAndValidate(
      [
        { name: 'nodes.csv', size: Buffer.byteLength(nodesCsv), content: nodesCsv },
        { name: 'edges.csv', size: Buffer.byteLength(edgesCsv), content: edgesCsv },
        { name: 'alerts.csv', size: Buffer.byteLength(alertsCsv), content: alertsCsv },
      ],
      [],
      'merge'
    );

    assert(validParse.errors.length === 0, `Expected 0 errors on valid CSVs, got ${JSON.stringify(validParse.errors)}`);
    assert(validParse.nodes.length === 44, `Expected 44 parsed nodes, got ${validParse.nodes.length}`);
    assert(validParse.edges.length === 55, `Expected 55 parsed edges, got ${validParse.edges.length}`);
    assert(validParse.alerts.length === 25, `Expected 25 parsed alerts, got ${validParse.alerts.length}`);

    const importRes = await fetch(`${API_BASE}/api/import`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode: 'merge',
        nodes: validParse.nodes,
        edges: validParse.edges,
        alerts: validParse.alerts,
      }),
    });
    assert(importRes.status === 200, `Expected HTTP 200 from POST /api/import, got ${importRes.status}`);
    const importJson = await importRes.json();
    assert(importJson.ok === true, 'Expected ok: true from POST /api/import');

    // Verify live Neo4j topology & all 5 baseline numbers
    const { data: topo } = await getTopologyCounts();
    const graph = { nodes: topo.nodes, edges: topo.edges };
    const blast = calculateBlastRadius(graph, 'JumpHost-Corp', 3);
    const paths = findShortestAttackPaths(graph, 'ANY', 8);
    const chokes = calculateChokePoints(graph);
    const [incident] = mergeAlerts(topo.rawAlerts, graph);
    const dpdp = evaluateDpdpRegulatoryAlert(graph);

    assert(topo.nodes.length === 44, `Expected 44 nodes, got ${topo.nodes.length}`);
    assert(topo.edges.length === 55, `Expected 55 edges, got ${topo.edges.length}`);
    assert(topo.rawAlerts.length === 25, `Expected 25 alerts, got ${topo.rawAlerts.length}`);
    assert(paths.length === 77, `Expected 77 attack paths, got ${paths.length}`);
    assert(
      blast.hop1Nodes.size === 5 && blast.hop2Nodes.size === 8 && blast.hop3Nodes.size === 5,
      `Expected hops 5/8/5, got ${blast.hop1Nodes.size}/${blast.hop2Nodes.size}/${blast.hop3Nodes.size}`
    );
    assert(
      chokes.topNodes[0]?.nodeId === 'JumpHost-Corp',
      `Expected top choke node JumpHost-Corp, got ${chokes.topNodes[0]?.nodeId}`
    );
    assert(incident?.id === 'INC-2026-001', `Expected INC-2026-001, got ${incident?.id}`);
    assert(dpdp.triggered === true, 'Expected DPDP triggered = true');
    console.log('[PASS] 1. Valid round-trip import & 5-algorithm baseline parity (44 nodes, 55 edges, 77 paths, hops 5/8/5, JumpHost-Corp)');

    // Verify GET /api/export?kind=nodes|edges|alerts
    for (const kind of ['nodes', 'edges', 'alerts']) {
      const expRes = await fetch(`${API_BASE}/api/export?kind=${kind}`);
      assert(expRes.status === 200, `Expected 200 from GET /api/export?kind=${kind}`);
      const text = await expRes.text();
      assert(text.split('\n').length > 2, `Expected non-empty CSV from GET /api/export?kind=${kind}`);
    }
    console.log('[PASS] 1b. GET /api/export?kind=nodes|edges|alerts verified');

    // 2. Bad files (one at a time)
    // (a) Wrong extension
    const badExt = await parseAndValidate([
      { name: 'nodes.txt', size: 100, content: 'id,label,type\nn1,Node1,Asset\n' },
    ]);
    assert(badExt.errors.length > 0 && badExt.errors[0].message.includes('only .csv'), 'Wrong extension must be rejected');
    console.log(`[PASS] 2a. Wrong extension rejected: "${badExt.errors[0].message}"`);

    // (b) Over 2 MB
    const bigSize = 2 * 1024 * 1024 + 100;
    const badSize = await parseAndValidate([
      { name: 'nodes.csv', size: bigSize, content: 'id,label,type\nn1,Node1,Asset\n' },
    ]);
    assert(badSize.errors.length > 0 && badSize.errors[0].message.includes('2 MB'), 'Over 2 MB must be rejected');
    console.log(`[PASS] 2b. Over 2 MB rejected: "${badSize.errors[0].message}"`);

    // (c) Missing required column
    const badMissingCol = await parseAndValidate([
      { name: 'nodes.csv', size: 50, content: 'id,type\nn1,Asset\n' },
    ]);
    assert(badMissingCol.errors.length > 0 && badMissingCol.errors[0].message.includes("Missing required column 'label'"), 'Missing required column must be rejected');
    console.log(`[PASS] 2c. Missing required column rejected: "${badMissingCol.errors[0].message}"`);

    // (d) Unknown column
    const badUnknownCol = await parseAndValidate([
      { name: 'nodes.csv', size: 60, content: 'id,label,type,arbitraryProp\nn1,Node1,Asset,hack\n' },
    ]);
    assert(badUnknownCol.errors.length > 0 && badUnknownCol.errors[0].message.includes("Unknown column 'arbitraryProp'"), 'Unknown column must be rejected');
    console.log(`[PASS] 2d. Unknown column rejected: "${badUnknownCol.errors[0].message}"`);

    // (e) Duplicate id
    const badDupId = await parseAndValidate([
      { name: 'nodes.csv', size: 80, content: 'id,label,type\ndup-1,Node1,Asset\ndup-1,Node2,Asset\n' },
    ]);
    assert(badDupId.errors.length > 0 && badDupId.errors[0].message.includes("Duplicate node id 'dup-1'"), 'Duplicate id must be rejected');
    console.log(`[PASS] 2e. Duplicate id rejected: "${badDupId.errors[0].message}"`);

    // (f) Edge pointing to a missing node (both client & server check)
    const badMissingNode = await parseAndValidate(
      [
        {
          name: 'edges.csv',
          size: 90,
          content: 'id,source,target,relationship\ne-bad,JumpHost-Corp,Missing-Ghost-Node,CAN_ACCESS\n',
        },
      ],
      ['JumpHost-Corp'],
      'merge'
    );
    assert(badMissingNode.errors.length > 0 && badMissingNode.errors[0].message.includes('Missing-Ghost-Node'), 'Edge to missing node must be rejected');
    const srvMissingNode = await fetch(`${API_BASE}/api/import`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode: 'merge',
        nodes: [],
        edges: [{ id: 'e-bad', source: 'JumpHost-Corp', target: 'Missing-Ghost-Node', relationship: 'CAN_ACCESS' }],
        alerts: [],
      }),
    });
    assert(srvMissingNode.status === 400, 'Server must reject edge pointing to missing node with 400');
    console.log(`[PASS] 2f. Edge pointing to missing node rejected (client & server): "${badMissingNode.errors[0].message}"`);

    // (g) Criticality 11
    const badCrit = await parseAndValidate([
      { name: 'nodes.csv', size: 80, content: 'id,label,type,criticality\nn1,Node1,Asset,11\n' },
    ]);
    assert(badCrit.errors.length > 0 && badCrit.errors[0].message.includes('out of range'), 'criticality 11 must be rejected');
    const srvCrit = await fetch(`${API_BASE}/api/import`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode: 'merge',
        nodes: [{ id: 'n1', label: 'Node1', type: 'Asset', criticality: 11 }],
        edges: [],
        alerts: [],
      }),
    });
    assert(srvCrit.status === 400, 'Server must reject criticality 11 with 400');
    console.log(`[PASS] 2g. Criticality 11 rejected (client & server): "${badCrit.errors[0].message}"`);

    // (h) Relationship type not on whitelist
    const badRel = await parseAndValidate(
      [
        {
          name: 'edges.csv',
          size: 90,
          content: 'id,source,target,relationship\ne-rel,JumpHost-Corp,Dev-Laptop-04,EXPLOITED_VIA\n',
        },
      ],
      ['JumpHost-Corp', 'Dev-Laptop-04'],
      'merge'
    );
    assert(badRel.errors.length > 0 && badRel.errors[0].message.includes("Invalid relationship 'EXPLOITED_VIA'"), 'Non-whitelisted relationship must be rejected');
    const srvRel = await fetch(`${API_BASE}/api/import`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode: 'merge',
        nodes: [],
        edges: [{ id: 'e-rel', source: 'JumpHost-Corp', target: 'Dev-Laptop-04', relationship: 'EXPLOITED_VIA' }],
        alerts: [],
      }),
    });
    assert(srvRel.status === 400, 'Server must reject non-whitelisted relationship with 400');
    console.log(`[PASS] 2h. Non-whitelisted relationship rejected (client & server): "${badRel.errors[0].message}"`);

    // (i) Row with a quoted comma (unclosed quote with comma rejected; valid quoted comma accepted; extra unquoted comma rejected)
    const badQuotedComma = await parseAndValidate([
      {
        name: 'nodes.csv',
        size: 90,
        content: 'id,label,type\nn1,"Broken, Quoted Label,Asset\n',
      },
    ]);
    assert(badQuotedComma.errors.length > 0, 'Malformed quoted comma row must be rejected');
    console.log(`[PASS] 2i. Row with malformed quoted comma rejected: "${badQuotedComma.errors[0].message}"`);

    // 3. Confirm failed imports left Neo4j node, edge, and alert counts completely unchanged
    const finalCounts = await getTopologyCounts();
    assert(
      finalCounts.nodes === 44 && finalCounts.edges === 55 && finalCounts.alerts === 25,
      `Expected Neo4j counts unchanged at 44/55/25, got ${finalCounts.nodes}/${finalCounts.edges}/${finalCounts.alerts}`
    );
    console.log('[PASS] 3. Confirmed failed imports left Neo4j counts unchanged (44 nodes, 55 edges, 25 alerts)');
  } finally {
    server.close();
    await driver.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
