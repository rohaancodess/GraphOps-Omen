import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import neo4j, { Driver, Integer } from 'neo4j-driver';
import { seedGraph, resetGraph } from './seed.js';
import { createExportHandler, createImportHandler } from './csvImportExport.js';

// Load .env from project root reliably
const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const app = express();
const PORT = 3001;

const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';

app.use(cors({ origin: FRONTEND_ORIGIN }));
app.use(express.json({ limit: '2mb' }));

// ── Shared Neo4j driver ──
let driver: Driver;
try {
  driver = neo4j.driver(
    process.env.NEO4J_URI!,
    neo4j.auth.basic(process.env.NEO4J_USERNAME!, process.env.NEO4J_PASSWORD!)
  );
} catch (err) {
  console.error('Failed to create Neo4j driver');
  process.exit(1);
}

const DB = process.env.NEO4J_DATABASE!;

// Helper: run a read query
export async function readQuery(cypher: string, params: Record<string, unknown> = {}) {
  const session = driver.session({ database: DB });
  try {
    const result = await session.run(cypher, params);
    return result;
  } finally {
    await session.close();
  }
}

// Helper: run a write query
export async function writeQuery(cypher: string, params: Record<string, unknown> = {}) {
  const session = driver.session({ database: DB });
  try {
    const result = await session.run(cypher, params);
    return result;
  } finally {
    await session.close();
  }
}

// ── GET /api/health ──
app.get('/api/health', async (_req, res) => {
  try {
    await readQuery('RETURN 1');
    res.json({ ok: true });
  } catch {
    res.status(500).json({ ok: false, error: 'Neo4j connection failed' });
  }
});

// ── POST /api/seed ──
app.post('/api/seed', async (_req, res) => {
  try {
    const counts = await seedGraph(driver, DB);
    res.json({ ok: true, ...counts });
  } catch {
    res.status(500).json({ ok: false, error: 'Seed failed' });
  }
});

// ── POST /api/reset ──
app.post('/api/reset', async (_req, res) => {
  try {
    await resetGraph(driver, DB);
    res.json({ ok: true, message: 'All nodes and relationships deleted' });
  } catch {
    res.status(500).json({ ok: false, error: 'Reset failed' });
  }
});

// ── GET /api/topology ──
app.get('/api/topology', async (_req, res) => {
  try {
    const session = driver.session({ database: DB });
    try {
      // Fetch all nodes
      const nodeResult = await session.run(
        'MATCH (n) WHERE n:Identity OR n:Asset OR n:Vulnerability OR n:Alert RETURN n, labels(n) AS labels'
      );

      const nodes: Record<string, unknown>[] = [];
      const rawAlerts: Record<string, unknown>[] = [];

      for (const record of nodeResult.records) {
        const n = record.get('n');
        const labels: string[] = record.get('labels');
        const props = { ...n.properties };

        // Convert neo4j integers to JS numbers
        for (const [k, v] of Object.entries(props)) {
          if (neo4j.isInt(v)) {
            props[k] = (v as Integer).toNumber();
          }
        }

        if (labels.includes('Alert')) {
          rawAlerts.push(props);
        } else {
          // Determine type from label
          const nodeType = labels.find((l: string) => ['Identity', 'Asset', 'Vulnerability'].includes(l));
          if (nodeType) {
            props.type = nodeType;
            nodes.push(props);
          }
        }
      }

      // Fetch all relationships
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
          if (neo4j.isInt(v)) {
            props[k] = (v as Integer).toNumber();
          }
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
  } catch {
    res.status(500).json({ error: 'Topology fetch failed' });
  }
});

// ── POST /api/edges/:id/sever ──
app.post('/api/edges/:id/sever', async (req, res) => {
  const edgeId = req.params.id;
  if (!edgeId || typeof edgeId !== 'string') {
    return res.status(400).json({ error: 'Invalid edge id' });
  }
  try {
    const result = await writeQuery(
      'MATCH ()-[r {id: $edgeId}]->() DELETE r RETURN count(r) AS deleted',
      { edgeId }
    );
    const deleted = result.records[0]?.get('deleted');
    const count = neo4j.isInt(deleted) ? (deleted as Integer).toNumber() : deleted;
    if (count === 0) {
      return res.status(404).json({ error: 'Edge not found' });
    }
    res.json({ ok: true, deleted: count });
  } catch {
    res.status(500).json({ ok: false, error: 'Sever failed' });
  }
});

// ── POST /api/nodes/:id/contain ──
app.post('/api/nodes/:id/contain', async (req, res) => {
  const nodeId = req.params.id;
  if (!nodeId || typeof nodeId !== 'string') {
    return res.status(400).json({ error: 'Invalid node id' });
  }
  try {
    // Remove all outgoing edges from node and set compromised = false
    const result = await writeQuery(
      `MATCH (n {id: $nodeId})-[r]->()
       DELETE r
       WITH count(r) AS deleted
       MATCH (n2 {id: $nodeId})
       SET n2.compromised = false
       RETURN deleted`,
      { nodeId }
    );
    const deleted = result.records[0]?.get('deleted');
    const count = neo4j.isInt(deleted) ? (deleted as Integer).toNumber() : deleted;
    res.json({ ok: true, deletedEdges: count });
  } catch {
    res.status(500).json({ ok: false, error: 'Contain failed' });
  }
});

// ── POST /api/revoke-dormant ──
app.post('/api/revoke-dormant', async (_req, res) => {
  try {
    const result = await writeQuery(
      `MATCH ()-[r]->()
       WHERE r.last_used_days > 90
       DELETE r
       RETURN count(r) AS deleted`
    );
    const deleted = result.records[0]?.get('deleted');
    const count = neo4j.isInt(deleted) ? (deleted as Integer).toNumber() : deleted;
    res.json({ ok: true, deleted: count });
  } catch {
    res.status(500).json({ ok: false, error: 'Revoke dormant failed' });
  }
});

// ── POST /api/import & GET /api/export ──
app.post('/api/import', createImportHandler(driver, DB));
app.get('/api/export', createExportHandler(driver, DB));

app.listen(PORT, () => {
  console.log(`GraphOps server listening on http://localhost:${PORT}`);
});
