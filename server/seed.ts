import { Driver } from 'neo4j-driver';
import { INITIAL_TOPOLOGY } from '../src/data/mockTopology.js';

export async function seedGraph(driver: Driver, database: string) {
  const session = driver.session({ database });
  try {
    const { nodes, edges, rawAlerts } = INITIAL_TOPOLOGY;

    // ── Uniqueness constraints (one per label) ──
    await session.run('CREATE CONSTRAINT IF NOT EXISTS FOR (n:Identity) REQUIRE n.id IS UNIQUE');
    await session.run('CREATE CONSTRAINT IF NOT EXISTS FOR (n:Asset) REQUIRE n.id IS UNIQUE');
    await session.run('CREATE CONSTRAINT IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.id IS UNIQUE');
    await session.run('CREATE CONSTRAINT IF NOT EXISTS FOR (n:Alert) REQUIRE n.id IS UNIQUE');

    // ── Seed nodes by type ──
    const identityNodes = nodes.filter(n => n.type === 'Identity');
    const assetNodes = nodes.filter(n => n.type === 'Asset');
    const vulnNodes = nodes.filter(n => n.type === 'Vulnerability');

    // Identity nodes
    await session.run(
      `UNWIND $items AS item
       MERGE (n:Identity {id: item.id})
       SET n += item`,
      { items: identityNodes.map(n => { const { type, ...rest } = n; return rest; }) }
    );

    // Asset nodes
    await session.run(
      `UNWIND $items AS item
       MERGE (n:Asset {id: item.id})
       SET n += item`,
      { items: assetNodes.map(n => { const { type, ...rest } = n; return rest; }) }
    );

    // Vulnerability nodes
    await session.run(
      `UNWIND $items AS item
       MERGE (n:Vulnerability {id: item.id})
       SET n += item`,
      { items: vulnNodes.map(n => { const { type, ...rest } = n; return rest; }) }
    );

    // Alert nodes
    await session.run(
      `UNWIND $items AS item
       MERGE (n:Alert {id: item.id})
       SET n += item`,
      { items: rawAlerts }
    );

    // ── Seed relationships by type ──
    const relTypes = ['CAN_ACCESS', 'AUTHENTICATED_TO', 'CONNECTED_TO', 'HAS_VULN'] as const;
    for (const relType of relTypes) {
      const relEdges = edges.filter(e => e.relationship === relType);
      if (relEdges.length === 0) continue;

      // Build edge properties without source/target/relationship
      const items = relEdges.map(e => {
        const { source, target, relationship, ...props } = e;
        return { source, target, props };
      });

      await session.run(
        `UNWIND $items AS item
         MATCH (a {id: item.source})
         MATCH (b {id: item.target})
         MERGE (a)-[r:${relType} {id: item.props.id}]->(b)
         SET r += item.props`,
        { items }
      );
    }

    // ── Verify counts ──
    const nodeCount = await session.run('MATCH (n) WHERE n:Identity OR n:Asset OR n:Vulnerability RETURN count(n) AS c');
    const relCount = await session.run('MATCH (:Identity|Asset|Vulnerability)-[r]->(:Identity|Asset|Vulnerability) RETURN count(r) AS c');
    const alertCount = await session.run('MATCH (n:Alert) RETURN count(n) AS c');

    const nc = nodeCount.records[0].get('c').toNumber();
    const rc = relCount.records[0].get('c').toNumber();
    const ac = alertCount.records[0].get('c').toNumber();

    return { nodes: nc, relationships: rc, alerts: ac };
  } finally {
    await session.close();
  }
}

export async function resetGraph(driver: Driver, database: string) {
  const session = driver.session({ database });
  try {
    await session.run('MATCH (n) DETACH DELETE n');
  } finally {
    await session.close();
  }
}
