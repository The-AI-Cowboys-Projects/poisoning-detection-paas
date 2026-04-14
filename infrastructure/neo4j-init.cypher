// =============================================================================
// LLM Data Poisoning Detection PaaS — Neo4j Initialization
// =============================================================================
// Run this script after the Neo4j container is healthy:
//
//   docker exec -i paas-neo4j cypher-shell \
//     -u neo4j -p "$NEO4J_PASSWORD" \
//     --database poisoning \
//     < infrastructure/neo4j-init.cypher
//
// What this script does:
//   1. Create uniqueness constraints on ProvenanceNode identifiers
//   2. Create indexes on high-cardinality lookup properties
//   3. Define named query templates as CALL procedures (reference patterns)
//
// Node label taxonomy:
//   (:Dataset)      — raw or curated data source
//   (:Transform)    — preprocessing / augmentation step
//   (:Model)        — trained or fine-tuned model artifact
//   (:Deployment)   — running inference endpoint
//
// Relationship types:
//   -[:DERIVED_FROM]->   — data lineage edge
//   -[:TRAINED_ON]->     — model trained on dataset
//   -[:FINE_TUNED_FROM]->— model fine-tuned from base model
//   -[:SERVED_BY]->      — model deployed via endpoint
//   -[:CONTAMINATED_BY]->— poisoning propagation edge (written by detection engine)
// =============================================================================


// ---------------------------------------------------------------------------
// 1. Uniqueness constraints
//    Implicitly create a supporting B-tree index on the constrained property.
// ---------------------------------------------------------------------------

// Every node has a globally unique UUID assigned at insertion time.
CREATE CONSTRAINT provenance_node_id_unique IF NOT EXISTS
  FOR (n:ProvenanceNode)
  REQUIRE n.node_id IS UNIQUE;

// Dataset constraints
CREATE CONSTRAINT dataset_id_unique IF NOT EXISTS
  FOR (d:Dataset)
  REQUIRE d.dataset_id IS UNIQUE;

// Transform constraints
CREATE CONSTRAINT transform_id_unique IF NOT EXISTS
  FOR (t:Transform)
  REQUIRE t.transform_id IS UNIQUE;

// Model constraints
CREATE CONSTRAINT model_id_unique IF NOT EXISTS
  FOR (m:Model)
  REQUIRE m.model_id IS UNIQUE;

// Deployment constraints
CREATE CONSTRAINT deployment_id_unique IF NOT EXISTS
  FOR (d:Deployment)
  REQUIRE d.deployment_id IS UNIQUE;


// ---------------------------------------------------------------------------
// 2. Indexes — multi-tenant lookups and graph traversal hot paths
// ---------------------------------------------------------------------------

// Tenant isolation — every node carries tenant_id for RLS-equivalent filtering
CREATE INDEX provenance_tenant_id IF NOT EXISTS
  FOR (n:ProvenanceNode)
  ON (n.tenant_id);

CREATE INDEX dataset_tenant_id IF NOT EXISTS
  FOR (d:Dataset)
  ON (d.tenant_id);

CREATE INDEX model_tenant_id IF NOT EXISTS
  FOR (m:Model)
  ON (m.tenant_id);

CREATE INDEX deployment_tenant_id IF NOT EXISTS
  FOR (dep:Deployment)
  ON (dep.tenant_id);

// Timestamp indexes — for time-bounded lineage queries
CREATE INDEX dataset_created_at IF NOT EXISTS
  FOR (d:Dataset)
  ON (d.created_at);

CREATE INDEX model_created_at IF NOT EXISTS
  FOR (m:Model)
  ON (m.created_at);

// Source tracking — where did the raw data originate?
CREATE INDEX dataset_source IF NOT EXISTS
  FOR (d:Dataset)
  ON (d.source);

// Verdict index — quickly find all poisoned nodes for a tenant
CREATE INDEX dataset_verdict IF NOT EXISTS
  FOR (d:Dataset)
  ON (d.poisoning_verdict);

// Relationship property index — contamination probability (Neo4j 5+)
CREATE INDEX contamination_probability IF NOT EXISTS
  FOR ()-[r:CONTAMINATED_BY]-()
  ON (r.probability);


// ---------------------------------------------------------------------------
// 3. Sample provenance graph — development seed data
//    Demonstrates the schema; DELETE in production before go-live.
// ---------------------------------------------------------------------------

// Only create seed data when the graph is empty
CALL apoc.util.sleep(0)  // no-op; ensures APOC is loaded
WITH 1 AS sentinel
WHERE NOT EXISTS { MATCH (n:Dataset) RETURN n }

MERGE (raw:Dataset:ProvenanceNode {
    dataset_id:        'seed-dataset-001',
    node_id:           randomUUID(),
    tenant_id:         '00000000-0000-0000-0000-000000000001',
    name:              'Public Web Crawl Seed',
    source:            'common-crawl',
    format:            'jsonl',
    record_count:      10000000,
    size_bytes:        53687091200,
    created_at:        datetime(),
    poisoning_verdict: 'unknown',
    hash_sha256:       'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
})

MERGE (clean:Dataset:ProvenanceNode {
    dataset_id:        'seed-dataset-002',
    node_id:           randomUUID(),
    tenant_id:         '00000000-0000-0000-0000-000000000001',
    name:              'Filtered Instruction Set',
    source:            'internal-curation-pipeline',
    format:            'jsonl',
    record_count:      500000,
    size_bytes:        1073741824,
    created_at:        datetime(),
    poisoning_verdict: 'clean',
    hash_sha256:       'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
})

MERGE (dedup:Transform:ProvenanceNode {
    transform_id: 'seed-transform-001',
    node_id:      randomUUID(),
    tenant_id:    '00000000-0000-0000-0000-000000000001',
    name:         'Deduplication + Toxicity Filter',
    version:      '1.2.0',
    created_at:   datetime()
})

MERGE (baseModel:Model:ProvenanceNode {
    model_id:   'seed-model-001',
    node_id:    randomUUID(),
    tenant_id:  '00000000-0000-0000-0000-000000000001',
    name:       'Seed Base LM',
    version:    '7B',
    framework:  'transformers',
    created_at: datetime()
})

MERGE (endpoint:Deployment:ProvenanceNode {
    deployment_id: 'seed-deployment-001',
    node_id:       randomUUID(),
    tenant_id:     '00000000-0000-0000-0000-000000000001',
    name:          'Staging Inference Endpoint',
    environment:   'staging',
    created_at:    datetime()
})

// Wire up the lineage graph
MERGE (clean)-[:DERIVED_FROM {weight: 1.0, created_at: datetime()}]->(raw)
MERGE (dedup)-[:DERIVED_FROM {weight: 1.0, created_at: datetime()}]->(raw)
MERGE (baseModel)-[:TRAINED_ON {split: 'train', created_at: datetime()}]->(clean)
MERGE (endpoint)-[:SERVED_BY {replicas: 2, created_at: datetime()}]->(baseModel);


// ---------------------------------------------------------------------------
// 4. Named query templates
//    These are stored as comments only — execute them directly via the driver.
//    They demonstrate the intended read patterns for the provenance API.
// ---------------------------------------------------------------------------

// --- Q1: Full lineage chain for a given model (upstream) ---
//
// MATCH path = (m:Model {model_id: $model_id, tenant_id: $tenant_id})
//              -[:TRAINED_ON|FINE_TUNED_FROM*1..10]->
//              (d:Dataset)
// RETURN path, nodes(path) AS chain, relationships(path) AS edges
// ORDER BY length(path) ASC

// --- Q2: Contamination blast radius for a poisoned dataset ---
//
// MATCH (poisoned:Dataset {dataset_id: $dataset_id, tenant_id: $tenant_id})
// CALL apoc.path.spanningTree(poisoned, {
//     relationshipFilter: 'CONTAMINATED_BY>|DERIVED_FROM>|TRAINED_ON>',
//     maxLevel: 8
// }) YIELD path
// RETURN path

// --- Q3: All models potentially affected by a poisoned dataset ---
//
// MATCH (poisoned:Dataset {dataset_id: $dataset_id, tenant_id: $tenant_id})
// MATCH (m:Model)
// WHERE EXISTS {
//     MATCH (m)-[:TRAINED_ON|FINE_TUNED_FROM*1..5]->(d:Dataset)
//     WHERE d.dataset_id = poisoned.dataset_id
//        OR EXISTS {
//            MATCH (d)-[:DERIVED_FROM*1..5]->(poisoned)
//        }
// }
// RETURN m.model_id, m.name, m.version
// ORDER BY m.created_at DESC

// --- Q4: Provenance graph statistics for tenant dashboard ---
//
// MATCH (n:ProvenanceNode {tenant_id: $tenant_id})
// RETURN
//     labels(n)[0]                AS node_type,
//     count(*)                    AS count,
//     sum(CASE WHEN n.poisoning_verdict = 'poisoned'   THEN 1 ELSE 0 END) AS poisoned,
//     sum(CASE WHEN n.poisoning_verdict = 'suspicious' THEN 1 ELSE 0 END) AS suspicious,
//     sum(CASE WHEN n.poisoning_verdict = 'clean'      THEN 1 ELSE 0 END) AS clean
// GROUP BY labels(n)[0]

// --- Q5: Recent contamination edges (for incident timeline) ---
//
// MATCH (a)-[r:CONTAMINATED_BY]->(b)
// WHERE r.tenant_id = $tenant_id
//   AND r.detected_at >= datetime($since)
// RETURN
//     a.dataset_id        AS source_id,
//     a.name              AS source_name,
//     b.dataset_id        AS target_id,
//     b.name              AS target_name,
//     r.probability       AS probability,
//     r.detected_at       AS detected_at
// ORDER BY r.detected_at DESC
// LIMIT 50

// --- Q6: Shortest contamination path between two datasets ---
//
// MATCH (src:Dataset {dataset_id: $source_id, tenant_id: $tenant_id}),
//       (dst:Dataset {dataset_id: $target_id, tenant_id: $tenant_id})
// MATCH path = shortestPath(
//     (src)-[:CONTAMINATED_BY|DERIVED_FROM*..20]->(dst)
// )
// RETURN path, length(path) AS hops


// ---------------------------------------------------------------------------
// 5. Verification
// ---------------------------------------------------------------------------
CALL apoc.util.sleep(0) WITH 1 AS x
RETURN
    'Initialization complete' AS status,
    datetime()               AS completed_at;
