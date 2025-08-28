const { ArtifactGraph } = require('../src/correlation/utils/graph');
const { impactedNodes, rootCauses, blastRadius } = require('../src/correlation/utils/query');

describe('Centralized Artifact Graph', () => {
  describe('ArtifactGraph', () => {
    let graph;

    beforeEach(() => {
      graph = new ArtifactGraph();
    });

    test('creates empty graph', () => {
      const stats = graph.stats();
      expect(stats.nodeCount).toBe(0);
      expect(stats.edgeCount).toBe(0);
      expect(stats.changedNodes).toBe(0);
    });

    test('adds nodes from drift results', () => {
      const result = {
        artifactId: 'api:GET:/users',
        type: 'api',
        file: 'src/api/users.js',
        severity: 'medium',
        changed: true
      };

      const nodeId = graph.upsertNode(result);
      expect(nodeId).toBe('api:GET:/users');

      const stats = graph.stats();
      expect(stats.nodeCount).toBe(1);
      expect(stats.changedNodes).toBe(1);

      const node = graph.getNode(nodeId);
      expect(node.kind).toBe('api');
      expect(node.meta.file).toBe('src/api/users.js');
      expect(node.changed).toBe(true);
    });

    test('de-duplicates edges by (src,dst,type)', () => {
      graph.upsertNode({ artifactId: 'api:GET:/users', type: 'api', changed: false });
      graph.upsertNode({ artifactId: 'db:table:users', type: 'database', changed: true });

      // Add same edge twice with different confidence
      graph.addEdge({
        src: 'api:GET:/users',
        dst: 'db:table:users',
        type: 'uses_table',
        confidence: 0.8,
        provenance: 'entity',
        evidence: [{ reason: 'table name match' }]
      });

      graph.addEdge({
        src: 'api:GET:/users',
        dst: 'db:table:users',
        type: 'uses_table',
        confidence: 0.9, // Higher confidence
        provenance: 'entity',
        evidence: [{ reason: 'SQL query analysis' }]
      });

      const stats = graph.stats();
      expect(stats.edgeCount).toBe(1); // Should be deduplicated

      const edges = graph.neighbors('api:GET:/users', { direction: 'out' });
      expect(edges).toHaveLength(1);
      expect(edges[0].confidence).toBe(0.9); // Should take max confidence
      expect(edges[0].evidence).toHaveLength(2); // Should combine evidence
    });

    test('supports bidirectional neighbor queries', () => {
      graph.upsertNode({ artifactId: 'api:GET:/users', type: 'api' });
      graph.upsertNode({ artifactId: 'db:table:users', type: 'database' });

      graph.addEdge({
        src: 'api:GET:/users',
        dst: 'db:table:users',
        type: 'uses_table',
        confidence: 0.8,
        provenance: 'entity'
      });

      const outgoing = graph.neighbors('api:GET:/users', { direction: 'out' });
      expect(outgoing).toHaveLength(1);
      expect(outgoing[0].dst).toBe('db:table:users');

      const incoming = graph.neighbors('db:table:users', { direction: 'in' });
      expect(incoming).toHaveLength(1);
      expect(incoming[0].dst).toBe('api:GET:/users'); // Reverse edge

      const both = graph.neighbors('api:GET:/users', { direction: 'both' });
      expect(both).toHaveLength(1);
    });
  });

  describe('Impact Analysis', () => {
    let graph;

    beforeEach(() => {
      graph = new ArtifactGraph();
      
      // Build test scenario: API → uses_table → DB → configured_by → Config
      graph.upsertNode({ artifactId: 'api:GET:/users', type: 'api', changed: false });
      graph.upsertNode({ artifactId: 'db:table:users', type: 'database', changed: true }); // Changed node
      graph.upsertNode({ artifactId: 'config:db.json', type: 'configuration', changed: false });

      graph.addEdge({
        src: 'api:GET:/users',
        dst: 'db:table:users',
        type: 'uses_table',
        confidence: 0.9,
        provenance: 'entity'
      });

      graph.addEdge({
        src: 'db:table:users',
        dst: 'config:db.json',
        type: 'configured_by',
        confidence: 0.8,
        provenance: 'infrastructure'
      });
    });

    test('finds nodes impacted by changes', () => {
      const impact = impactedNodes(graph, { maxDepth: 3, minConfidence: 0.5 });
      
      // Should find config impacted via db → config path
      expect(impact.has('config:db.json')).toBe(true);
      
      const configImpact = impact.get('config:db.json');
      expect(configImpact.confidence).toBeCloseTo(0.8); // Min of path confidences
      expect(configImpact.path).toHaveLength(1); // db → config
      expect(configImpact.source).toBe('db:table:users');
    });

    test('respects confidence thresholds', () => {
      const impact = impactedNodes(graph, { maxDepth: 3, minConfidence: 0.85 });
      
      // Config path confidence (0.8) should be below threshold (0.85)
      expect(impact.has('config:db.json')).toBe(false);
    });

    test('respects depth limits', () => {
      // Add another hop: Config → Infrastructure
      graph.upsertNode({ artifactId: 'iac:rds:db-instance', type: 'infrastructure', changed: false });
      graph.addEdge({
        src: 'config:db.json',
        dst: 'iac:rds:db-instance',
        type: 'provisions',
        confidence: 0.7,
        provenance: 'infrastructure'
      });

      // Path from changed db:table:users: db → config (depth 1) → iac (depth 2)
      // With maxDepth=1, only config should be reachable
      const impactDepth1 = impactedNodes(graph, { maxDepth: 1, minConfidence: 0.5 });
      expect(impactDepth1.has('config:db.json')).toBe(true);
      expect(impactDepth1.has('iac:rds:db-instance')).toBe(false); // Beyond depth limit

      // With maxDepth=2, iac should also be reachable
      const impactDepth2 = impactedNodes(graph, { maxDepth: 2, minConfidence: 0.5 });
      expect(impactDepth2.has('config:db.json')).toBe(true);
      expect(impactDepth2.has('iac:rds:db-instance')).toBe(true); // Within depth limit
    });
  });

  describe('Root Cause Analysis', () => {
    let graph, impact;

    beforeEach(() => {
      graph = new ArtifactGraph();
      
      // Forked scenario: IaC (changed) → provisions → Lambda1 → calls → API1
      //                                → provisions → Lambda2 → calls → API2
      graph.upsertNode({ artifactId: 'iac:lambda:processor', type: 'infrastructure', changed: true });
      graph.upsertNode({ artifactId: 'code:lambda1', type: 'code', changed: false });
      graph.upsertNode({ artifactId: 'code:lambda2', type: 'code', changed: false });
      graph.upsertNode({ artifactId: 'api:GET:/v1/process', type: 'api', changed: false });
      graph.upsertNode({ artifactId: 'api:POST:/v1/jobs', type: 'api', changed: false });

      // Build edges
      graph.addEdge({ src: 'iac:lambda:processor', dst: 'code:lambda1', type: 'provisions', confidence: 0.9, provenance: 'infrastructure' });
      graph.addEdge({ src: 'iac:lambda:processor', dst: 'code:lambda2', type: 'provisions', confidence: 0.9, provenance: 'infrastructure' });
      graph.addEdge({ src: 'code:lambda1', dst: 'api:GET:/v1/process', type: 'calls', confidence: 0.8, provenance: 'code' });
      graph.addEdge({ src: 'code:lambda2', dst: 'api:POST:/v1/jobs', type: 'calls', confidence: 0.8, provenance: 'code' });

      impact = impactedNodes(graph, { maxDepth: 3, minConfidence: 0.6 });
    });

    test('identifies root causes covering most impact', () => {
      const analysis = rootCauses(graph, { targets: impact, minConfidence: 0.6 });
      
      expect(analysis.causes).toHaveLength(1);
      expect(analysis.causes[0].nodeId).toBe('iac:lambda:processor');
      expect(analysis.causes[0].coveredTargets).toHaveLength(4); // Covers all impacted nodes
      expect(analysis.coverage).toBeCloseTo(1.0); // 100% coverage
    });

    test('provides meaningful cause descriptions', () => {
      const analysis = rootCauses(graph, { targets: impact, minConfidence: 0.6 });
      
      const cause = analysis.causes[0];
      expect(cause.kind).toBe('infrastructure');
      expect(cause.nodeId).toBe('iac:lambda:processor');
      expect(cause.coverageScore).toBeCloseTo(1.0);
    });
  });

  describe('Blast Radius Calculation', () => {
    let graph, impact;

    beforeEach(() => {
      graph = new ArtifactGraph();
      
      // Mixed impact scenario
      graph.upsertNode({ artifactId: 'db:migration:001', type: 'database', changed: true });
      graph.upsertNode({ artifactId: 'api:GET:/users', type: 'api', changed: false, service: 'user-service', metadata: { severity: 'high' } });
      graph.upsertNode({ artifactId: 'api:POST:/users', type: 'api', changed: false, service: 'user-service', metadata: { severity: 'medium' } });
      graph.upsertNode({ artifactId: 'config:app.yml', type: 'configuration', changed: false, service: 'user-service' });
      graph.upsertNode({ artifactId: 'iac:rds:users-db', type: 'infrastructure', changed: false, service: 'user-service' });

      // Create impact paths
      const impacts = new Map();
      impacts.set('api:GET:/users', { confidence: 0.9, path: [], source: 'db:migration:001' });
      impacts.set('api:POST:/users', { confidence: 0.8, path: [], source: 'db:migration:001' });
      impacts.set('config:app.yml', { confidence: 0.7, path: [], source: 'db:migration:001' });
      impacts.set('iac:rds:users-db', { confidence: 0.6, path: [], source: 'db:migration:001' });

      impact = impacts;
    });

    test('calculates blast radius metrics', () => {
      const radius = blastRadius(graph, impact);
      
      expect(radius.total).toBe(4);
      expect(radius.byKind).toEqual({
        api: 2,
        configuration: 1,
        infrastructure: 1
      });
      expect(radius.byService).toEqual({
        'user-service': 4
      });
    });

    test('calculates risk score based on impact distribution', () => {
      const radius = blastRadius(graph, impact);
      
      // Risk score should be elevated due to API and infrastructure impact
      expect(radius.riskScore).toBeGreaterThan(0.5);
      expect(radius.riskScore).toBeLessThanOrEqual(1.0);
    });
  });

  describe('Integration with Correlation Engine', () => {
    test('builds graph from expanded results and correlations', () => {
      const { buildCorrelationGraph } = require('../src/correlation/engine');
      
      const expandedResults = [
        { artifactId: 'api:GET:/users', type: 'api', file: 'api/users.js', changed: false },
        { artifactId: 'db:table:users', type: 'database', file: 'migrations/001.sql', changed: true }
      ];

      const correlations = [
        {
          source: { artifactId: 'api:GET:/users' },
          target: { artifactId: 'db:table:users' },
          relationship: 'uses_table',
          finalScore: 0.9,
          confidence: 0.9,
          userDefined: false,
          strategies: ['entity'],
          evidence: [{ reason: 'table name match' }]
        }
      ];

      const graph = buildCorrelationGraph(expandedResults, correlations);
      
      expect(graph).toBeTruthy();
      const stats = graph.stats();
      expect(stats.nodeCount).toBe(2);
      expect(stats.edgeCount).toBe(1);
      expect(stats.changedNodes).toBe(1);

      const edges = graph.neighbors('api:GET:/users', { direction: 'out' });
      expect(edges).toHaveLength(1);
      expect(edges[0].type).toBe('uses_table');
      expect(edges[0].confidence).toBe(0.9);
      expect(edges[0].provenance).toBe('entity');
    });

    test('handles safety limits', () => {
      const { buildCorrelationGraph } = require('../src/correlation/engine');
      
      const config = {
        graph: {
          node_limit: 1, // Very low limit
          edge_limit: 1000
        }
      };

      const expandedResults = [
        { artifactId: 'api:GET:/users', type: 'api' },
        { artifactId: 'db:table:users', type: 'database' },
        { artifactId: 'config:app.yml', type: 'configuration' } // Exceeds limit
      ];

      const graph = buildCorrelationGraph(expandedResults, [], config);
      expect(graph).toBeNull(); // Should return null when limits exceeded
    });
  });
});