// Centralized artifact graph for impact analysis
const { getArtifactId } = require('./artifacts');

/**
 * Centralized artifact graph using adjacency lists
 * Reuses existing correlation data and artifactId system
 */
class ArtifactGraph {
  constructor() {
    this.nodes = new Map();         // id -> ArtifactNode
    this.adjacency = new Map();     // id -> Array<GraphEdge> (outgoing)
    this.reverse = new Map();       // id -> Array<GraphEdge> (incoming)
  }
  
  /**
   * Add or update a node from a drift result
   * Reuses existing artifactId logic for consistency
   */
  upsertNode(result) {
    const id = result.artifactId || getArtifactId(result);
    
    if (!this.nodes.has(id)) {
      this.nodes.set(id, {
        id,
        kind: result.type || 'unknown',
        meta: {
          file: result.file,
          severity: result.severity,
          method: result.method,
          service: result.service,
          path: result.endpoints?.[0],
          table: result.entities?.[0],
          ...result.metadata
        },
        changed: !!result.changed
      });
      
      // Initialize adjacency lists
      if (!this.adjacency.has(id)) {
        this.adjacency.set(id, []);
      }
      if (!this.reverse.has(id)) {
        this.reverse.set(id, []);
      }
    }
    
    return id;
  }
  
  /**
   * Add edge with de-duplication by (src,dst,type)
   * Takes max confidence for duplicate edges
   */
  addEdge(edge) {
    const { src, dst, type, confidence, provenance, evidence = [] } = edge;
    
    // Ensure adjacency lists exist
    if (!this.adjacency.has(src)) this.adjacency.set(src, []);
    if (!this.reverse.has(dst)) this.reverse.set(dst, []);
    
    // Check for existing edge
    const existing = this.adjacency.get(src).find(e => 
      e.dst === dst && e.type === type
    );
    
    if (existing) {
      // Merge with max confidence and combine evidence
      existing.confidence = Math.max(existing.confidence, confidence);
      const combinedEvidence = [...existing.evidence, ...evidence]
        .slice(0, 5); // Limit evidence size
      existing.evidence = combinedEvidence;
      
      // Update provenance if new one has higher confidence
      if (confidence > existing.confidence) {
        existing.provenance = provenance;
      }
    } else {
      // Add new edge
      const newEdge = { src, dst, type, confidence, provenance, evidence };
      this.adjacency.get(src).push(newEdge);
      
      // Add reverse edge for efficient backward traversal
      this.reverse.get(dst).push({
        src: dst,
        dst: src,
        type,
        confidence,
        provenance,
        evidence
      });
    }
  }
  
  /**
   * Get neighbors of a node
   */
  neighbors(nodeId, options = {}) {
    const { direction = 'out' } = options;
    
    switch (direction) {
      case 'out':
        return this.adjacency.get(nodeId) || [];
      case 'in':
        return this.reverse.get(nodeId) || [];
      case 'both':
        return [
          ...(this.adjacency.get(nodeId) || []),
          ...(this.reverse.get(nodeId) || [])
        ];
      default:
        return [];
    }
  }
  
  /**
   * Get node by ID
   */
  getNode(nodeId) {
    return this.nodes.get(nodeId);
  }
  
  /**
   * Get graph statistics
   */
  stats() {
    let edgeCount = 0;
    this.adjacency.forEach(edges => edgeCount += edges.length);
    
    return {
      nodeCount: this.nodes.size,
      edgeCount,
      changedNodes: Array.from(this.nodes.values()).filter(n => n.changed).length
    };
  }
  
  /**
   * Get all changed nodes (source nodes for impact analysis)
   */
  getChangedNodes() {
    return Array.from(this.nodes.values()).filter(node => node.changed);
  }
  
  /**
   * Safety bounds check
   */
  exceedsLimits(config = {}) {
    const nodeLimit = config.node_limit || 2000;
    const edgeLimit = config.edge_limit || 6000;
    const stats = this.stats();
    
    return {
      exceedsNodes: stats.nodeCount > nodeLimit,
      exceedsEdges: stats.edgeCount > edgeLimit,
      stats
    };
  }
}

module.exports = {
  ArtifactGraph
};