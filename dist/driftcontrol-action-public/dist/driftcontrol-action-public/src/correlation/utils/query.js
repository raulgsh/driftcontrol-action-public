// Graph query algorithms for impact analysis
const core = require('@actions/core');

/**
 * Find all nodes impacted by changes using BFS from changed nodes
 * Uses bottleneck (min) path aggregation by default for conservative estimates
 */
function impactedNodes(graph, config = {}) {
  const {
    maxDepth = 3,
    minConfidence = 0.55,
    pathAggregation = 'min'
  } = config;
  
  const impacted = new Map(); // nodeId -> {confidence, path, depth}
  const changedNodes = graph.getChangedNodes();
  
  if (changedNodes.length === 0) {
    return impacted;
  }
  
  core.debug(`Starting impact analysis from ${changedNodes.length} changed nodes`);
  
  // BFS from each changed node
  changedNodes.forEach(changedNode => {
    const queue = [{
      nodeId: changedNode.id,
      confidence: 1.0,
      path: [],
      depth: 0
    }];
    
    const visited = new Set();
    
    while (queue.length > 0) {
      const current = queue.shift();
      
      // Skip if already processed with higher confidence
      const existing = impacted.get(current.nodeId);
      if (existing && existing.confidence >= current.confidence) {
        continue;
      }
      
      // Record this path as the best for this node
      impacted.set(current.nodeId, {
        confidence: current.confidence,
        path: current.path,
        depth: current.depth,
        source: changedNode.id
      });
      
      // Avoid cycles and depth limits
      const visitKey = `${current.nodeId}-${current.depth}`;
      if (visited.has(visitKey)) {
        continue;
      }
      visited.add(visitKey);
      
      // Don't expand if at max depth
      if (current.depth >= maxDepth) {
        continue;
      }
      
      // Expand to neighbors
      const edges = graph.neighbors(current.nodeId, { direction: 'out' });
      
      edges.forEach(edge => {
        let pathConfidence;
        
        // Calculate path confidence based on aggregation method
        if (pathAggregation === 'product') {
          pathConfidence = current.confidence * edge.confidence;
        } else {
          // Default: min (bottleneck) aggregation
          pathConfidence = Math.min(current.confidence, edge.confidence);
        }
        
        // Only continue if path meets confidence threshold
        if (pathConfidence >= minConfidence) {
          queue.push({
            nodeId: edge.dst,
            confidence: pathConfidence,
            path: [...current.path, edge],
            depth: current.depth + 1
          });
        }
      });
    }
  });
  
  // Remove changed nodes from impact set (they're sources, not impacted)
  changedNodes.forEach(node => impacted.delete(node.id));
  
  core.debug(`Impact analysis found ${impacted.size} impacted nodes`);
  return impacted;
}

/**
 * Identify root causes using greedy set cover approach
 * Finds changed nodes that explain the most high-confidence impacts
 */
function rootCauses(graph, options = {}) {
  const { targets, minConfidence = 0.55 } = options;
  
  if (!targets || targets.size === 0) {
    return { causes: [] };
  }
  
  const changedNodes = graph.getChangedNodes();
  const targetList = Array.from(targets.keys());
  
  // For each changed node, find which targets it can explain
  const explanationMap = new Map(); // changedNodeId -> Set<targetId>
  
  changedNodes.forEach(changedNode => {
    const explained = new Set();
    
    targetList.forEach(targetId => {
      const targetData = targets.get(targetId);
      if (targetData && targetData.confidence >= minConfidence) {
        // Check if this changed node is the source of the impact path
        if (targetData.source === changedNode.id) {
          explained.add(targetId);
        }
      }
    });
    
    if (explained.size > 0) {
      explanationMap.set(changedNode.id, explained);
    }
  });
  
  // Greedy set cover: pick changed node that explains most uncovered targets
  const covered = new Set();
  const causes = [];
  
  while (covered.size < targetList.length && explanationMap.size > 0) {
    // Find changed node that explains most uncovered targets
    let bestNode = null;
    let bestScore = 0;
    let bestNewTargets = new Set();
    
    explanationMap.forEach((explainedTargets, nodeId) => {
      const newTargets = new Set();
      explainedTargets.forEach(targetId => {
        if (!covered.has(targetId)) {
          newTargets.add(targetId);
        }
      });
      
      if (newTargets.size > bestScore) {
        bestNode = nodeId;
        bestScore = newTargets.size;
        bestNewTargets = newTargets;
      }
    });
    
    if (bestNode && bestScore > 0) {
      const node = graph.getNode(bestNode);
      causes.push({
        nodeId: bestNode,
        kind: node?.kind || 'unknown',
        file: node?.meta?.file || bestNode,
        coveredTargets: Array.from(bestNewTargets),
        coverageScore: bestScore / targetList.length
      });
      
      // Mark targets as covered
      bestNewTargets.forEach(targetId => covered.add(targetId));
      
      // Remove this node from consideration
      explanationMap.delete(bestNode);
    } else {
      break; // No more improvements possible
    }
  }
  
  const coverage = covered.size / targetList.length;
  core.debug(`Root cause analysis: ${causes.length} causes explain ${Math.round(coverage * 100)}% of targets`);
  
  return { causes, coverage };
}

/**
 * Calculate blast radius metrics
 * Counts impacted nodes by type and service
 */
function blastRadius(graph, impacted, config = {}) {
  const byKind = {};
  const byService = {};
  const bySeverity = {};
  let total = 0;
  
  impacted.forEach((impactData, nodeId) => {
    const node = graph.getNode(nodeId);
    if (!node) return;
    
    // Only count non-changed nodes as impacted
    if (!node.changed) {
      total++;
      
      // Count by kind
      const kind = node.kind || 'unknown';
      byKind[kind] = (byKind[kind] || 0) + 1;
      
      // Count by service if available
      const service = node.meta?.service;
      if (service && typeof service === 'string') {
        byService[service] = (byService[service] || 0) + 1;
      }
      
      // Count by severity if available
      const severity = node.meta?.severity;
      if (severity) {
        bySeverity[severity] = (bySeverity[severity] || 0) + 1;
      }
    }
  });
  
  // Calculate risk score based on distribution
  let riskScore = 0;
  
  // Higher risk if many different kinds are affected
  const kindCount = Object.keys(byKind).length;
  riskScore += kindCount * 0.2;
  
  // Higher risk if critical systems are affected
  const criticalKinds = ['api', 'database', 'infrastructure'];
  criticalKinds.forEach(kind => {
    if (byKind[kind]) {
      riskScore += byKind[kind] * 0.3;
    }
  });
  
  // Cap at 1.0
  riskScore = Math.min(1.0, riskScore);
  
  return {
    total,
    byKind,
    byService,
    bySeverity,
    riskScore
  };
}

/**
 * Explain shortest high-confidence path between two nodes
 */
function explainPath(graph, options = {}) {
  const { srcId, dstId, maxDepth = 4, minConfidence = 0.55 } = options;
  
  if (!srcId || !dstId || !graph.getNode(srcId) || !graph.getNode(dstId)) {
    return null;
  }
  
  // BFS to find shortest path
  const queue = [{ nodeId: srcId, path: [], confidence: 1.0, depth: 0 }];
  const visited = new Set();
  
  while (queue.length > 0) {
    const current = queue.shift();
    
    if (current.nodeId === dstId) {
      // Found path
      return {
        path: current.path,
        confidence: current.confidence,
        explanation: buildPathExplanation(graph, current.path)
      };
    }
    
    const visitKey = `${current.nodeId}-${current.depth}`;
    if (visited.has(visitKey) || current.depth >= maxDepth) {
      continue;
    }
    visited.add(visitKey);
    
    // Expand neighbors
    const edges = graph.neighbors(current.nodeId, { direction: 'out' });
    edges.forEach(edge => {
      const pathConfidence = Math.min(current.confidence, edge.confidence);
      if (pathConfidence >= minConfidence) {
        queue.push({
          nodeId: edge.dst,
          path: [...current.path, edge],
          confidence: pathConfidence,
          depth: current.depth + 1
        });
      }
    });
  }
  
  return null; // No path found
}

/**
 * Build human-readable explanation of a path
 */
function buildPathExplanation(graph, path) {
  if (!path || path.length === 0) {
    return 'Direct connection';
  }
  
  const explanations = path.map((edge, i) => {
    const srcNode = graph.getNode(edge.src);
    const dstNode = graph.getNode(edge.dst);
    const conf = Math.round(edge.confidence * 100);
    
    const srcDesc = srcNode ? `${srcNode.kind}:${srcNode.meta?.file || edge.src}` : edge.src;
    const dstDesc = dstNode ? `${dstNode.kind}:${dstNode.meta?.file || edge.dst}` : edge.dst;
    
    return `${srcDesc} --${edge.type}(${conf}%)--> ${dstDesc}`;
  });
  
  return explanations.join('\n');
}

module.exports = {
  impactedNodes,
  rootCauses,
  blastRadius,
  explainPath
};