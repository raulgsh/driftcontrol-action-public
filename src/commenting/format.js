/**
 * Formatting utilities for comments
 */

// Build ASCII correlation graph - enhanced with graph data
function buildCorrelationGraph(driftResults, correlations) {
  // Use new graph structure if available
  if (correlations && correlations._graph && correlations._impact) {
    return renderGraphAscii(correlations._graph, correlations._impact, correlations._rootCauses);
  }
  
  // Fallback to legacy rendering
  let graph = 'Drift Correlation Graph:\n\n';
  const drawnRelationships = new Set();
  
  driftResults.forEach(result => {
    if (result.correlations && result.correlations.length > 0) {
      result.correlations.forEach(corr => {
        if (corr.source === result) {
          // Create a unique key for this relationship to avoid duplicates
          const relKey = `${corr.source.type}:${corr.source.file}→${corr.target.type}:${corr.target.file}`;
          if (!drawnRelationships.has(relKey)) {
            drawnRelationships.add(relKey);
            
            // Format the labels
            const sourceLabel = `[${corr.source.type}] ${shortenPath(corr.source.file)}`;
            const targetLabel = `[${corr.target.type}] ${shortenPath(corr.target.file)}`;
            const confidence = Math.round((corr.confidence || 0.5) * 100);
            
            // Add the relationship line
            graph += `${sourceLabel}\n`;
            graph += `  └─${corr.relationship}(${confidence}%)→ ${targetLabel}\n`;
          }
        }
      });
    }
  });
  
  // If no relationships were drawn, indicate that
  if (drawnRelationships.size === 0) {
    return 'No correlations found';
  }
  
  return graph;
}

// Enhanced ASCII rendering using graph data
function renderGraphAscii(graph, impact, rootCauses) {
  const lines = [];
  const rendered = new Set();
  
  // Show summary first
  const stats = graph.stats();
  const impactSize = impact ? impact.size : 0;
  lines.push(`Impact Analysis: ${impactSize} nodes affected from ${stats.changedNodes} changes`);
  lines.push('');
  
  // Show root causes prominently
  if (rootCauses && rootCauses.causes && rootCauses.causes.length > 0) {
    lines.push('🎯 Root Causes:');
    rootCauses.causes.slice(0, 3).forEach(cause => {
      const node = graph.getNode(cause.nodeId);
      const coverage = Math.round(cause.coverageScore * 100);
      const nodeDesc = node ? `${node.kind}:${shortenPath(node.meta.file || cause.nodeId)}` : cause.nodeId;
      lines.push(`  ⚡ ${nodeDesc} (covers ${coverage}% of impact)`);
    });
    lines.push('');
  }
  
  // Show top impact paths (from changed nodes)
  if (impact && impact.size > 0) {
    lines.push('🔗 Impact Paths:');
    
    // Sort impacts by confidence and limit display
    const sortedImpacts = Array.from(impact.entries())
      .filter(([nodeId, data]) => data.path && data.path.length > 0)
      .sort((a, b) => b[1].confidence - a[1].confidence)
      .slice(0, 8); // Limit to prevent overwhelming output
    
    sortedImpacts.forEach(([nodeId, data]) => {
      const targetNode = graph.getNode(nodeId);
      const conf = Math.round(data.confidence * 100);
      const targetDesc = targetNode ? 
        `${targetNode.kind}:${shortenPath(targetNode.meta.file || nodeId)}` : 
        nodeId;
      
      lines.push(`  ${targetDesc} (${conf}% confidence)`);
      
      // Show path (simplified to first 2 hops to save space)
      const pathPreview = data.path.slice(0, 2);
      pathPreview.forEach((edge, i) => {
        const srcNode = graph.getNode(edge.src);
        const edgeConf = Math.round(edge.confidence * 100);
        const indent = '    ' + '  '.repeat(i);
        const srcDesc = srcNode ? 
          `${srcNode.kind}:${shortenPath(srcNode.meta.file || edge.src)}` : 
          edge.src;
        
        if (i === 0) {
          lines.push(`${indent}├─ via ${srcDesc}`);
        }
        lines.push(`${indent}└─${edge.type}(${edgeConf}%)→`);
      });
      
      if (data.path.length > 2) {
        lines.push(`      ... (+${data.path.length - 2} more hops)`);
      }
      lines.push('');
    });
  }
  
  // Truncate if too long
  const maxLines = 25;
  if (lines.length > maxLines) {
    const truncated = lines.slice(0, maxLines - 1);
    truncated.push(`... (${lines.length - maxLines + 1} more lines truncated for readability)`);
    return truncated.join('\n');
  }
  
  return lines.join('\n') || 'No impact paths found';
}

// Helper to shorten file paths for readability
function shortenPath(path) {
  if (!path) return 'unknown';
  
  // If path is longer than 40 chars, show .../ and last part
  if (path.length > 40) {
    const parts = path.split('/');
    if (parts.length > 2) {
      return `.../${parts[parts.length - 2]}/${parts[parts.length - 1]}`;
    }
    return `.../${parts[parts.length - 1]}`;
  }
  
  return path;
}

// Convert glob patterns to regex (consolidates logic from analyzers)
function globToRegex(glob) {
  let pattern;
  if (glob.includes('**/')) {
    // Split by **/ and handle all segments
    const segments = glob.split('**/');
    
    // Escape and prepare each segment
    const processedSegments = segments.map((segment, index) => {
      // Escape dots and replace single wildcards
      const escaped = segment
        .replace(/\./g, '\\.')
        .replace(/\*/g, '[^/]*');
      
      // First segment doesn't need wildcard prefix
      if (index === 0) {
        return escaped;
      }
      // Last segment doesn't need wildcard suffix
      if (index === segments.length - 1) {
        return escaped;
      }
      // Middle segments are just patterns
      return escaped;
    });
    
    // Join with .* to match any directory depth
    pattern = '^' + processedSegments.join('.*') + '$';
  } else {
    // Handle patterns without **/
    // Need to anchor to start for non-** patterns
    pattern = '^' + glob
      .replace(/\./g, '\\.')
      .replace(/\*\*/g, '.*')
      .replace(/\*/g, '[^/]*')
      + '$';
  }
  return new RegExp(pattern);
}

module.exports = {
  buildCorrelationGraph,
  shortenPath,
  globToRegex
};