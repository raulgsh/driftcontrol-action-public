/**
 * Formatting utilities for comments
 */

// Build ASCII correlation graph
function buildCorrelationGraph(driftResults) {
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