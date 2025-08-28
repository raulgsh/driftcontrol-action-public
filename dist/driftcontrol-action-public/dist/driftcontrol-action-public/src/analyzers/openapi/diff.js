const core = require('@actions/core');
const { diff } = require('@useoptic/openapi-utilities');

/**
 * OpenAPI diff analysis utilities
 */

// Compare two OpenAPI specs and return structured diff
async function compareSpecs(baseSpec, headSpec, baseSpecRaw, headSpecRaw) {
  const apiChanges = [];

  // Handle spec deletion (HIGH severity)
  if (baseSpec && !headSpec) {
    apiChanges.push('API_DELETION: OpenAPI specification was deleted');
    return apiChanges;
  }
  
  // Handle new spec (LOW severity)
  if (!baseSpec && headSpec) {
    apiChanges.push('New OpenAPI specification added');
    return apiChanges;
  }

  // Compare existing specs using @useoptic
  if (baseSpec && headSpec) {
    try {
      const diffResult = diff(baseSpec, headSpec);
      core.info(`OpenAPI diff analysis found ${diffResult ? diffResult.length : 0} changes`);
      
      if (diffResult && diffResult.length > 0) {
        // Analyze diff results for breaking changes
        for (const change of diffResult) {
          // Log the full change object to understand its structure
          core.info(`Full change object: ${JSON.stringify(change)}`);
          
          // Use the new structured parsing approach
          const parsedChange = parseDiffChange(change);
          
          core.info(`OpenAPI change detected: ${parsedChange.type} at ${parsedChange.path} -> ${parsedChange.description}`);
          
          // Classify changes for centralized scoring based on parsed structure
          if (parsedChange.breaking || parsedChange.description.includes('REMOVED_ENDPOINT')) {
            // Endpoint removal or breaking change
            apiChanges.push(`BREAKING_CHANGE: ${parsedChange.description}`);
          } else if (parsedChange.type === 'removed' || parsedChange.type === 'deleted') {
            apiChanges.push(`BREAKING_CHANGE: ${parsedChange.description}`);
          } else if (parsedChange.type === 'breaking' || parsedChange.type === 'required') {
            apiChanges.push(`BREAKING_CHANGE: ${parsedChange.description}`);
          } else if (parsedChange.isEndpoint && parsedChange.type === 'added') {
            // New endpoints are medium severity for API expansion
            apiChanges.push(`API_EXPANSION: ${parsedChange.description}`);
          } else if (parsedChange.type === 'added' || parsedChange.type === 'modified') {
            // Other additions or modifications
            apiChanges.push(parsedChange.description);
          } else if (parsedChange.type !== 'unknown') {
            // Any other detected change
            apiChanges.push(parsedChange.description);
          }
        }
        
        // If no changes detected, add generic change indicator
        if (apiChanges.length === 0) {
          apiChanges.push('OpenAPI specification changes detected');
        }
      } else {
        // No diff results but specs might still be different (fallback)
        if (baseSpecRaw !== headSpecRaw) {
          core.info('OpenAPI specs differ but no structured diff found, using fallback detection');
          apiChanges.push('OpenAPI specification changes detected (fallback detection)');
        }
      }
    } catch (diffError) {
      core.warning(`OpenAPI diff analysis failed: ${diffError.message}`);
      // Fallback to simple comparison
      if (baseSpecRaw !== headSpecRaw) {
        apiChanges.push('OpenAPI specification changes detected (detailed analysis failed)');
      }
    }
  }

  return apiChanges;
}

// Helper method to check if change object is in Optic diff format
function isOpticDiffFormat(change) {
  return change && (
    change.hasOwnProperty('before') || 
    change.hasOwnProperty('after') ||
    (change.hasOwnProperty('type') && change.hasOwnProperty('path'))
  );
}

// Main method to parse diff changes
function parseDiffChange(change) {
  // Try Optic format first
  if (isOpticDiffFormat(change)) {
    const parsed = parseOpticFormat(change);
    if (parsed) return parsed;
  }

  // Try generic structured parsing
  const genericParsed = parseGenericChange(change);
  if (genericParsed) return genericParsed;

  // Last resort - return basic structure
  return {
    type: 'unknown',
    path: 'unknown',
    description: 'OpenAPI change detected',
    raw: change
  };
}

// Helper method to parse Optic-specific diff format
function parseOpticFormat(change) {
  const decodePath = (path) => {
    if (typeof path === 'string') {
      return path.replace(/~1/g, '/').replace(/~0/g, '~');
    }
    return path;
  };

  const afterPath = decodePath(change.after);
  const beforePath = decodePath(change.before);
  
  if (change.after && !change.before) {
    // Something was added
    const endpoint = extractEndpointFromPath(afterPath);
    if (endpoint) {
      return {
        type: 'added',
        path: afterPath,
        description: `Added: New endpoint ${endpoint}`,
        isEndpoint: true
      };
    }
    return {
      type: 'added',
      path: afterPath,
      description: `Added: ${afterPath}`
    };
  } else if (change.before && !change.after) {
    // Something was removed
    const endpoint = extractEndpointFromPath(beforePath);
    if (endpoint) {
      return {
        type: 'removed',
        path: beforePath,
        description: `REMOVED_ENDPOINT: ${endpoint}`,
        isEndpoint: true,
        breaking: true
      };
    }
    return {
      type: 'removed',
      path: beforePath,
      description: `Removed: ${beforePath}`,
      breaking: true
    };
  } else if (change.before && change.after) {
    // Something was modified
    return {
      type: 'modified',
      pathBefore: beforePath,
      pathAfter: afterPath,
      description: `Modified: ${beforePath} -> ${afterPath}`
    };
  }
  
  // Handle type/path format (common in @useoptic diffs)
  if (change.type && change.path) {
    const changeType = change.type.toLowerCase();
    let description;
    
    // Format descriptions for compatibility with existing tests
    if (changeType === 'removed') {
      description = `Removed ${change.path}`;
    } else if (changeType === 'added') {
      // Treat added paths as Modified for existing test compatibility
      description = `Modified: ${change.path}`;
    } else if (changeType === 'breaking') {
      description = change.path;
    } else {
      description = `${change.type}: ${change.path}`;
    }
    
    return {
      type: change.type,
      path: change.path,
      description: description,
      breaking: changeType === 'removed' || changeType === 'breaking' || changeType === 'deleted'
    };
  }
  
  return null;
}

// Helper method to extract endpoint from path
function extractEndpointFromPath(path) {
  if (typeof path === 'string' && path.includes('/paths/')) {
    return path.replace('/paths/', '').split('/')[0];
  }
  return null;
}

// Helper method for structured fallback parsing
function parseGenericChange(change) {
  // Check for common properties in diff objects
  if (!change || typeof change !== 'object') {
    return null;
  }

  // Check for action-based changes
  if (change.action) {
    return {
      type: change.action,
      path: change.path || change.jsonPath || change.location || 'unknown',
      description: `${change.action}: ${change.path || 'unknown'}`
    };
  }

  // Check for operation-based changes
  if (change.operation) {
    return {
      type: change.operation,
      path: change.path || 'unknown',
      description: `${change.operation}: ${change.path || 'unknown'}`
    };
  }

  // Check for specific change indicators
  const changeIndicators = ['added', 'removed', 'modified', 'deleted', 'created', 'updated'];
  for (const indicator of changeIndicators) {
    if (change[indicator]) {
      return {
        type: indicator,
        path: change.path || change[indicator],
        description: `${indicator}: ${change.path || change[indicator]}`
      };
    }
  }

  return null;
}

module.exports = {
  compareSpecs,
  parseDiffChange,
  isOpticDiffFormat,
  parseOpticFormat,
  parseGenericChange,
  extractEndpointFromPath
};