// Artifact identification and processing utilities
const core = require('@actions/core');

// Normalize paths/APIs for artifact IDs
function normPath(p) {
  return p ? p.replace(/\\/g, '/').replace(/\/+/g, '/').replace(/\/$/, '').replace(/^\.\//, '') : '';
}

function normApi(ep) {
  if (!ep) return 'api:unknown';
  const parts = ep.split(':');
  const hasMethod = parts.length > 1;
  const method = (hasMethod ? parts[0] : 'GET').toUpperCase();
  const path = normPath((hasMethod ? parts.slice(1).join(':') : ep)
    .toLowerCase()
    .replace(/\{[^}]+\}/g, m => m.toLowerCase())); // Normalize placeholders
  return `api:${method}:${path}`;
};

function getArtifactId(result) {
  if (!result) return 'unknown';
  if (result.id) return result.id; // Pre-computed if available
  
  // API: normalize method:path
  if (result.type === 'api' && result.endpoints && result.endpoints[0]) {
    return normApi(result.endpoints[0]);
  }
  
  // Database: lowercase table name
  if (result.type === 'database' && result.entities && result.entities[0]) {
    return `db:table:${result.entities[0].toLowerCase()}`;
  }
  
  // Infrastructure: resource type and ID
  if (result.type === 'infrastructure' && result.resources && result.resources[0]) {
    const resourceType = (result.resourceType || 'resource').toLowerCase();
    return `iac:${resourceType}:${result.resources[0].toLowerCase()}`;
  }
  
  // Configuration files
  if (result.type === 'configuration' && result.file) {
    return `config:${normPath(result.file)}`;
  }
  
  // File-based fallback: normalize path
  if (result.file) return `file:${normPath(result.file)}`;
  
  // Type-based fallback
  return `${result.type}:${result.name || result.severity || 'unknown'}`.toLowerCase();
}

// Canonical pair key for undirected pairs
function getPairKey(a, b) {
  const A = getArtifactId(a);
  const B = getArtifactId(b);
  return A < B ? `${A}::${B}` : `${B}::${A}`; // Canonical ordering
}

// Expand multi-item results into atomic artifacts
function expandResults(driftResults) {
  const expanded = [];
  for (const r of driftResults) {
    if (r.type === 'api' && Array.isArray(r.endpoints) && r.endpoints.length > 1) {
      for (const ep of r.endpoints) {
        expanded.push({ ...r, endpoints: [ep], id: normApi(ep) });
      }
    } else if (r.type === 'database' && Array.isArray(r.entities) && r.entities.length > 1) {
      for (const ent of r.entities) {
        expanded.push({ ...r, entities: [ent], id: `db:table:${ent.toLowerCase()}` });
      }
    } else {
      expanded.push(r);
    }
  }
  
  core.info(`Expanded ${driftResults.length} drift results into ${expanded.length} atomic artifacts`);
  return expanded;
}

module.exports = {
  normPath,
  normApi,
  getArtifactId,
  getPairKey,
  expandResults
};