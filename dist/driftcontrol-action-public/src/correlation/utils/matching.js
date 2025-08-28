// Token matching and rule resolution utilities
const micromatch = require('micromatch');
const { getPairKey } = require('./artifacts');

// Shared token matcher for rule resolution
function matchToken(result, token) {
  if (!token) return false;
  const t = String(token).toLowerCase();
  
  const candidates = [
    result.file, result.table, result.name, result.resourceId,
    result.resourceType, result.artifactId,
    ...(result.endpoints || []),
    ...(result.entities || []),
    ...(result.resources || [])
  ].filter(Boolean).map(x => String(x).toLowerCase());
  
  // Check for glob pattern
  if (token.includes('*') || token.includes('?')) {
    return candidates.some(c => micromatch.isMatch(c, t));
  }
  
  // Exact or substring match
  return candidates.some(c => c === t || c.includes(t));
}

// Resolve token to actual artifacts
function resolveTokenToArtifacts(driftResults, token) {
  if (!token) return [];
  return driftResults.filter(r => matchToken(r, token));
}

// Resolve rule pairs to actual artifact pairs
function resolveRulePairsToArtifacts(driftResults, rules) {
  const pairs = new Set();
  
  (rules || []).forEach(rule => {
    if (!rule.source || !rule.target || rule.type === 'ignore') return; // Skip ignore rules
    
    const sources = resolveTokenToArtifacts(driftResults, rule.source);
    const targets = resolveTokenToArtifacts(driftResults, rule.target);
    
    sources.forEach(s => {
      targets.forEach(t => {
        if (s !== t) pairs.add(getPairKey(s, t));
      });
    });
  });
  
  return pairs;
}

module.exports = {
  matchToken,
  resolveTokenToArtifacts,
  resolveRulePairsToArtifacts
};