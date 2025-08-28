// Safety and validation utilities for correlation processing

// Check if a pair involves critical changes that should not be ignored
function isCriticalPair(a, b) {
  const txt = (x) => (x?.changes || []).join(' ') + ' ' + JSON.stringify(x);
  const combined = txt(a) + ' ' + txt(b);
  
  // Destructive database operations
  const hasDbDestructive = /DROP\s+(TABLE|COLUMN)|TRUNCATE|ALTER\s+TABLE.*(SET\s+NOT\s+NULL|TYPE)/i.test(combined);
  
  // Security vulnerabilities
  const hasCve = /CVE-|GHSA-|SECURITY_VULNERABILITY|MALICIOUS_PACKAGE/i.test(combined);
  
  // Wide-open security groups
  const hasWideSg = /0\.0\.0\.0\/0|::\/0|SECURITY_GROUP_DELETION/i.test(combined);
  
  // Secret key changes
  const hasSecretChanges = /SECRET_KEY_REMOVED|SECRET_KEY_ADDED/i.test(combined);
  
  return hasDbDestructive || hasCve || hasWideSg || hasSecretChanges;
}

// Deduplicate evidence array by file:line entries
function dedupeEvidence(evidenceArray) {
  if (!Array.isArray(evidenceArray)) return [];
  
  const seen = new Set();
  const deduped = evidenceArray.filter(ev => {
    if (!ev || typeof ev !== 'object') return true; // Keep non-objects
    
    const key = hasFileLine(ev) ? `${ev.file}:${ev.line}` : JSON.stringify(ev);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  
  return deduped.length < evidenceArray.length ? deduped : evidenceArray;
}

// Clamp value to [0, 1] range
function clamp01(x) {
  if (!Number.isFinite(x)) return 0;
  return Math.max(0, Math.min(1, x));
}

// Check if evidence has file:line structure
function hasFileLine(evidence) {
  if (!evidence) return false;
  if (Array.isArray(evidence)) {
    return evidence.some(e => 
      e && typeof e !== 'string' && (e.file || e.line)
    );
  }
  return evidence && typeof evidence === 'object' && 
         (evidence.file || evidence.line);
}

module.exports = {
  isCriticalPair,
  dedupeEvidence,
  clamp01,
  hasFileLine
};