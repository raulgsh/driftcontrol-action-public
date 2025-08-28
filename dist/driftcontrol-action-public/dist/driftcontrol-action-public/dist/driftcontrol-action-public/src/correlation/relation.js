// Relation detection and root cause analysis utilities
const { extractMetadata, extractTableNamesWithConfidence } = require('./utils/extraction');
const { generateEntityVariations, findBestMatch } = require('./utils/text');
const { correlateFields, detectApiOperations, detectDbOperations, operationsCorrelate } = require('./utils/operations');

function detectRelation(apiResult, dbResult) {
  const correlations = [];
  
  // Extract relevant data from results
  const apiPath = apiResult.file || '';
  const apiEndpoints = apiResult.endpoints || [];
  const apiMetadata = apiResult.metadata || extractMetadata(apiResult, []);
  
  const dbContent = (dbResult.changes || []).join(' ');
  const dbEntities = dbResult.entities || [];
  const dbMetadata = dbResult.metadata || extractMetadata(dbResult, []);
  
  // 1. Entity-based correlation with semantic matching
  const pathSegments = apiPath.split('/').filter(s => s && !s.includes('{') && !s.includes(':'));
  const apiPathEntities = apiEndpoints.concat(pathSegments).filter(e => e && e.length > 2);
  
  // Extract table names with confidence scoring
  const tableNames = extractTableNamesWithConfidence(dbContent);
  const allDbEntities = [...new Set([...dbEntities, ...tableNames.map(t => t.name)])];
  
  // Match using singular/plural forms and common naming patterns
  apiPathEntities.forEach(apiEntity => {
    const apiVariations = generateEntityVariations(apiEntity);
    
    allDbEntities.forEach(dbEntity => {
      const dbVariations = generateEntityVariations(dbEntity);
      const match = findBestMatch(apiVariations, dbVariations);
      
      if (match.confidence > 0.6) {
        correlations.push({
          type: 'entity_match',
          apiEntity: apiEntity,
          dbTable: dbEntity,
          confidence: match.confidence,
          reasoning: `API entity '${apiEntity}' correlates with database table '${dbEntity}'`
        });
      }
    });
  });
  
  // 2. Field-level correlation
  if (apiMetadata.fields && apiMetadata.fields.length > 0 && dbMetadata.fields && dbMetadata.fields.length > 0) {
    const fieldMatches = correlateFields(apiMetadata.fields, dbMetadata.fields);
    correlations.push(...fieldMatches);
  }
  
  // 3. Operation correlation (CRUD mapping)
  const apiOperations = detectApiOperations(apiPath, apiResult);
  const dbOperations = detectDbOperations(dbContent);
  
  if (operationsCorrelate(apiOperations, dbOperations)) {
    correlations.push({
      type: 'operation_match',
      confidence: 0.8,
      reasoning: 'API and database operations are aligned (CRUD pattern match)'
    });
  }
  
  // Return highest confidence correlation
  if (correlations.length > 0) {
    correlations.sort((a, b) => b.confidence - a.confidence);
    return correlations[0].confidence > 0.6; // Only return true for high-confidence matches
  }
  
  return false;
}

function identifyRootCauses(correlations, driftResults) {
  const rootCauses = [];
  
  // Find nodes with only outgoing edges (potential root causes)
  const incomingCount = new Map();
  const outgoingCount = new Map();
  
  driftResults.forEach(r => {
    incomingCount.set(r, 0);
    outgoingCount.set(r, 0);
  });
  
  correlations.forEach(c => {
    incomingCount.set(c.target, (incomingCount.get(c.target) || 0) + 1);
    outgoingCount.set(c.source, (outgoingCount.get(c.source) || 0) + 1);
  });
  
  // A root cause has outgoing edges but no incoming edges
  driftResults.forEach(result => {
    const incoming = incomingCount.get(result) || 0;
    const outgoing = outgoingCount.get(result) || 0;
    
    if (incoming === 0 && outgoing > 0) {
      rootCauses.push({
        result,
        type: 'root_cause',
        confidence: Math.min(0.9, 0.6 + (outgoing * 0.1)) // Higher confidence with more impacts
      });
    }
  });
  
  // If no clear root causes found, identify nodes with highest impact
  if (rootCauses.length === 0 && correlations.length > 0) {
    const impactScores = new Map();
    
    driftResults.forEach(result => {
      const outgoing = outgoingCount.get(result) || 0;
      const incoming = incomingCount.get(result) || 0;
      const score = outgoing - (incoming * 0.5); // Favor nodes with more outgoing than incoming
      impactScores.set(result, score);
    });
    
    // Find the highest impact node
    let maxScore = -1;
    let maxResult = null;
    
    impactScores.forEach((score, result) => {
      if (score > maxScore) {
        maxScore = score;
        maxResult = result;
      }
    });
    
    if (maxResult && maxScore > 0) {
      rootCauses.push({
        result: maxResult,
        type: 'likely_root_cause',
        confidence: Math.min(0.7, 0.4 + (maxScore * 0.1))
      });
    }
  }
  
  return rootCauses;
}

module.exports = {
  detectRelation,
  identifyRootCauses
};