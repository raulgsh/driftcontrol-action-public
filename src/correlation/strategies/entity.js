// Entity-based correlation strategy
const CorrelationStrategy = require('../strategy-base');
const { getPairKey } = require('../utils/artifacts');
const { generateEntityVariations, findBestMatch } = require('../utils/text');
const { detectRelation } = require('../relation');

class EntityCorrelationStrategy extends CorrelationStrategy {
  constructor(config) {
    super('entity', config);
  }
  
  async run({ driftResults, files, config, processedPairs, candidatePairs }) {
    const correlations = [];
    const apiChanges = driftResults.filter(r => r.type === 'api');
    const dbChanges = driftResults.filter(r => r.type === 'database');
    
    for (const api of apiChanges) {
      for (const db of dbChanges) {
        const pairKey = getPairKey(api, db);
        
        // Skip if processed
        if (processedPairs.has(pairKey)) continue;
        
        // Skip if not a candidate (for medium/high cost strategies)
        if (this.budget !== 'low' && candidatePairs && !candidatePairs.has(pairKey)) continue;
        
        // Use detectRelation for sophisticated matching
        if (detectRelation(api, db)) {
          const apiEntities = api.metadata?.entities || [];
          const dbEntities = db.metadata?.entities || [];
          
          let bestMatch = { confidence: 0 };
          apiEntities.forEach(apiEntity => {
            dbEntities.forEach(dbEntity => {
              const apiVars = generateEntityVariations(apiEntity);
              const dbVars = generateEntityVariations(dbEntity);
              const match = findBestMatch(apiVars, dbVars);
              if (match.confidence > bestMatch.confidence) {
                bestMatch = { ...match, apiEntity, dbEntity };
              }
            });
          });
          
          if (bestMatch.confidence > 0.6) {
            correlations.push({
              source: api,
              target: db,
              relationship: 'api_uses_table',
              confidence: bestMatch.confidence,
              evidence: [`API entity '${bestMatch.apiEntity}' correlates with table '${bestMatch.dbEntity}'`]
            });
          }
        }
      }
    }
    
    return correlations;
  }
}

module.exports = EntityCorrelationStrategy;