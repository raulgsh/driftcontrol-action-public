// Operation-based correlation strategy
const CorrelationStrategy = require('../strategy-base');
const { getPairKey } = require('../utils/artifacts');

class OperationCorrelationStrategy extends CorrelationStrategy {
  constructor(config) {
    super('operation', config);
  }
  
  async run({ driftResults, files, config, processedPairs, candidatePairs }) {
    const correlations = [];
    const apiChanges = driftResults.filter(r => r.type === 'api');
    const dbChanges = driftResults.filter(r => r.type === 'database');
    
    for (const api of apiChanges) {
      for (const db of dbChanges) {
        const pairKey = getPairKey(api, db);
        
        if (processedPairs.has(pairKey)) continue;
        if (this.budget !== 'low' && candidatePairs && !candidatePairs.has(pairKey)) continue;
        
        const apiOps = api.metadata?.operations || [];
        const dbOps = db.metadata?.operations || [];
        
        if (apiOps.length > 0 && dbOps.length > 0) {
          const matchingOps = apiOps.filter(op => dbOps.includes(op));
          if (matchingOps.length > 0) {
            const confidence = Math.min(0.9, 0.6 + (matchingOps.length * 0.1));
            correlations.push({
              source: api,
              target: db,
              relationship: 'operation_alignment',
              confidence: confidence,
              evidence: [`Aligned operations: ${matchingOps.join(', ')}`]
            });
          }
        }
      }
    }
    
    return correlations;
  }
}

module.exports = OperationCorrelationStrategy;