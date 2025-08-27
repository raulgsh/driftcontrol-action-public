// Temporal correlation strategy (disabled by default as it's noisy)
const CorrelationStrategy = require('../strategy-base');
const { getPairKey } = require('../utils/artifacts');

class TemporalCorrelationStrategy extends CorrelationStrategy {
  constructor(config) {
    super('temporal', config);
    this.enabled = config.enabled || false; // Disabled by default
  }
  
  async run({ driftResults, files, config, processedPairs, candidatePairs }) {
    const correlations = [];
    
    // Safe directory extraction
    const getDir = (p) => (p && p.includes('/')) ? p.slice(0, p.lastIndexOf('/')) : '';
    
    // Find drift results in the same directory
    for (let i = 0; i < driftResults.length; i++) {
      const result1 = driftResults[i];
      if (!result1.file) continue;
      
      const dir1 = getDir(result1.file);
      
      for (let j = i + 1; j < driftResults.length; j++) {
        const result2 = driftResults[j];
        if (!result2.file) continue;
        
        const pairKey = getPairKey(result1, result2);
        
        if (processedPairs.has(pairKey)) continue;
        if (this.budget !== 'low' && candidatePairs && !candidatePairs.has(pairKey)) continue;
        
        const dir2 = getDir(result2.file);
        
        if (dir1 === dir2) {
          correlations.push({
            source: result1,
            target: result2,
            relationship: 'temporal_correlation',
            confidence: 0.65,
            evidence: ['Files changed in the same directory']
          });
        }
      }
    }
    
    return correlations;
  }
}

module.exports = TemporalCorrelationStrategy;