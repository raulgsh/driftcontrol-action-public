// Infrastructure correlation strategy
const CorrelationStrategy = require('../strategy-base');
const { getPairKey } = require('../utils/artifacts');
const { generateEntityVariations, findBestMatch } = require('../utils/text');

class InfrastructureCorrelationStrategy extends CorrelationStrategy {
  constructor(config) {
    super('infrastructure', config);
    this.budget = config.budget || 'medium';
  }
  
  async run({ driftResults, files, config, processedPairs, candidatePairs }) {
    const correlations = [];
    const iacChanges = driftResults.filter(r => r.type === 'infrastructure');
    const configChanges = driftResults.filter(r => r.type === 'configuration');
    const apiChanges = driftResults.filter(r => r.type === 'api');
    
    // Infrastructure to configuration
    for (const iac of iacChanges) {
      for (const cfg of configChanges) {
        const pairKey = getPairKey(iac, cfg);
        
        if (processedPairs.has(pairKey)) continue;
        if (this.budget !== 'low' && candidatePairs && !candidatePairs.has(pairKey)) continue;
        
        if ((iac.file?.includes('terraform') || iac.file?.includes('cloudformation')) && 
            (cfg.file?.includes('env') || cfg.file?.includes('config'))) {
          correlations.push({
            source: iac,
            target: cfg,
            relationship: 'infra_affects_config',
            confidence: 0.7,
            evidence: ['Infrastructure change may affect application configuration']
          });
        }
        
        // Check for resource dependencies
        if (iac.resources && cfg.dependencies) {
          const sharedResources = [];
          iac.resources.forEach(resource => {
            cfg.dependencies.forEach(dep => {
              const resourceVars = generateEntityVariations(resource);
              const depVars = generateEntityVariations(dep);
              const match = findBestMatch(resourceVars, depVars);
              if (match.confidence > 0.7) {
                sharedResources.push(resource);
              }
            });
          });
          
          if (sharedResources.length > 0) {
            correlations.push({
              source: iac,
              target: cfg,
              relationship: 'resource_dependency',
              confidence: 0.75,
              evidence: [`Shared resources: ${sharedResources.join(', ')}`]
            });
          }
        }
      }
      
      // Infrastructure to API
      for (const api of apiChanges) {
        const pairKey = getPairKey(iac, api);
        
        if (processedPairs.has(pairKey)) continue;
        if (this.budget !== 'low' && candidatePairs && !candidatePairs.has(pairKey)) continue;
        
        if (iac.resources) {
          const apiRelatedTerms = ['api', 'gateway', 'function', 'lambda', 'endpoint', 'service'];
          const isApiInfra = iac.resources.some(r => {
            const rLower = r.toLowerCase();
            return apiRelatedTerms.some(term => rLower.includes(term));
          });
          
          if (isApiInfra) {
            correlations.push({
              source: iac,
              target: api,
              relationship: 'infra_hosts_api',
              confidence: 0.75,
              evidence: ['Infrastructure changes affect API deployment']
            });
          }
        }
      }
    }
    
    return correlations;
  }
}

module.exports = InfrastructureCorrelationStrategy;