// Dependency correlation strategy
const CorrelationStrategy = require('../strategy-base');
const { getPairKey } = require('../utils/artifacts');

class DependencyCorrelationStrategy extends CorrelationStrategy {
  constructor(config) {
    super('dependency', config);
  }
  
  async run({ driftResults, files, config, processedPairs, candidatePairs }) {
    const correlations = [];
    const packageChanges = driftResults.filter(r => 
      r.type === 'configuration' && r.file?.includes('package')
    );
    const apiChanges = driftResults.filter(r => r.type === 'api');
    const dbChanges = driftResults.filter(r => r.type === 'database');
    
    for (const pkg of packageChanges) {
      const pkgDeps = pkg.metadata?.dependencies || [];
      
      // Link package changes to API
      for (const api of apiChanges) {
        const pairKey = getPairKey(pkg, api);
        
        if (processedPairs.has(pairKey)) continue;
        if (this.budget !== 'low' && candidatePairs && !candidatePairs.has(pairKey)) continue;
        
        if (pkgDeps.length > 0) {
          const apiDeps = pkgDeps.filter(dep => {
            const depLower = dep.toLowerCase();
            return depLower.includes('express') || depLower.includes('fastify') || 
                   depLower.includes('koa') || depLower.includes('hapi') ||
                   depLower.includes('swagger') || depLower.includes('openapi');
          });
          
          if (apiDeps.length > 0) {
            correlations.push({
              source: pkg,
              target: api,
              relationship: 'dependency_affects_api',
              confidence: 0.8,
              evidence: [`API-related dependencies changed: ${apiDeps.join(', ')}`]
            });
          }
        }
      }
      
      // Link package changes to database
      for (const db of dbChanges) {
        const pairKey = getPairKey(pkg, db);
        
        if (processedPairs.has(pairKey)) continue;
        if (this.budget !== 'low' && candidatePairs && !candidatePairs.has(pairKey)) continue;
        
        if (pkgDeps.length > 0) {
          const dbDeps = pkgDeps.filter(dep => {
            const depLower = dep.toLowerCase();
            return depLower.includes('sequelize') || depLower.includes('typeorm') ||
                   depLower.includes('prisma') || depLower.includes('knex') ||
                   depLower.includes('mongoose') || depLower.includes('pg') ||
                   depLower.includes('mysql') || depLower.includes('sqlite');
          });
          
          if (dbDeps.length > 0) {
            correlations.push({
              source: pkg,
              target: db,
              relationship: 'dependency_affects_db',
              confidence: 0.8,
              evidence: [`Database-related dependencies changed: ${dbDeps.join(', ')}`]
            });
          }
        }
      }
    }
    
    return correlations;
  }
}

module.exports = DependencyCorrelationStrategy;