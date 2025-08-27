// Code analysis correlation strategy
const CorrelationStrategy = require('../strategy-base');
const { getPairKey, getArtifactId } = require('../utils/artifacts');
const { analyzeChangedFiles, bfsSymbols, matchDbRefs } = require('../../code-analysis');

class CodeAnalysisStrategy extends CorrelationStrategy {
  constructor(config) {
    super('code', { budget: 'medium', ...config });
  }
  
  async run({ driftResults, files, config, processedPairs, candidatePairs }) {
    const correlations = [];
    
    try {
      // Analyze changed files to extract handlers, DB refs, and call graph
      const { handlers, dbRefs, calls } = await analyzeChangedFiles({ 
        files, 
        changedOnly: true, 
        depth: 2 
      });
      
      if (handlers.length === 0 || dbRefs.length === 0) {
        return correlations; // No correlations possible
      }
      
      // Index handlers by API result
      const handlersByApiId = this.indexHandlersAgainstApiResults(handlers, driftResults);
      
      // Index DB refs by table name
      const dbRefsByTable = this.indexDbRefsByTable(dbRefs);
      
      // Find correlations between API and database results
      const apiResults = driftResults.filter(r => r.type === 'api');
      const dbResults = driftResults.filter(r => r.type === 'database');
      
      for (const api of apiResults) {
        const apiId = getArtifactId(api);
        const matchingHandlers = handlersByApiId.get(apiId) || [];
        
        for (const handler of matchingHandlers) {
          // Trace shallow call graph from handler
          const reachableSymbols = bfsSymbols(handler, calls, 2);
          const reachableDbRefs = matchDbRefs(reachableSymbols, dbRefs);
          
          for (const db of dbResults) {
            const pairKey = getPairKey(api, db);
            
            // Skip if already processed
            if (processedPairs.has(pairKey)) continue;
            
            // Skip if not a candidate (respects budget gating)
            if (this.budget !== 'low' && candidatePairs && !candidatePairs.has(pairKey)) continue;
            
            // Find matching DB operations
            const tableName = this.extractTableFromDbResult(db);
            if (!tableName) continue;
            
            const matchingDbRefs = reachableDbRefs.filter(ref => 
              this.tablesMatch(ref.table, tableName)
            );
            
            if (matchingDbRefs.length === 0) continue;
            
            // Calculate confidence and build evidence
            const { confidence, evidence } = this.calculateConfidenceAndEvidence(
              handler, matchingDbRefs, reachableSymbols
            );
            
            correlations.push({
              source: api,
              target: db,
              relationship: 'api_uses_table',
              confidence,
              evidence: evidence.slice(0, 2) // Limit evidence for performance
            });
          }
        }
      }
      
    } catch (error) {
      // Log error but don't fail the entire correlation process
      console.warn('CodeAnalysisStrategy failed:', error.message);
    }
    
    return correlations;
  }
  
  // Index handlers against API drift results
  indexHandlersAgainstApiResults(handlers, driftResults) {
    const index = new Map();
    
    const apiResults = driftResults.filter(r => r.type === 'api');
    
    apiResults.forEach(api => {
      const apiId = getArtifactId(api);
      const matchingHandlers = [];
      
      // Extract API endpoints from result
      const endpoints = api.endpoints || [];
      
      endpoints.forEach(endpoint => {
        const { method, path } = this.parseEndpoint(endpoint);
        
        // Find handlers that match this endpoint
        handlers.forEach(handler => {
          if (this.endpointMatches(handler, method, path)) {
            matchingHandlers.push(handler);
          }
        });
      });
      
      if (matchingHandlers.length > 0) {
        index.set(apiId, matchingHandlers);
      }
    });
    
    return index;
  }
  
  // Index DB refs by table name for quick lookup
  indexDbRefsByTable(dbRefs) {
    const index = new Map();
    
    dbRefs.forEach(ref => {
      const table = ref.table.toLowerCase();
      if (!index.has(table)) index.set(table, []);
      index.get(table).push(ref);
    });
    
    return index;
  }
  
  // Extract table name from database drift result
  extractTableFromDbResult(dbResult) {
    if (dbResult.entities && dbResult.entities.length > 0) {
      return dbResult.entities[0].toLowerCase();
    }
    
    // Try to extract from changes
    if (dbResult.changes && dbResult.changes.length > 0) {
      const sqlContent = dbResult.changes.join(' ');
      const tableMatch = sqlContent.match(/(?:FROM|INTO|TABLE|UPDATE|ALTER)\s+[`"']?(\w+)[`"']?/i);
      if (tableMatch) {
        return tableMatch[1].toLowerCase();
      }
    }
    
    return null;
  }
  
  // Parse endpoint string into method and path
  parseEndpoint(endpoint) {
    const match = endpoint.match(/^(\w+):(.+)$/);
    if (match) {
      return { method: match[1].toUpperCase(), path: match[2] };
    }
    // Default to GET if no method specified
    return { method: 'GET', path: endpoint };
  }
  
  // Check if handler matches the API endpoint
  endpointMatches(handler, method, path) {
    // Exact method match
    if (handler.method !== method) return false;
    
    // Path matching with normalization
    const normalizedHandlerPath = this.normalizePath(handler.path);
    const normalizedApiPath = this.normalizePath(path);
    
    return normalizedHandlerPath === normalizedApiPath;
  }
  
  // Normalize API path for comparison
  normalizePath(path) {
    return path
      .toLowerCase()
      .replace(/\{[^}]+\}/g, '{id}') // Normalize path parameters
      .replace(/\/+/g, '/') // Remove duplicate slashes
      .replace(/\/$/, ''); // Remove trailing slash
  }
  
  // Check if table names match (with variations)
  tablesMatch(dbRefTable, resultTable) {
    const normalizedRef = dbRefTable.toLowerCase();
    const normalizedResult = resultTable.toLowerCase();
    
    // Exact match
    if (normalizedRef === normalizedResult) return true;
    
    // Plural/singular variations
    if (this.pluralize(normalizedRef) === normalizedResult) return true;
    if (normalizedRef === this.pluralize(normalizedResult)) return true;
    
    // Snake_case vs camelCase
    if (this.camelToSnake(normalizedRef) === normalizedResult) return true;
    if (normalizedRef === this.camelToSnake(normalizedResult)) return true;
    
    return false;
  }
  
  // Simple pluralization
  pluralize(word) {
    if (word.endsWith('y')) return word.slice(0, -1) + 'ies';
    if (word.endsWith('s') || word.endsWith('sh') || word.endsWith('ch')) return word + 'es';
    return word + 's';
  }
  
  // Convert camelCase to snake_case
  camelToSnake(str) {
    return str.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`).replace(/^_/, '');
  }
  
  // Calculate confidence score and build evidence
  calculateConfidenceAndEvidence(handler, matchingDbRefs, reachableSymbols) {
    let maxConfidence = 0;
    const evidence = [];
    
    matchingDbRefs.forEach(dbRef => {
      let confidence = 0;
      let reason = '';
      
      const handlerSymbol = `${handler.file}:${handler.symbol}`;
      const dbSymbol = `${dbRef.file}:${dbRef.symbol}`;
      
      if (handlerSymbol === dbSymbol) {
        // Same function - highest confidence
        confidence = 0.90;
        reason = `${dbRef.orm}.${dbRef.table}.${dbRef.op} called directly in ${handler.symbol}`;
      } else {
        // Different function - calculate hops
        const handlerIndex = reachableSymbols.indexOf(handlerSymbol);
        const dbIndex = reachableSymbols.indexOf(dbSymbol);
        
        if (handlerIndex !== -1 && dbIndex !== -1) {
          const hops = Math.abs(dbIndex - handlerIndex);
          if (hops === 1) {
            confidence = 0.80;
            reason = `${dbRef.orm}.${dbRef.table}.${dbRef.op} called 1 hop from ${handler.symbol}`;
          } else if (hops === 2) {
            confidence = 0.70;
            reason = `${dbRef.orm}.${dbRef.table}.${dbRef.op} called 2 hops from ${handler.symbol}`;
          }
        }
      }
      
      // Adjust confidence for ORM inference
      if (['prisma', 'sequelize', 'typeorm'].includes(dbRef.orm) && 
          dbRef.table !== handler.path.split('/').pop()) {
        confidence -= 0.05; // Small penalty for inferred table names
      }
      
      if (confidence > maxConfidence) {
        maxConfidence = confidence;
      }
      
      if (confidence > 0) {
        evidence.push({
          file: dbRef.file,
          line: dbRef.line,
          reason
        });
      }
    });
    
    return { confidence: maxConfidence, evidence };
  }
}

module.exports = CodeAnalysisStrategy;