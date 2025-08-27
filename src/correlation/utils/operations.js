// Operation detection and correlation utilities
const { generateEntityVariations, findBestMatch } = require('./text');

// Correlate fields between API and database
function correlateFields(apiFields, dbFields) {
  const correlations = [];
  
  apiFields.forEach(apiField => {
    const apiVariations = generateEntityVariations(apiField);
    
    dbFields.forEach(dbField => {
      const dbVariations = generateEntityVariations(dbField);
      const match = findBestMatch(apiVariations, dbVariations);
      
      if (match.confidence > 0.7) {
        correlations.push({
          type: 'field_match',
          apiField: apiField,
          dbField: dbField,
          confidence: match.confidence,
          reasoning: `API field '${apiField}' maps to database column '${dbField}'`
        });
      }
    });
  });
  
  return correlations;
}

// Detect API operations from path and result
function detectApiOperations(apiPath, apiResult) {
  const operations = new Set();
  
  // Check path patterns
  if (apiPath.match(/\/create|\/add|\/new/i)) operations.add('create');
  if (apiPath.match(/\/get|\/list|\/search|\/find/i)) operations.add('read');
  if (apiPath.match(/\/update|\/edit|\/modify/i)) operations.add('update');
  if (apiPath.match(/\/delete|\/remove/i)) operations.add('delete');
  
  // Check changes for operation keywords
  if (apiResult.changes) {
    apiResult.changes.forEach(change => {
      const upperChange = change.toUpperCase();
      if (upperChange.includes('POST') || upperChange.includes('CREATE')) operations.add('create');
      if (upperChange.includes('GET') || upperChange.includes('READ')) operations.add('read');
      if (upperChange.includes('PUT') || upperChange.includes('PATCH') || upperChange.includes('UPDATE')) operations.add('update');
      if (upperChange.includes('DELETE') || upperChange.includes('REMOVE')) operations.add('delete');
    });
  }
  
  return Array.from(operations);
}

// Detect database operations from SQL content
function detectDbOperations(dbContent) {
  const operations = new Set();
  const upperContent = dbContent.toUpperCase();
  
  if (upperContent.match(/CREATE\s+TABLE|INSERT\s+INTO/)) operations.add('create');
  if (upperContent.match(/SELECT\s+/)) operations.add('read');
  if (upperContent.match(/UPDATE\s+|ALTER\s+TABLE/)) operations.add('update');
  if (upperContent.match(/DELETE\s+FROM|DROP\s+TABLE|TRUNCATE/)) operations.add('delete');
  
  return Array.from(operations);
}

// Check if operations correlate
function operationsCorrelate(apiOps, dbOps) {
  if (apiOps.length === 0 || dbOps.length === 0) return false;
  
  // Check for any matching operations
  const intersection = apiOps.filter(op => dbOps.includes(op));
  return intersection.length > 0;
}

module.exports = {
  correlateFields,
  detectApiOperations,
  detectDbOperations,
  operationsCorrelate
};