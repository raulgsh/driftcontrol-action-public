// Metadata extraction utilities from drift results

// Extract metadata with confidence scoring
function extractMetadata(result, files) {
  const metadata = {
    entities: [],
    operations: [],
    fields: [],
    dependencies: []
  };
  
  if (result.type === 'api') {
    // Extract API entities from paths and endpoints
    if (result.file) {
      const pathParts = result.file.split('/').filter(p => p && !p.includes('.'));
      metadata.entities.push(...pathParts);
    }
    if (result.endpoints) {
      metadata.entities.push(...result.endpoints.map(e => e.replace(/^\//g, '').split('/')[0]).filter(e => e));
    }
    
    // Extract operations from API changes
    if (result.changes) {
      result.changes.forEach(change => {
        if (change.includes('POST') || change.includes('CREATE')) metadata.operations.push('create');
        if (change.includes('GET') || change.includes('read')) metadata.operations.push('read');
        if (change.includes('PUT') || change.includes('PATCH') || change.includes('UPDATE')) metadata.operations.push('update');
        if (change.includes('DELETE')) metadata.operations.push('delete');
      });
    }
  } else if (result.type === 'database') {
    // Extract database entities
    if (result.entities) {
      metadata.entities.push(...result.entities);
    }
    
    // Extract table names from SQL content
    if (result.changes) {
      const sqlContent = result.changes.join(' ');
      const tables = extractTableNamesWithConfidence(sqlContent);
      metadata.entities.push(...tables.map(t => t.name));
      
      // Extract operations
      if (sqlContent.match(/CREATE\s+TABLE/i)) metadata.operations.push('create');
      if (sqlContent.match(/SELECT/i)) metadata.operations.push('read');
      if (sqlContent.match(/UPDATE|ALTER/i)) metadata.operations.push('update');
      if (sqlContent.match(/DELETE|DROP/i)) metadata.operations.push('delete');
    }
  } else if (result.type === 'configuration') {
    // Extract dependencies from package changes
    if (result.changes) {
      result.changes.forEach(change => {
        const depMatch = change.match(/DEPENDENCY:\s*(\S+)/);
        if (depMatch) metadata.dependencies.push(depMatch[1]);
      });
    }
  }
  
  // Remove duplicates
  metadata.entities = [...new Set(metadata.entities)];
  metadata.operations = [...new Set(metadata.operations)];
  metadata.fields = [...new Set(metadata.fields)];
  metadata.dependencies = [...new Set(metadata.dependencies)];
  
  return metadata;
}

// Extract table names with confidence scoring
function extractTableNamesWithConfidence(sqlContent) {
  const tables = new Map();
  const patterns = [
    { regex: /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"']?(\w+)[`"']?/gi, confidence: 1.0 },
    { regex: /ALTER\s+TABLE\s+[`"']?(\w+)[`"']?/gi, confidence: 0.9 },
    { regex: /DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?[`"']?(\w+)[`"']?/gi, confidence: 1.0 },
    { regex: /UPDATE\s+[`"']?(\w+)[`"']?\s+SET/gi, confidence: 0.8 },
    { regex: /INSERT\s+INTO\s+[`"']?(\w+)[`"']?/gi, confidence: 0.8 },
    { regex: /DELETE\s+FROM\s+[`"']?(\w+)[`"']?/gi, confidence: 0.8 },
    { regex: /FROM\s+[`"']?(\w+)[`"']?/gi, confidence: 0.7 },
    { regex: /JOIN\s+[`"']?(\w+)[`"']?/gi, confidence: 0.7 }
  ];
  
  patterns.forEach(pattern => {
    let match;
    while ((match = pattern.regex.exec(sqlContent)) !== null) {
      const tableName = match[1].toLowerCase();
      // Skip common SQL keywords that might be captured
      if (['select', 'from', 'where', 'and', 'or', 'as', 'on', 'set'].includes(tableName)) continue;
      
      const existing = tables.get(tableName);
      if (!existing || existing.confidence < pattern.confidence) {
        tables.set(tableName, { name: tableName, confidence: pattern.confidence });
      }
    }
  });
  
  return Array.from(tables.values());
}

module.exports = {
  extractMetadata,
  extractTableNamesWithConfidence
};