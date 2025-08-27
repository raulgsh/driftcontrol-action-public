const core = require('@actions/core');

/**
 * SQL Utilities - helper functions for table/column name extraction
 */

// Extract table name from various statement types
function extractTableName(stmt) {
  let nameNode = null;
  
  // Extract the node from either table or name property
  if (stmt.table) {
    nameNode = Array.isArray(stmt.table) ? stmt.table[0] : stmt.table;
  } else if (stmt.name) {
    nameNode = Array.isArray(stmt.name) ? stmt.name[0] : stmt.name;
  }
  
  if (!nameNode) {
    return null;
  }
  
  // Handle schema-qualified names (e.g., public.users or dbo.customers)
  let schemaName = null;
  let tableName = null;
  
  // Check for schema/database qualifier
  if (typeof nameNode === 'object' && nameNode !== null) {
    schemaName = nameNode.db || nameNode.schema;
    tableName = nameNode.table || nameNode.name || nameNode.value;
  } else if (typeof nameNode === 'string') {
    tableName = nameNode;
  }
  
  // Build fully qualified name if schema is present
  if (schemaName && tableName) {
    return `${schemaName}.${tableName}`;
  } else if (typeof tableName === 'string') {
    return tableName;
  }
  
  // Prevent returning objects
  core.debug(`extractTableName: Could not extract string from node: ${JSON.stringify(nameNode)}`);
  return null;
}

// Extract column name from various statement types (similar defensive approach as extractTableName)
function extractColumnName(column) {
  if (!column) {
    return null;
  }
  
  // Handle different column structures from the AST
  let columnName = null;
  
  // Try various property paths
  if (typeof column === 'string') {
    columnName = column;
  } else if (typeof column === 'object') {
    // If this is a column_ref type, extract the column property first
    if (column.type === 'column_ref' && column.column) {
      return extractColumnName(column.column);
    }
    
    // Check direct properties first
    columnName = column.column || column.name || column.value;
    
    // Handle nested expr.value structure (for DROP COLUMN in some dialects)
    if (!columnName && column.expr && column.expr.value) {
      columnName = column.expr.value;
    }
    
    // Handle case where column.column is itself an object
    if (!columnName && column.column && typeof column.column === 'object') {
      columnName = column.column.expr?.value || column.column.value;
    }
  }
  
  // Return only if it's a string
  if (typeof columnName === 'string') {
    return columnName;
  }
  
  // Prevent returning objects
  core.debug(`extractColumnName: Could not extract string from column: ${JSON.stringify(column)}`);
  return null;
}

module.exports = {
  extractTableName,
  extractColumnName
};