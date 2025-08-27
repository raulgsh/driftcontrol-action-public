const core = require('@actions/core');
const { Parser } = require('node-sql-parser');
const { splitQuery, mysqlSplitterOptions, postgreSplitterOptions, mssqlSplitterOptions } = require('dbgate-query-splitter');
const { detectSqlDialect } = require('./classify');
const { extractTableName, extractColumnName } = require('./utils');

/**
 * SQL Parsing utilities - AST-based and fallback regex parsing
 */

// Map our dialect detection to dbgate splitter options
function getSplitterOptions(dialect) {
  switch (dialect?.toLowerCase()) {
    case 'mysql':
    case 'mariadb':
      return mysqlSplitterOptions;
    case 'postgresql':
    case 'postgres':
      return postgreSplitterOptions;
    case 'mssql':
    case 'transactsql':
      return mssqlSplitterOptions;
    default:
      return mysqlSplitterOptions; // Safe default
  }
}

// Parse SQL file using two-phase approach: full-file AST then statement-by-statement with robust splitting
function parseSqlFile(content, filename) {
  const parser = new Parser();
  const dialect = detectSqlDialect(content);
  
  core.info(`Detected SQL dialect: ${dialect} for ${filename}`);
  
  const droppedTables = new Set();
  const createdTables = new Set();
  const droppedColumns = new Map();
  const addedColumns = new Map();
  const sqlChanges = [];
  
  // PHASE 1: Try to parse entire file at once (most efficient)
  try {
    const ast = parser.astify(content, { database: dialect });
    const allStatements = Array.isArray(ast) ? ast : [ast];
    core.info(`Successfully parsed all ${allStatements.length} statements in ${filename} using full-file AST mode`);
    
    for (const stmt of allStatements) {
      analyzeStatement(stmt, sqlChanges, droppedTables, createdTables, droppedColumns, addedColumns);
    }
  } catch (fullFileParseError) {
    // PHASE 2: Fall back to statement-by-statement parsing
    core.warning(`Full-file AST parsing failed for ${filename}: ${fullFileParseError.message}. Using resilient statement-by-statement mode`);
    
    // Use dbgate-query-splitter for robust splitting
    const splitterOptions = getSplitterOptions(dialect);
    const statements = splitQuery(content, splitterOptions);
    
    for (const statementText of statements) {
      if (!statementText || statementText.trim().length === 0) continue;
      
      try {
        // Try AST parsing for individual statement
        const ast = parser.astify(statementText, { database: dialect });
        const parsedStatements = Array.isArray(ast) ? ast : [ast];
        
        for (const stmt of parsedStatements) {
          analyzeStatement(stmt, sqlChanges, droppedTables, createdTables, droppedColumns, addedColumns);
        }
      } catch (singleStatementParseError) {
        // Final fallback: regex analysis for this statement
        core.warning(`AST parsing failed for statement in ${filename}. Reverting to regex for: "${statementText.substring(0, 70)}..."`);
        const regexChanges = fallbackRegexAnalysis(statementText, filename);
        sqlChanges.push(...regexChanges);

        // CRITICAL FIX: Extract entities from failed statement for correlation engine
        const entities = extractEntitiesFromContent(statementText);
        for (const entity of entities) {
          const entityLower = entity.toLowerCase();
          // Intelligently categorize based on SQL keywords
          const upperStatement = statementText.toUpperCase();
          
          if (upperStatement.includes('DROP TABLE') && upperStatement.includes(entity.toUpperCase())) {
            droppedTables.add(entityLower);
          } else if (upperStatement.includes('CREATE TABLE') && upperStatement.includes(entity.toUpperCase())) {
            createdTables.add(entityLower);
          } else {
            // Default to createdTables to ensure entity isn't lost
            createdTables.add(entityLower);
          }
        }
      }
    }
  }
  
  // Smart table rename detection (DROP+CREATE same table name)
  const renamedTables = new Set([...droppedTables].filter(table => {
    // Ensure we're comparing strings properly
    const tableLower = typeof table === 'string' ? table.toLowerCase() : String(table).toLowerCase();
    return createdTables.has(tableLower);
  }));
  for (const table of renamedTables) {
    // Remove from high-severity drops if it's a rename
    const dropIndex = sqlChanges.findIndex(change => change.includes(`DROP TABLE: ${table}`));
    if (dropIndex !== -1) {
      sqlChanges.splice(dropIndex, 1);
    }
    sqlChanges.push(`TABLE RENAME: ${table} (schema change)`);
  }
  
  // Column rename heuristics
  for (const [tableName, dropped] of droppedColumns) {
    const added = addedColumns.get(tableName) || [];
    const netLoss = dropped.length - added.length;
    
    if (netLoss > 0) {
      sqlChanges.push(`COLUMN LOSS: ${tableName} (net -${netLoss} columns)`);
    } else if (dropped.length > 0 && added.length > 0) {
      sqlChanges.push(`COLUMN RENAME: ${tableName} (${dropped.length} dropped, ${added.length} added)`);
    }
  }
  
  // Compute entities from union of dropped/created tables (normalize to strings, non-empty)
  const entities = [...new Set([...droppedTables, ...createdTables])]
    .map(t => typeof t === 'string' ? t : String(t))
    .filter(t => t && t.length > 0);
  
  return { sqlChanges, entities };
}

// Analyze individual SQL statement from AST
function analyzeStatement(stmt, sqlChanges, droppedTables, createdTables, droppedColumns, addedColumns) {
  switch (stmt.type) {
    case 'drop':
      analyzeDropStatement(stmt, sqlChanges, droppedTables, droppedColumns);
      break;
    case 'create':
      analyzeCreateStatement(stmt, createdTables);
      break;
    case 'alter':
      analyzeAlterStatement(stmt, sqlChanges, droppedColumns, addedColumns);
      break;
    case 'truncate':
      const tableName = extractTableName(stmt);
      if (tableName) {
        sqlChanges.push(`TRUNCATE TABLE: ${tableName}`);
      }
      break;
  }
}

// Analyze DROP statements
function analyzeDropStatement(stmt, sqlChanges, droppedTables, droppedColumns) {
  const keyword = stmt.keyword?.toLowerCase();
  
  if (keyword === 'table') {
    const tableName = extractTableName(stmt);
    if (tableName) {
      droppedTables.add(tableName.toLowerCase());
      sqlChanges.push(`DROP TABLE: ${tableName}`);
      core.info(`Found DROP TABLE: ${tableName}`);
    }
  } else if (keyword === 'column' && stmt.column) {
    const columnName = extractColumnName(stmt.column);
    const tableName = extractTableName(stmt);
    if (tableName && columnName) {
      if (!droppedColumns.has(tableName)) droppedColumns.set(tableName, []);
      droppedColumns.get(tableName).push(columnName);
      sqlChanges.push(`DROP COLUMN: ${columnName}`);
      core.info(`Found DROP COLUMN: ${columnName} from table ${tableName}`);
    }
  } else if (keyword === 'constraint' && stmt.name) {
    sqlChanges.push(`DROP CONSTRAINT: ${stmt.name}`);
  }
}

// Analyze CREATE statements
function analyzeCreateStatement(stmt, createdTables) {
  const keyword = stmt.keyword?.toLowerCase();
  
  if (keyword === 'table') {
    const tableName = extractTableName(stmt);
    if (tableName) {
      createdTables.add(tableName.toLowerCase());
      core.info(`Found CREATE TABLE: ${tableName}`);
    }
  }
}

// Analyze ALTER statements
function analyzeAlterStatement(stmt, sqlChanges, droppedColumns, addedColumns) {
  const tableName = extractTableName(stmt);
  
  if (stmt.expr && Array.isArray(stmt.expr)) {
    for (const expr of stmt.expr) {
      const action = expr.action?.toLowerCase();
      
      if (action === 'drop') {
        const resource = expr.resource?.toLowerCase();
        if (resource === 'column' && expr.column) {
          const columnName = extractColumnName(expr.column);
          if (columnName) {
            if (tableName) {
              if (!droppedColumns.has(tableName)) droppedColumns.set(tableName, []);
              droppedColumns.get(tableName).push(columnName);
            }
            sqlChanges.push(`DROP COLUMN: ${columnName}`);
          }
        } else if (resource === 'constraint' && expr.name) {
          sqlChanges.push(`DROP CONSTRAINT: ${expr.name}`);
        }
      } else if (action === 'add') {
        const resource = expr.resource?.toLowerCase();
        if (resource === 'column' && expr.column) {
          const columnName = extractColumnName(expr.column);
          if (columnName && tableName) {
            if (!addedColumns.has(tableName)) addedColumns.set(tableName, []);
            addedColumns.get(tableName).push(columnName);
          }
          
          // Check for NOT NULL constraint
          if (expr.column.nullable === false || expr.column.not_null) {
            sqlChanges.push('NOT NULL constraint added');
          }
        } else if (resource === 'constraint') {
          if (expr.constraint_type === 'not null') {
            sqlChanges.push('NOT NULL constraint added');
          }
        }
      } else if (action === 'modify' || action === 'alter') {
        if (expr.column && expr.dataType) {
          const columnName = expr.column.column || expr.column;
          const newType = expr.dataType;
          sqlChanges.push(`TYPE NARROWING: ${columnName} -> ${newType}`);
        }
      }
    }
  }
}

// Fallback to regex-based analysis when AST parsing fails
function fallbackRegexAnalysis(content, filename) {
  const sqlChanges = [];
  
  // Check for destructive operations (HIGH severity) - improved regex to handle quoted identifiers
  const destructivePatterns = [
    { pattern: /DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?((?:[\w`"\[\]]+\.)?[\w`"\[\]]+)/gi, type: 'DROP TABLE' },
    { pattern: /DROP\s+COLUMN\s+([\w`"\[\]]+)/gi, type: 'DROP COLUMN' },
    { pattern: /TRUNCATE\s+TABLE\s+((?:[\w`"\[\]]+\.)?[\w`"\[\]]+)/gi, type: 'TRUNCATE TABLE' },
    { pattern: /DROP\s+CONSTRAINT\s+([\w`"\[\]]+)/gi, type: 'DROP CONSTRAINT' }
  ];
  
  const droppedTables = new Set();
  const createdTables = new Set();
  const droppedColumns = new Map();
  const addedColumns = new Map();
  
  // Analyze destructive operations
  for (const { pattern, type } of destructivePatterns) {
    let match;
    pattern.lastIndex = 0; // Reset regex
    while ((match = pattern.exec(content)) !== null) {
      const objectName = match[1].replace(/[`"\[\]]/g, ''); // Clean quotes
      core.info(`Fallback found ${type}: ${objectName} in ${filename}`);
      
      if (type === 'DROP TABLE') {
        droppedTables.add(objectName.toLowerCase());
      } else if (type === 'DROP COLUMN') {
        // Extract table name from context
        const beforeMatch = content.substring(0, match.index);
        const tableMatch = beforeMatch.match(/ALTER\s+TABLE\s+((?:[\w`"\[\]]+\.)?[\w`"\[\]]+)/gi);
        if (tableMatch) {
          const tableName = tableMatch[tableMatch.length - 1].split(/\s+/)[2].replace(/[`"\[\]]/g, '');
          if (!droppedColumns.has(tableName)) droppedColumns.set(tableName, []);
          droppedColumns.get(tableName).push(objectName);
          core.info(`Fallback mapped DROP COLUMN ${objectName} to table ${tableName}`);
        }
      }
      
      sqlChanges.push(`${type}: ${objectName}`);
    }
  }
  
  // Check for table creations
  const createTablePattern = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?((?:[\w`"\[\]]+\.)?[\w`"\[\]]+)/gi;
  let match;
  while ((match = createTablePattern.exec(content)) !== null) {
    const tableName = match[1].replace(/[`"\[\]]/g, '');
    createdTables.add(tableName.toLowerCase());
  }
  
  // Smart table rename detection
  const renamedTables = new Set([...droppedTables].filter(table => createdTables.has(table)));
  for (const table of renamedTables) {
    const dropIndex = sqlChanges.findIndex(change => change.includes(`DROP TABLE: ${table}`));
    if (dropIndex !== -1) {
      sqlChanges.splice(dropIndex, 1);
    }
    sqlChanges.push(`TABLE RENAME: ${table} (schema change)`);
  }
  
  // Check for column operations
  const addColumnPattern = /ADD\s+(?:COLUMN\s+)?([\w`"\[\]]+)/gi;
  while ((match = addColumnPattern.exec(content)) !== null) {
    const beforeMatch = content.substring(0, match.index);
    const tableMatch = beforeMatch.match(/ALTER\s+TABLE\s+((?:[\w`"\[\]]+\.)?[\w`"\[\]]+)/gi);
    if (tableMatch) {
      const tableName = tableMatch[tableMatch.length - 1].split(/\s+/)[2].replace(/[`"\[\]]/g, '');
      const columnName = match[1].replace(/[`"\[\]]/g, '');
      if (!addedColumns.has(tableName)) addedColumns.set(tableName, []);
      addedColumns.get(tableName).push(columnName);
    }
  }
  
  // Column rename heuristics
  for (const [tableName, dropped] of droppedColumns) {
    const added = addedColumns.get(tableName) || [];
    const netLoss = dropped.length - added.length;
    
    if (netLoss > 0) {
      sqlChanges.push(`COLUMN LOSS: ${tableName} (net -${netLoss} columns)`);
    } else if (dropped.length > 0 && added.length > 0) {
      sqlChanges.push(`COLUMN RENAME: ${tableName} (${dropped.length} dropped, ${added.length} added)`);
    }
  }
  
  // Check for type-narrowing operations (PostgreSQL syntax)
  const typeNarrowingPattern = /ALTER\s+(?:TABLE\s+(?:[\w`"\[\]]+\.)?[\w`"\[\]]+\s+ALTER\s+)?COLUMN\s+([\w`"\[\]]+)\s+TYPE\s+(\w+)/gi;
  while ((match = typeNarrowingPattern.exec(content)) !== null) {
    const columnName = match[1].replace(/[`"\[\]]/g, '');
    sqlChanges.push(`TYPE NARROWING: ${columnName} -> ${match[2]}`);
  }
  
  // Check for NOT NULL constraints
  const notNullPatterns = [
    /ALTER\s+COLUMN\s+\w+\s+SET\s+NOT\s+NULL/gi,
    /ADD\s+CONSTRAINT\s+\w+\s+NOT\s+NULL/gi,
    /\w+\s+\w+\s+NOT\s+NULL/gi
  ];
  
  for (const pattern of notNullPatterns) {
    if (pattern.test(content)) {
      sqlChanges.push('NOT NULL constraint added');
      break;
    }
  }
  
  return sqlChanges;
}

// Extract entities from SQL content using regex (fallback method)
function extractEntitiesFromContent(content) {
  const entities = new Set();
  const patterns = [
    /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"'\[]?((?:\w+\.)?[\w]+)[`"'\]]?/gi,
    /ALTER\s+TABLE\s+[`"'\[]?((?:\w+\.)?[\w]+)[`"'\]]?/gi,
    /DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?[`"'\[]?((?:\w+\.)?[\w]+)[`"'\]]?/gi,
    /FROM\s+[`"'\[]?((?:\w+\.)?[\w]+)[`"'\]]?/gi,
    /JOIN\s+[`"'\[]?((?:\w+\.)?[\w]+)[`"'\]]?/gi,
    /UPDATE\s+[`"'\[]?((?:\w+\.)?[\w]+)[`"'\]]?/gi,
    /INSERT\s+INTO\s+[`"'\[]?((?:\w+\.)?[\w]+)[`"'\]]?/gi
  ];
  
  patterns.forEach(pattern => {
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const tableName = match[1].toLowerCase();
      // Skip common SQL keywords
      if (!['select', 'from', 'where', 'and', 'or', 'as', 'on', 'set'].includes(tableName)) {
        entities.add(tableName);
      }
    }
  });
  
  return Array.from(entities);
}

module.exports = {
  parseSqlFile,
  fallbackRegexAnalysis,
  extractEntitiesFromContent
};