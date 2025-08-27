const core = require('@actions/core');
const { Parser } = require('node-sql-parser');
const riskScorer = require('./risk-scorer');

class SqlAnalyzer {
  constructor() {
    this.riskScorer = riskScorer;
    this.parser = new Parser();
  }

  // Detect SQL dialect based on content heuristics
  detectSqlDialect(content) {
    // PostgreSQL indicators
    if (/\bRETURNING\s+\*|\bSERIAL\b|\:\:\w+|\bPG_/i.test(content)) {
      return 'PostgreSQL';
    }
    // MySQL indicators
    if (/\bAUTO_INCREMENT\b|\bFULLTEXT\b|\bENGINE\s*=\s*\w+/i.test(content)) {
      return 'MySQL';
    }
    // T-SQL/SQL Server indicators
    if (/\bGO\b\s*$|@@IDENTITY|\[dbo\]|\bNVARCHAR/im.test(content)) {
      return 'TransactSQL';
    }
    // SQLite indicators
    if (/\bAUTOINCREMENT\b|\bPRAGMA\b/i.test(content)) {
      return 'SQLite';
    }
    // Default to PostgreSQL as most common
    return 'PostgreSQL';
  }

  async analyzeSqlFiles(files, octokit, owner, repo, pullRequestHeadSha, sqlGlob) {
    const driftResults = [];
    let hasHighSeverity = false;
    let hasMediumSeverity = false;

    // Process files for drift detection - convert glob to proper regex
    // Transform glob patterns like "migrations/**/*.sql" to regex
    // Special case for common pattern: **/* means "any file in this dir or subdirs"
    let globRegexPattern;
    if (sqlGlob.includes('**/')) {
      // For patterns like "migrations/**/*.sql", match anything under migrations/
      const parts = sqlGlob.split('**/');
      const prefix = parts[0].replace(/\./g, '\\.');
      const suffix = parts[1]
        .replace(/\./g, '\\.')
        .replace(/\*/g, '[^/]*');
      // Match prefix, then any path (including no subdirs), then suffix
      globRegexPattern = `^${prefix}.*${suffix}$`;
    } else {
      // Fallback for other patterns
      globRegexPattern = sqlGlob
        .replace(/\./g, '\\.')
        .replace(/\*\*/g, '.*')
        .replace(/\*/g, '[^/]*')
        + '$';
    }
    const sqlPattern = new RegExp(globRegexPattern);
    
    // Check for SQL migration files in changed files
    const changedSqlFiles = files.filter(file => sqlPattern.test(file.filename));
    
    core.info(`SQL glob pattern: ${sqlGlob} -> regex: ${globRegexPattern}`);
    core.info(`Files checked: ${files.map(f => f.filename).join(', ')}`);
    core.info(`Matching SQL files: ${changedSqlFiles.map(f => f.filename).join(', ')}`);
    if (changedSqlFiles.length === 0) {
      return { driftResults, hasHighSeverity, hasMediumSeverity };
    }

    core.info(`Found ${changedSqlFiles.length} SQL migration files`);
    
    // Advanced SQL drift detection with smart rename detection and DML filtering
    
    // Collect all SQL file contents for cross-file analysis
    const sqlFileContents = new Map();
    
    for (const file of changedSqlFiles) {
      if (file.status === 'removed') continue; // Skip deleted files
      
      // Fetch file content for analysis
      try {
        const { data: fileData } = await octokit.rest.repos.getContent({
          owner,
          repo,
          path: file.filename,
          ref: pullRequestHeadSha
        });
        
        const content = Buffer.from(fileData.content, 'base64').toString();
        sqlFileContents.set(file.filename, content);
      } catch (fileError) {
        core.warning(`Could not analyze file ${file.filename}: ${fileError.message}`);
      }
    }
    
    // Perform advanced analysis on all collected SQL contents
    for (const [filename, content] of sqlFileContents) {
      let sqlChanges = [];
      
      // Filter out non-blocking DML operations (per CLAUDE.md:57)
      const dmlPatterns = [
        /INSERT\s+INTO/i,
        /UPDATE\s+\w+\s+SET/i,
        /DELETE\s+FROM/i
      ];
      
      const isDmlOnly = dmlPatterns.some(pattern => pattern.test(content)) && 
                       !content.match(/CREATE|ALTER|DROP|TRUNCATE/i);
      
      if (isDmlOnly) {
        core.info(`Skipping DML-only migration: ${filename}`);
        continue;
      }
      
      // Try to use AST-based parsing first
      try {
        sqlChanges = this.parseSqlWithAst(content, filename);
        core.info(`Successfully parsed ${filename} using SQL parser`);
      } catch (parseError) {
        // Fallback to regex-based parsing if AST parsing fails
        core.warning(`AST parsing failed for ${filename}: ${parseError.message}. Using fallback regex analysis.`);
        sqlChanges = this.fallbackRegexAnalysis(content, filename);
      }
      
      // Use centralized risk scorer for consistent severity assessment
      if (sqlChanges.length > 0) {
        const scoringResult = this.riskScorer.scoreChanges(sqlChanges, 'SQL');
        
        // Update global severity tracking
        if (scoringResult.severity === 'high') {
          hasHighSeverity = true;
        } else if (scoringResult.severity === 'medium') {
          hasMediumSeverity = true;
        }
        
        driftResults.push({
          type: 'database',
          file: filename,
          severity: scoringResult.severity,
          changes: sqlChanges,
          reasoning: scoringResult.reasoning,
          tablesAnalyzed: [...droppedTables, ...createdTables].length,
          // Add metadata for correlation
          entities: [...new Set([...droppedTables, ...createdTables])],
          operations: sqlChanges.map(c => c.split(':')[0].trim())
        });
      }
    }

    return { driftResults, hasHighSeverity, hasMediumSeverity };
  }

  // Parse SQL using AST for accurate analysis
  parseSqlWithAst(content, filename) {
    const sqlChanges = [];
    const dialect = this.detectSqlDialect(content);
    
    core.info(`Detected SQL dialect: ${dialect} for ${filename}`);
    
    // Parse SQL into AST
    const ast = this.parser.astify(content, { database: dialect });
    const statements = Array.isArray(ast) ? ast : [ast];
    
    const droppedTables = new Set();
    const createdTables = new Set();
    const droppedColumns = new Map();
    const addedColumns = new Map();
    
    // Analyze each statement
    for (const stmt of statements) {
      this.analyzeStatement(stmt, sqlChanges, droppedTables, createdTables, droppedColumns, addedColumns);
    }
    
    // Smart table rename detection (DROP+CREATE same table name)
    const renamedTables = new Set([...droppedTables].filter(table => createdTables.has(table.toLowerCase())));
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
    
    return sqlChanges;
  }

  // Analyze individual SQL statement from AST
  analyzeStatement(stmt, sqlChanges, droppedTables, createdTables, droppedColumns, addedColumns) {
    switch (stmt.type) {
      case 'drop':
        this.analyzeDropStatement(stmt, sqlChanges, droppedTables, droppedColumns);
        break;
      case 'create':
        this.analyzeCreateStatement(stmt, createdTables);
        break;
      case 'alter':
        this.analyzeAlterStatement(stmt, sqlChanges, droppedColumns, addedColumns);
        break;
      case 'truncate':
        const tableName = this.extractTableName(stmt);
        if (tableName) {
          sqlChanges.push(`TRUNCATE TABLE: ${tableName}`);
        }
        break;
    }
  }

  // Analyze DROP statements
  analyzeDropStatement(stmt, sqlChanges, droppedTables, droppedColumns) {
    const keyword = stmt.keyword?.toLowerCase();
    
    if (keyword === 'table') {
      const tableName = this.extractTableName(stmt);
      if (tableName) {
        droppedTables.add(tableName.toLowerCase());
        sqlChanges.push(`DROP TABLE: ${tableName}`);
        core.info(`Found DROP TABLE: ${tableName}`);
      }
    } else if (keyword === 'column' && stmt.column) {
      const columnName = stmt.column.column || stmt.column;
      const tableName = this.extractTableName(stmt);
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
  analyzeCreateStatement(stmt, createdTables) {
    const keyword = stmt.keyword?.toLowerCase();
    
    if (keyword === 'table') {
      const tableName = this.extractTableName(stmt);
      if (tableName) {
        createdTables.add(tableName.toLowerCase());
        core.info(`Found CREATE TABLE: ${tableName}`);
      }
    }
  }

  // Analyze ALTER statements
  analyzeAlterStatement(stmt, sqlChanges, droppedColumns, addedColumns) {
    const tableName = this.extractTableName(stmt);
    
    if (stmt.expr && Array.isArray(stmt.expr)) {
      for (const expr of stmt.expr) {
        const action = expr.action?.toLowerCase();
        
        if (action === 'drop') {
          const resource = expr.resource?.toLowerCase();
          if (resource === 'column' && expr.column) {
            const columnName = expr.column.column || expr.column;
            if (!droppedColumns.has(tableName)) droppedColumns.set(tableName, []);
            droppedColumns.get(tableName).push(columnName);
            sqlChanges.push(`DROP COLUMN: ${columnName}`);
          } else if (resource === 'constraint' && expr.name) {
            sqlChanges.push(`DROP CONSTRAINT: ${expr.name}`);
          }
        } else if (action === 'add') {
          const resource = expr.resource?.toLowerCase();
          if (resource === 'column' && expr.column) {
            const columnName = expr.column.column || expr.column.name || expr.column;
            if (!addedColumns.has(tableName)) addedColumns.set(tableName, []);
            addedColumns.get(tableName).push(columnName);
            
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

  // Extract table name from various statement types
  extractTableName(stmt) {
    if (stmt.table) {
      if (Array.isArray(stmt.table)) {
        return stmt.table[0]?.table || stmt.table[0]?.name || stmt.table[0];
      }
      return stmt.table.table || stmt.table.name || stmt.table;
    }
    if (stmt.name) {
      if (Array.isArray(stmt.name)) {
        return stmt.name[0]?.value || stmt.name[0];
      }
      return stmt.name.value || stmt.name;
    }
    return null;
  }

  // Fallback to regex-based analysis when AST parsing fails
  fallbackRegexAnalysis(content, filename) {
    const sqlChanges = [];
    
    // Check for destructive operations (HIGH severity) - improved regex to handle quoted identifiers
    const destructivePatterns = [
      { pattern: /DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([\w`"\[\]]+)/gi, type: 'DROP TABLE' },
      { pattern: /DROP\s+COLUMN\s+([\w`"\[\]]+)/gi, type: 'DROP COLUMN' },
      { pattern: /TRUNCATE\s+TABLE\s+([\w`"\[\]]+)/gi, type: 'TRUNCATE TABLE' },
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
          const tableMatch = beforeMatch.match(/ALTER\s+TABLE\s+([\w`"\[\]]+)/gi);
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
    const createTablePattern = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w`"\[\]]+)/gi;
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
      const tableMatch = beforeMatch.match(/ALTER\s+TABLE\s+([\w`"\[\]]+)/gi);
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
    
    // Check for type-narrowing operations
    const typeNarrowingPattern = /ALTER\s+COLUMN\s+([\w`"\[\]]+)\s+TYPE\s+(\w+)/gi;
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
}

module.exports = SqlAnalyzer;