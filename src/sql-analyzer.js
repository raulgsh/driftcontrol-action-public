const core = require('@actions/core');
const riskScorer = require('./risk-scorer');

class SqlAnalyzer {
  constructor() {
    this.riskScorer = riskScorer;
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
      const sqlChanges = [];
      
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
      
      // Check for destructive operations (HIGH severity)
      const destructivePatterns = [
        { pattern: /DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(\w+)/gi, type: 'DROP TABLE' },
        { pattern: /DROP\s+COLUMN\s+(\w+)/gi, type: 'DROP COLUMN' },
        { pattern: /TRUNCATE\s+TABLE\s+(\w+)/gi, type: 'TRUNCATE TABLE' },
        { pattern: /DROP\s+CONSTRAINT\s+(\w+)/gi, type: 'DROP CONSTRAINT' }
      ];
      
      const droppedTables = new Set();
      const createdTables = new Set();
      const droppedColumns = new Map(); // table -> columns[]
      const addedColumns = new Map(); // table -> columns[]
      
      // Analyze destructive operations
      for (const { pattern, type } of destructivePatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const objectName = match[1];
          core.info(`Found ${type}: ${objectName} in ${filename}`);
          
          if (type === 'DROP TABLE') {
            droppedTables.add(objectName.toLowerCase());
          } else if (type === 'DROP COLUMN') {
            // Extract table name from context (simplified heuristic)
            const beforeMatch = content.substring(0, match.index);
            const tableMatch = beforeMatch.match(/ALTER\s+TABLE\s+(\w+)/gi);
            if (tableMatch) {
              const tableName = tableMatch[tableMatch.length - 1].split(/\s+/)[2];
              if (!droppedColumns.has(tableName)) droppedColumns.set(tableName, []);
              droppedColumns.get(tableName).push(objectName);
              core.info(`Mapped DROP COLUMN ${objectName} to table ${tableName}`);
            }
          }
          
          sqlChanges.push(`${type}: ${objectName}`);
        }
      }
      
      // Check for table creations (for rename detection)
      const createTablePattern = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)/gi;
      let match;
      while ((match = createTablePattern.exec(content)) !== null) {
        createdTables.add(match[1].toLowerCase());
      }
      
      // Smart table rename detection (DROP+CREATE same table name)
      const renamedTables = new Set([...droppedTables].filter(table => createdTables.has(table)));
      for (const table of renamedTables) {
        // Remove from high-severity drops if it's a rename
        const dropIndex = sqlChanges.findIndex(change => change.includes(`DROP TABLE: ${table}`));
        if (dropIndex !== -1) {
          sqlChanges.splice(dropIndex, 1);
        }
        sqlChanges.push(`TABLE RENAME: ${table} (schema change)`);
        // Keep as high severity since schema might have changed
      }
      
      // Check for column operations and renames
      const addColumnPattern = /ADD\s+(?:COLUMN\s+)?(\w+)/gi;
      while ((match = addColumnPattern.exec(content)) !== null) {
        const beforeMatch = content.substring(0, match.index);
        const tableMatch = beforeMatch.match(/ALTER\s+TABLE\s+(\w+)/gi);
        if (tableMatch) {
          const tableName = tableMatch[tableMatch.length - 1].split(/\s+/)[2];
          if (!addedColumns.has(tableName)) addedColumns.set(tableName, []);
          addedColumns.get(tableName).push(match[1]);
        }
      }
      
      // Column rename heuristics (net column loss = High)
      for (const [tableName, dropped] of droppedColumns) {
        const added = addedColumns.get(tableName) || [];
        const netLoss = dropped.length - added.length;
        
        if (netLoss > 0) {
          sqlChanges.push(`COLUMN LOSS: ${tableName} (net -${netLoss} columns)`);
        } else if (dropped.length > 0 && added.length > 0) {
          sqlChanges.push(`COLUMN RENAME: ${tableName} (${dropped.length} dropped, ${added.length} added)`);
        }
      }
      
      // Check for type-narrowing operations (MEDIUM severity)
      const typeNarrowingPattern = /ALTER\s+COLUMN\s+(\w+)\s+TYPE\s+(\w+)/gi;
      while ((match = typeNarrowingPattern.exec(content)) !== null) {
        sqlChanges.push(`TYPE NARROWING: ${match[1]} -> ${match[2]}`);
      }
      
      // Check for other medium-risk operations
      const mediumRiskPatterns = [
        { pattern: /NOT\s+NULL/gi, type: 'NOT NULL constraint' },
        { pattern: /ADD\s+CONSTRAINT.*NOT\s+NULL/gi, type: 'NOT NULL constraint' }
      ];
      
      for (const { pattern, type } of mediumRiskPatterns) {
        if (pattern.test(content)) {
          sqlChanges.push(`${type} added`);
        }
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
          tablesAnalyzed: [...droppedTables, ...createdTables].length
        });
      }
    }

    return { driftResults, hasHighSeverity, hasMediumSeverity };
  }
}

module.exports = SqlAnalyzer;