const core = require('@actions/core');
const riskScorer = require('../../risk-scorer');
const { globToRegex } = require('../../comment-generator');
const { isDmlOnly } = require('./classify');
const { parseSqlWithAst, fallbackRegexAnalysis, extractEntitiesFromContent } = require('./parse');

/**
 * Main SQL Analyzer class - orchestrates SQL drift analysis
 */
class SqlAnalyzer {
  constructor() {
    this.riskScorer = riskScorer;
  }

  async analyzeSqlFiles(files, octokit, owner, repo, pullRequestHeadSha, sqlGlob) {
    const driftResults = [];
    let hasHighSeverity = false;
    let hasMediumSeverity = false;

    // Process files for drift detection - use shared glob to regex conversion
    const sqlPattern = globToRegex(sqlGlob);
    const globRegexPattern = sqlPattern.source; // For logging purposes
    
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
      if (isDmlOnly(content)) {
        core.info(`Skipping DML-only migration: ${filename}`);
        continue;
      }
      
      // Try to use AST-based parsing first
      let parseResult = { sqlChanges: [], entities: [] };
      try {
        parseResult = parseSqlWithAst(content, filename);
        sqlChanges = parseResult.sqlChanges;
        core.info(`Successfully parsed ${filename} using SQL parser`);
      } catch (parseError) {
        // Fallback to regex-based parsing if AST parsing fails
        core.warning(`AST parsing failed for ${filename}: ${parseError.message}. Using fallback regex analysis.`);
        sqlChanges = fallbackRegexAnalysis(content, filename);
        parseResult.entities = extractEntitiesFromContent(content);
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
          tablesAnalyzed: parseResult.entities.length,
          // Add metadata for correlation
          entities: parseResult.entities,
          operations: sqlChanges.map(c => c.split(':')[0].trim())
        });
      }
    }

    return { driftResults, hasHighSeverity, hasMediumSeverity };
  }
}

module.exports = SqlAnalyzer;