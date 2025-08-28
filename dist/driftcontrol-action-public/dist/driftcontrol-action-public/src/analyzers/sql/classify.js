const core = require('@actions/core');

/**
 * SQL Classification utilities - dialect detection and DML classification
 */

// Detect SQL dialect based on content heuristics
function detectSqlDialect(content) {
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

// Check if content contains only DML operations (non-blocking)
function isDmlOnly(content) {
  const dmlPatterns = [
    /INSERT\s+INTO/i,
    /UPDATE\s+\w+\s+SET/i,
    /DELETE\s+FROM/i
  ];
  
  return dmlPatterns.some(pattern => pattern.test(content)) && 
         !content.match(/CREATE|ALTER|DROP|TRUNCATE/i);
}

module.exports = {
  detectSqlDialect,
  isDmlOnly
};