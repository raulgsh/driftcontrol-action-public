// Risk Scorer Module - Barrel Export
// Re-exports the complete risk scorer for backward compatibility

const { assessHighSeverity, assessMediumSeverity, isCriticalSecurityIssue } = require('./base-rules');
const { scoreChanges } = require('./scorer');
const { assessCorrelationImpact } = require('./correlation');
const { applyOverride } = require('./overrides');

// Create the riskScorer object that matches the original interface
const riskScorer = {
  assessHighSeverity,
  assessMediumSeverity,
  scoreChanges,
  isCriticalSecurityIssue,
  assessCorrelationImpact,
  applyOverride
};

module.exports = riskScorer;