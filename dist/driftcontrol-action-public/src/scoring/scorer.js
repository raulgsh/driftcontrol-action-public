const core = require('@actions/core');
const { assessHighSeverity, assessMediumSeverity } = require('./base-rules');

/**
 * Main scoring logic
 */

// Transparent scoring: explains why a severity was assigned
function scoreChanges(changes, changeType = 'UNKNOWN') {
  const scoringResult = {
    severity: 'low',
    reasoning: [],
    changes: changes
  };
  
  core.info(`Risk scoring for ${changeType}: ${JSON.stringify(changes)}`);
  
  // Assess High severity first (most critical)
  const isHighSeverity = assessHighSeverity(changeType, changes);
  const isMediumSeverity = assessMediumSeverity(changeType, changes);
  
  core.info(`High severity check: ${isHighSeverity}, Medium severity check: ${isMediumSeverity}`);
  
  if (isHighSeverity) {
    scoringResult.severity = 'high';
    scoringResult.reasoning.push('Contains destructive or breaking operations');
  }
  // Then Medium severity (if not already High)
  else if (isMediumSeverity) {
    scoringResult.severity = 'medium';
    scoringResult.reasoning.push('Contains potentially breaking or constraining changes');
  }
  // Default to Low severity
  else if (changes && changes.length > 0) {
    scoringResult.severity = 'low';
    scoringResult.reasoning.push('Contains backward-compatible changes');
  }
  
  core.info(`Final severity: ${scoringResult.severity}`);
  return scoringResult;
}

module.exports = {
  scoreChanges
};