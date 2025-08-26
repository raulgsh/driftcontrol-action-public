// Centralized Risk Scoring Engine (MVP 3-level) - consolidates duplicate logic
const riskScorer = {
  // High severity: Breaking API changes, destructive DB operations
  assessHighSeverity(changeType, details) {
    const highRiskIndicators = [
      'DROP TABLE', 'DROP COLUMN', 'TRUNCATE TABLE', 'DROP CONSTRAINT',
      'COLUMN LOSS', 'API_DELETION', 'BREAKING_CHANGE'
    ];
    
    return highRiskIndicators.some(indicator => 
      changeType.toUpperCase().includes(indicator) || 
      (details && details.some(d => d.toUpperCase().includes(indicator)))
    );
  },
  
  // Medium severity: New required fields, non-nullable constraints, type narrowing
  assessMediumSeverity(changeType, details) {
    const mediumRiskIndicators = [
      'TYPE NARROWING', 'NOT NULL', 'REQUIRED', 'COLUMN RENAME',
      'BREAKING CHANGE', 'ADD CONSTRAINT'
    ];
    
    return mediumRiskIndicators.some(indicator => 
      changeType.toUpperCase().includes(indicator) || 
      (details && details.some(d => d.toUpperCase().includes(indicator)))
    );
  },
  
  // Transparent scoring: explains why a severity was assigned
  scoreChanges(changes, changeType = 'UNKNOWN') {
    const core = require('@actions/core');
    
    const scoringResult = {
      severity: 'low',
      reasoning: [],
      changes: changes
    };
    
    core.info(`Risk scoring for ${changeType}: ${JSON.stringify(changes)}`);
    
    // Assess High severity first (most critical)
    const isHighSeverity = this.assessHighSeverity(changeType, changes);
    const isMediumSeverity = this.assessMediumSeverity(changeType, changes);
    
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
  },
  
  // Policy override with reason tracking
  applyOverride(result, overrideReason = null) {
    if (overrideReason) {
      result.override = {
        applied: true,
        reason: overrideReason,
        originalSeverity: result.severity,
        timestamp: new Date().toISOString()
      };
      // Override allows merge regardless of severity
      result.allowMerge = true;
    }
    
    return result;
  }
};

module.exports = riskScorer;