// Centralized Risk Scoring Engine (MVP 3-level) - consolidates duplicate logic
const riskScorer = {
  // High severity: Breaking API changes, destructive DB operations, critical infrastructure changes
  assessHighSeverity(changeType, details) {
    const highRiskIndicators = [
      'DROP TABLE', 'DROP COLUMN', 'TRUNCATE TABLE', 'DROP CONSTRAINT',
      'COLUMN LOSS', 'API_DELETION', 'BREAKING_CHANGE',
      'SECURITY_GROUP_DELETION', 'RESOURCE_DELETION',
      'SECRET_KEY_REMOVED', 'SECRET_KEY_ADDED',
      'MAJOR_VERSION_BUMP', 'SECURITY_VULNERABILITY', 'CVE_DETECTED',
      'INTEGRITY_MISMATCH', 'TRANSITIVE_MAJOR_BUMP'
    ];
    
    // Check for high-risk property-level patterns
    const highRiskPropertyPatterns = [
      /cidr.*0\.0\.0\.0\/0/i,        // CIDR opened to internet
      /DeletionPolicy.*Delete/i,      // Changed to Delete
      /publicly.*true/i,              // Made publicly accessible
      /encryption.*false/i,           // Encryption disabled
      /ssl.*false/i,                  // SSL disabled
      /PROPERTY_REMOVED.*security/i,  // Security property removed
      /PROPERTY_MODIFIED.*0\.0\.0\.0/i // Network opened to internet
    ];
    
    const hasHighRiskIndicator = highRiskIndicators.some(indicator => 
      changeType.toUpperCase().includes(indicator) || 
      (details && details.some(d => d.toUpperCase().includes(indicator)))
    );
    
    const hasHighRiskProperty = details && details.some(d => 
      highRiskPropertyPatterns.some(pattern => pattern.test(d))
    );
    
    return hasHighRiskIndicator || hasHighRiskProperty;
  },
  
  // Medium severity: New required fields, non-nullable constraints, type narrowing, security changes
  assessMediumSeverity(changeType, details) {
    const mediumRiskIndicators = [
      'TYPE NARROWING', 'NOT NULL', 'REQUIRED', 'COLUMN RENAME',
      'BREAKING CHANGE', 'ADD CONSTRAINT', 'API_EXPANSION',
      'SECURITY_GROUP_CHANGE', 'COST_INCREASE', 'RESOURCE_DELETION_POLICY',
      'FEATURE_FLAG_', 'CONTAINER_REMOVED', 'DEPENDENCY_REMOVED',
      'MINOR_VERSION_BUMP', 'LICENSE_CHANGE', 'DEPRECATED_PACKAGE',
      'TRANSITIVE_DEPENDENCIES_CHANGED', 'NEW_LOCK_FILE'
    ];
    
    // Check for medium-risk property-level patterns
    const mediumRiskPropertyPatterns = [
      /PROPERTY_MODIFIED.*port/i,     // Port changes
      /PROPERTY_MODIFIED.*timeout/i,  // Timeout changes
      /PROPERTY_MODIFIED.*size/i,     // Resource size changes
      /PROPERTY_ADDED.*rule/i,        // New rules added
      /PROPERTY_REMOVED.*monitoring/i, // Monitoring removed
      /ingress.*modified/i,           // Ingress rules modified
      /egress.*modified/i             // Egress rules modified
    ];
    
    const hasMediumRiskIndicator = mediumRiskIndicators.some(indicator => 
      changeType.toUpperCase().includes(indicator) || 
      (details && details.some(d => d.toUpperCase().includes(indicator)))
    );
    
    const hasMediumRiskProperty = details && details.some(d => 
      mediumRiskPropertyPatterns.some(pattern => pattern.test(d))
    );
    
    return hasMediumRiskIndicator || hasMediumRiskProperty;
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
  },
  
  // Assess correlation impact on severity
  assessCorrelationImpact(result, correlations) {
    const core = require('@actions/core');
    
    // If no correlations, return result unchanged
    if (!correlations || correlations.length === 0) return result;
    
    // Count high-confidence correlations involving this result
    const strongCorrelations = correlations.filter(c => 
      c.confidence > 0.7 && (c.source === result || c.target === result)
    );
    
    const impactCount = strongCorrelations.length;
    
    // Calculate cascade impact (how many other components are affected)
    const affectedComponents = new Set();
    strongCorrelations.forEach(c => {
      if (c.source === result) affectedComponents.add(c.target.file || c.target.type);
      if (c.target === result) affectedComponents.add(c.source.file || c.source.type);
    });
    
    const cascadeImpact = affectedComponents.size;
    
    // Store correlation details in result
    result.correlationImpact = {
      count: impactCount,
      cascade: cascadeImpact,
      correlations: strongCorrelations
    };
    
    // Upgrade severity based on correlation impact
    const originalSeverity = result.severity;
    
    if (cascadeImpact >= 3 && result.severity === 'medium') {
      result.severity = 'high';
      result.reasoning = [...(result.reasoning || []), 
        `Upgraded from medium to high severity: affects ${cascadeImpact} cross-layer components`
      ];
      core.info(`Correlation impact: upgraded ${result.file || result.type} from medium to high (${cascadeImpact} components affected)`);
    } else if (cascadeImpact >= 2 && result.severity === 'low') {
      result.severity = 'medium';
      result.reasoning = [...(result.reasoning || []), 
        `Upgraded from low to medium severity: affects ${cascadeImpact} cross-layer components`
      ];
      core.info(`Correlation impact: upgraded ${result.file || result.type} from low to medium (${cascadeImpact} components affected)`);
    } else if (impactCount >= 4 && result.severity !== 'high') {
      // Many correlations even if not all different components
      result.severity = 'high';
      result.reasoning = [...(result.reasoning || []), 
        `Upgraded to high severity: ${impactCount} strong cross-layer correlations detected`
      ];
      core.info(`Correlation impact: upgraded ${result.file || result.type} to high (${impactCount} strong correlations)`);
    }
    
    // Add correlation details to reasoning if severity was upgraded
    if (result.severity !== originalSeverity) {
      const correlationTypes = [...new Set(strongCorrelations.map(c => c.relationship))];
      result.reasoning.push(`Correlation types: ${correlationTypes.join(', ')}`);
      
      // Add specific impact details
      if (strongCorrelations.some(c => c.relationship === 'api_uses_table')) {
        result.reasoning.push('API endpoints directly depend on affected database tables');
      }
      if (strongCorrelations.some(c => c.relationship === 'operation_alignment')) {
        result.reasoning.push('Database operations align with API CRUD operations');
      }
      if (strongCorrelations.some(c => c.relationship === 'dependency_affects_api' || c.relationship === 'dependency_affects_db')) {
        result.reasoning.push('Package dependency changes affect multiple layers');
      }
    }
    
    return result;
  }
};

module.exports = riskScorer;