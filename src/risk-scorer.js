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
  
  // Check if this is a critical security issue that should not be downgraded
  isCriticalSecurityIssue(result) {
    if (!result || !result.changes) return false;
    
    // Critical security patterns that should never be downgraded
    const criticalPatterns = [
      'SECURITY_VULNERABILITY',
      'CVE_DETECTED',
      'CVE-',
      'DROP TABLE',
      'DROP COLUMN',
      'TRUNCATE TABLE',
      'SECURITY_GROUP_DELETION',
      'SECRET_KEY_REMOVED',
      'SECRET_KEY_ADDED',
      'INTEGRITY_MISMATCH',
      'MALICIOUS_PACKAGE'
    ];
    
    // Check if any change matches critical patterns
    return result.changes.some(change => {
      const upperChange = change.toUpperCase();
      return criticalPatterns.some(pattern => upperChange.includes(pattern));
    });
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
  assessCorrelationImpact(result, correlations, config) {
    const core = require('@actions/core');
    
    // If no correlations, return result unchanged
    if (!correlations || correlations.length === 0) return result;
    
    // Helper function to get artifact ID (should use the same logic as index.js)
    const getArtifactId = (r) => {
      if (!r) return 'unknown';
      if (r.artifactId) return r.artifactId; // Use pre-computed ID if available
      if (r.id) return r.id;
      if (r.file) return r.file;
      if (r.type && r.name) return `${r.type}:${r.name}`;
      if (r.type && r.entities && r.entities[0]) return `${r.type}:${r.entities[0]}`;
      if (r.type) return `${r.type}:${r.severity || 'unknown'}`;
      return 'unknown';
    };
    
    const resultId = result.artifactId || getArtifactId(result);
    const thresholds = config?.thresholds || {
      correlate_min: 0.55,
      block_min: 0.80
    };
    
    // Filter correlations involving this result using finalScore
    const relevantCorrelations = correlations.filter(c => {
      const sourceId = c.source.artifactId || getArtifactId(c.source);
      const targetId = c.target.artifactId || getArtifactId(c.target);
      return (sourceId === resultId || targetId === resultId) && 
             (c.finalScore >= thresholds.correlate_min || c.confidence >= thresholds.correlate_min);
    });
    
    // Categorize by impact level using finalScore
    const hardLinks = relevantCorrelations.filter(c => 
      (c.finalScore || c.confidence) >= thresholds.block_min
    );
    const softLinks = relevantCorrelations.filter(c => {
      const score = c.finalScore || c.confidence;
      return score >= thresholds.correlate_min && score < thresholds.block_min;
    });
    
    // Separate user-defined correlations
    const userDefinedCorrelations = relevantCorrelations.filter(c => c.userDefined);
    
    const impactCount = hardLinks.length;
    
    // Calculate cascade impact (how many other components are affected)
    const affectedComponents = new Set();
    hardLinks.forEach(c => {
      const sourceId = c.source.artifactId || getArtifactId(c.source);
      const targetId = c.target.artifactId || getArtifactId(c.target);
      const otherId = sourceId === resultId ? targetId : sourceId;
      affectedComponents.add(otherId);
    });
    
    const cascadeImpact = affectedComponents.size;
    
    // Store correlation details in result
    result.correlationImpact = {
      hard: hardLinks.length,
      soft: softLinks.length,
      cascade: cascadeImpact,
      correlations: relevantCorrelations
    };
    
    // Check if this is a critical security issue that should never be downgraded
    const isCriticalSecurity = this.isCriticalSecurityIssue(result);
    
    // Safety rail: Critical security issues must stay HIGH
    if (isCriticalSecurity && result.severity !== 'high') {
      result.severity = 'high';
      result.reasoning = [...(result.reasoning || []), 
        'Critical security issue - severity enforced to HIGH'
      ];
      core.info(`Safety rail: enforced HIGH severity for critical security issue in ${resultId}`);
    }
    
    // Upgrade severity based on correlation impact
    const originalSeverity = result.severity;
    
    // User-defined correlations have higher impact weight
    if (userDefinedCorrelations.length > 0) {
      // Never downgrade critical security issues
      if (isCriticalSecurity && result.severity === 'high') {
        result.reasoning = [...(result.reasoning || []), 
          `Critical security issue - severity cannot be reduced`
        ];
      } else {
        // User-defined correlations immediately upgrade severity by one level
        if (result.severity === 'low') {
          result.severity = 'medium';
          result.reasoning = [...(result.reasoning || []), 
            `Upgraded from low to medium severity: ${userDefinedCorrelations.length} user-defined correlation(s) detected`
          ];
          core.info(`User-defined correlation impact: upgraded ${resultId} from low to medium`);
        } else if (result.severity === 'medium' && userDefinedCorrelations.length >= 2) {
          result.severity = 'high';
          result.reasoning = [...(result.reasoning || []), 
            `Upgraded from medium to high severity: ${userDefinedCorrelations.length} user-defined correlations detected`
          ];
          core.info(`User-defined correlation impact: upgraded ${resultId} from medium to high`);
        }
      }
      
      // Add user-defined correlation details
      userDefinedCorrelations.forEach(corr => {
        if (corr.rule && corr.rule.description) {
          result.reasoning.push(`User-defined: ${corr.rule.description}`);
        }
      });
    }
    
    // Apply standard heuristic-based severity upgrades (if not already upgraded by user rules)
    if (result.severity === originalSeverity) {
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
    }
    
    // Add correlation details to reasoning if severity was upgraded
    if (result.severity !== originalSeverity) {
      const correlationTypes = [...new Set(relevantCorrelations.map(c => c.relationship || ''))].filter(Boolean);
      if (correlationTypes.length > 0) {
        result.reasoning.push(`Correlation types: ${correlationTypes.sort().join(', ')}`);
      }
      
      // Add specific impact details
      if (relevantCorrelations.some(c => c.relationship?.includes('api_uses_table'))) {
        result.reasoning.push('API endpoints directly depend on affected database tables');
      }
      if (relevantCorrelations.some(c => c.relationship?.includes('operation_alignment'))) {
        result.reasoning.push('Database operations align with API CRUD operations');
      }
      if (relevantCorrelations.some(c => c.relationship?.includes('dependency_affects'))) {
        result.reasoning.push('Package dependency changes affect multiple layers');
      }
      
      // Add finalScore details for transparency
      const highScoreCorrelations = relevantCorrelations.filter(c => (c.finalScore || c.confidence) >= 0.9);
      if (highScoreCorrelations.length > 0) {
        result.reasoning.push(`${highScoreCorrelations.length} correlations with confidence ≥ 0.9`);
      }
    }
    
    return result;
  }
};

module.exports = riskScorer;