const core = require('@actions/core');
const { isCriticalSecurityIssue } = require('./base-rules');

/**
 * Correlation impact assessment for risk scoring
 */

// Assess correlation impact on severity
function assessCorrelationImpact(result, correlations, config) {
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
  
  // Calculate cascade impact - prefer graph-based metrics when available
  let cascadeImpact = 0;
  let graphMetrics = null;
  
  if (correlations._blastRadius && result.graphMetrics) {
    // Use graph-based blast radius calculation
    cascadeImpact = correlations._blastRadius.total;
    graphMetrics = {
      blastRadius: correlations._blastRadius.total,
      riskScore: correlations._blastRadius.riskScore,
      pathConfidence: result.graphMetrics.confidence,
      pathDepth: result.graphMetrics.depth,
      isRootCause: result.graphMetrics.isRootCause,
      impactByKind: correlations._blastRadius.byKind
    };
    
    core.debug(`Using graph metrics for ${resultId}: blast radius ${cascadeImpact}, risk score ${graphMetrics.riskScore.toFixed(2)}`);
  } else {
    // Fallback to legacy cascade calculation
    const affectedComponents = new Set();
    hardLinks.forEach(c => {
      const sourceId = c.source.artifactId || getArtifactId(c.source);
      const targetId = c.target.artifactId || getArtifactId(c.target);
      const otherId = sourceId === resultId ? targetId : sourceId;
      affectedComponents.add(otherId);
    });
    cascadeImpact = affectedComponents.size;
  }
  
  // Store correlation details in result
  result.correlationImpact = {
    hard: hardLinks.length,
    soft: softLinks.length,
    cascade: cascadeImpact,
    correlations: relevantCorrelations,
    graph: graphMetrics  // Include graph metrics if available
  };
  
  // Check if this is a critical security issue that should never be downgraded
  const isCriticalSecurity = isCriticalSecurityIssue(result);
  
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
  
  // Apply graph-enhanced severity upgrades (if not already upgraded by user rules)
  if (result.severity === originalSeverity) {
    // Use graph metrics for more sophisticated severity assessment
    if (graphMetrics) {
      // Root cause nodes have higher impact weight
      if (graphMetrics.isRootCause && result.severity === 'low') {
        result.severity = 'medium';
        result.reasoning = [...(result.reasoning || []), 
          `Upgraded from low to medium: identified as root cause affecting ${graphMetrics.blastRadius} components`
        ];
        core.info(`Graph analysis: upgraded ${resultId} to medium (root cause)`);
      } else if (graphMetrics.isRootCause && result.severity === 'medium' && graphMetrics.blastRadius >= 3) {
        result.severity = 'high';
        result.reasoning = [...(result.reasoning || []), 
          `Upgraded from medium to high: root cause with blast radius ${graphMetrics.blastRadius}`
        ];
        core.info(`Graph analysis: upgraded ${resultId} to high (root cause with wide impact)`);
      }
      
      // High-confidence paths suggest strong dependencies
      if (graphMetrics.pathConfidence >= 0.9 && cascadeImpact >= 2 && result.severity === 'low') {
        result.severity = 'medium';
        result.reasoning = [...(result.reasoning || []), 
          `Upgraded from low to medium: high-confidence path (${Math.round(graphMetrics.pathConfidence * 100)}%) affects ${cascadeImpact} components`
        ];
        core.info(`Graph analysis: upgraded ${resultId} to medium (high-confidence path)`);
      }
      
      // Graph risk score threshold
      if (graphMetrics.riskScore >= 0.7 && result.severity !== 'high') {
        result.severity = 'high';
        result.reasoning = [...(result.reasoning || []), 
          `Upgraded to high severity: graph risk score ${graphMetrics.riskScore.toFixed(2)} (affects critical systems)`
        ];
        core.info(`Graph analysis: upgraded ${resultId} to high (risk score ${graphMetrics.riskScore.toFixed(2)})`);
      }
      
      // Add graph-based impact details
      if (Object.keys(graphMetrics.impactByKind).length > 1) {
        const kinds = Object.entries(graphMetrics.impactByKind)
          .map(([k, v]) => `${k}:${v}`)
          .join(', ');
        result.reasoning.push(`Cross-layer impact: ${kinds}`);
      }
    } else {
      // Fallback to legacy cascade logic
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

module.exports = {
  assessCorrelationImpact
};