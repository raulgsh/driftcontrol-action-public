/**
 * Base severity assessment rules
 */

// High severity: Breaking API changes, destructive DB operations, critical infrastructure changes
function assessHighSeverity(changeType, details) {
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
    (details && Array.isArray(details) && details.some(d => d.toUpperCase().includes(indicator)))
  );
  
  const hasHighRiskProperty = details && Array.isArray(details) && details.some(d => 
    highRiskPropertyPatterns.some(pattern => pattern.test(d))
  ) || false;
  
  return hasHighRiskIndicator || hasHighRiskProperty;
}

// Medium severity: New required fields, non-nullable constraints, type narrowing, security changes
function assessMediumSeverity(changeType, details) {
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
    (details && Array.isArray(details) && details.some(d => d.toUpperCase().includes(indicator)))
  );
  
  const hasMediumRiskProperty = details && Array.isArray(details) && details.some(d => 
    mediumRiskPropertyPatterns.some(pattern => pattern.test(d))
  ) || false;
  
  return hasMediumRiskIndicator || hasMediumRiskProperty;
}

// Check if this is a critical security issue that should not be downgraded
function isCriticalSecurityIssue(result) {
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
}

module.exports = {
  assessHighSeverity,
  assessMediumSeverity,
  isCriticalSecurityIssue
};