/**
 * Override policy management for risk scoring
 */

// Policy override with reason tracking
function applyOverride(result, overrideReason = null) {
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

module.exports = {
  applyOverride
};