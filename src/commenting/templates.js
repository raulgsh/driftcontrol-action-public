const { getLLMExplanation } = require('./llm');

/**
 * Template-based fix suggestions and rule-based explanations
 */

// Rule-based fix suggestion generator with optional LLM enhancement
async function generateFixSuggestion(change, driftType, severity, llmConfig = null) {
  // Try LLM enhancement first if configured
  if (llmConfig && llmConfig.enabled) {
    const llmExplanation = await getLLMExplanation(change, driftType, severity, llmConfig);
    if (llmExplanation) {
      return llmExplanation;
    }
  }
  
  // Fall back to rule-based suggestions
  if (!change) {
    // Handle null/empty change string - return generic suggestion
    if (severity === 'high') {
      return 'High impact change detected. Consider phased rollout and rollback plan.';
    }
    if (severity === 'medium') {
      return 'Monitor for issues after deployment. Have rollback procedure ready.';
    }
    return null;
  }
  
  const changeUpper = change.toUpperCase();
  
  // Database drift fix suggestions
  if (driftType === 'database') {
    if (changeUpper.includes('DROP TABLE')) {
      return 'Consider backing up data before dropping tables. Use `CREATE TABLE ... AS SELECT` for data migration if needed.';
    }
    if (changeUpper.includes('DROP COLUMN')) {
      return 'Create a backup of affected data. Consider deprecating the column first before removal in a future migration.';
    }
    if (changeUpper.includes('COLUMN LOSS')) {
      return 'Review if dropped columns contain important data. Add data migration script to preserve critical information.';
    }
    if (changeUpper.includes('TYPE NARROWING')) {
      return 'Validate existing data compatibility with new type. Add data cleaning script if needed before type change.';
    }
    if (changeUpper.includes('NOT NULL')) {
      return 'Ensure all existing rows have values for this column. Add default values or data population script.';
    }
    if (changeUpper.includes('TRUNCATE TABLE')) {
      return 'Verify this is intentional data loss. Consider using DELETE with WHERE clause for selective removal.';
    }
  }
  
  // API drift fix suggestions  
  if (driftType === 'api') {
    if (changeUpper.includes('API_DELETION')) {
      return 'Notify API consumers in advance. Provide migration path to alternative endpoints.';
    }
    if (changeUpper.includes('BREAKING_CHANGE') || changeUpper.includes('REMOVED')) {
      return 'Implement API versioning (v1, v2) to maintain backward compatibility. Add deprecation notices before removal.';
    }
    if (changeUpper.includes('REQUIRED')) {
      return 'Make new required fields optional initially, then enforce in next major version. Provide default values.';
    }
    if (changeUpper.includes('MODIFIED') && severity === 'medium') {
      return 'Document API changes in changelog. Update client SDKs and example code.';
    }
  }
  
  // Infrastructure drift fix suggestions
  if (driftType === 'infrastructure') {
    if (changeUpper.includes('SECURITY_GROUP_DELETION')) {
      return '🔒 Review security implications and ensure alternative security controls are in place';
    }
    if (changeUpper.includes('SECURITY_GROUP_CHANGE')) {
      return '🛡️ Validate security group rules don\'t expose sensitive services to public internet';
    }
    if (changeUpper.includes('RESOURCE_DELETION')) {
      return '⚠️ Ensure data backup and migration strategy before deleting resources';
    }
    if (changeUpper.includes('COST_INCREASE')) {
      return '💰 Review budget allocation and consider cost optimization strategies';
    }
    if (changeUpper.includes('RESOURCE_DELETION_POLICY')) {
      return '📋 Verify deletion policy aligns with data retention requirements';
    }
  }
  
  // Configuration drift fix suggestions
  if (driftType === 'configuration') {
    if (changeUpper.includes('SECRET_KEY')) {
      return '🔐 CRITICAL: Verify no secrets are exposed. Rotate credentials if necessary';
    }
    if (changeUpper.includes('FEATURE_FLAG')) {
      return '🚦 Ensure feature flag changes are coordinated with release plan';
    }
    if (changeUpper.includes('DEPENDENCY_REMOVED')) {
      return '📦 Verify removed dependencies are no longer used in codebase';
    }
    if (changeUpper.includes('DEPENDENCY_ADDED')) {
      return '🔍 Review new dependencies for security vulnerabilities and licensing';
    }
    if (changeUpper.includes('CONTAINER_REMOVED')) {
      return '🐳 Ensure container removal won\'t break dependent services';
    }
    if (changeUpper.includes('CONFIG_KEY')) {
      return '⚙️ Verify configuration changes are documented and tested';
    }
  }
  
  // Generic suggestions based on severity
  if (severity === 'high') {
    return 'High impact change detected. Consider phased rollout and rollback plan.';
  }
  if (severity === 'medium') {
    return 'Monitor for issues after deployment. Have rollback procedure ready.';
  }
  
  return null;
}

module.exports = {
  generateFixSuggestion
};