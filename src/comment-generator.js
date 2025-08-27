// Helper function to generate comment body
async function generateCommentBody(driftResults, isOverride, llmConfig = null) {
  const severityEmojis = {
    high: '🔴',
    medium: '🟡', 
    low: '🟢'
  };
  
  let comment = '<!-- driftcontrol:comment -->\n';
  comment += '## 🔍 DriftControl Analysis Report\n\n';
  
  if (isOverride) {
    comment += '> ⚠️ **Policy Override Active** - Drift detected but merge allowed with audit trail.\n\n';
  }
  
  // Group results by severity
  const groupedResults = {
    high: driftResults.filter(r => r.severity === 'high'),
    medium: driftResults.filter(r => r.severity === 'medium'),
    low: driftResults.filter(r => r.severity === 'low')
  };
  
  // Add summary
  const totalIssues = driftResults.length;
  const highCount = groupedResults.high.length;
  const mediumCount = groupedResults.medium.length;
  const lowCount = groupedResults.low.length;
  
  comment += `**Summary**: ${totalIssues} drift issue${totalIssues !== 1 ? 's' : ''} detected\n`;
  if (highCount > 0) comment += `- ${severityEmojis.high} ${highCount} High severity\n`;
  if (mediumCount > 0) comment += `- ${severityEmojis.medium} ${mediumCount} Medium severity\n`;  
  if (lowCount > 0) comment += `- ${severityEmojis.low} ${lowCount} Low severity\n`;
  comment += '\n';
  
  // Add LLM-generated impact summary if available
  if (llmConfig && llmConfig.enabled) {
    const impactSummary = await generateImpactSummary(driftResults, llmConfig);
    if (impactSummary) {
      comment += `**📊 Impact Analysis**:\n${impactSummary}\n\n`;
    }
  }
  
  // Display correlation graph if present
  const hasCorrelations = driftResults.some(r => r.correlations && r.correlations.length > 0);
  if (hasCorrelations) {
    comment += '**🔗 Cross-Layer Correlations Detected**:\n\n';
    
    // Build simple ASCII graph
    const graph = buildCorrelationGraph(driftResults);
    if (graph && graph !== 'No correlations found') {
      comment += '```\n' + graph + '\n```\n\n';
    }
    
    // List root causes
    const rootCauses = driftResults.filter(r => r.rootCause);
    if (rootCauses.length > 0) {
      comment += '**🎯 Identified Root Causes**:\n';
      rootCauses.forEach(r => {
        const confidence = Math.round((r.rootCause.confidence || 0.5) * 100);
        const icon = r.rootCause.type === 'root_cause' ? '⚡' : '🔍';
        comment += `- ${icon} **${r.type.toUpperCase()}**: \`${r.file}\` (${confidence}% confidence)\n`;
      });
      comment += '\n';
    }
  }
  
  // Add detailed results with collapsible sections for readability
  for (const severity of ['high', 'medium', 'low']) {
    const results = groupedResults[severity];
    if (results.length === 0) continue;
    
    // Make sections collapsible to improve readability
    const sectionTitle = `${severity.toUpperCase()} Severity Issues (${results.length})`;
    comment += `<details>\n<summary><strong>${severityEmojis[severity]} ${sectionTitle}</strong></summary>\n\n`;
    
    for (const result of results) {
      // Enhanced readability with better visual structure
      comment += `#### ${result.type.toUpperCase()} Drift: \`${result.file}\`\n\n`;
      
      // Show metadata in a more organized way
      const metadata = [];
      if (result.renamed) {
        metadata.push(`Renamed from \`${result.renamed.from}\``);
      }
      if (result.type === 'database' && result.tablesAnalyzed) {
        metadata.push(`Analyzed ${result.tablesAnalyzed} table(s)`);
      }
      
      if (metadata.length > 0) {
        comment += `📋 **Context**: ${metadata.join(' • ')}\n\n`;
      }
      
      // Show detailed changes with rule-based fix suggestions
      for (const change of result.changes) {
        comment += `- ${change}\n`;
        
        // Add rule-based or LLM-enhanced fix suggestions based on change patterns
        const fixSuggestion = await generateFixSuggestion(change, result.type, result.severity, llmConfig);
        if (fixSuggestion) {
          comment += `  💡 **Explanation**: ${fixSuggestion}\n`;
        }
      }
      
      // Show transparent scoring reasoning in organized format
      if (result.reasoning && result.reasoning.length > 0) {
        comment += `\n🎯 **Risk Assessment**: ${result.reasoning.join(', ')}\n`;
      }
      
      // Show override information in prominent format if applied
      if (result.override) {
        comment += `\n⚠️ **Override Applied**: ${result.override.reason}\n`;
        comment += `📅 *Original severity: ${result.override.originalSeverity} • ${result.override.timestamp}*\n`;
      }
      
      comment += '\n';
    }
    
    // Close collapsible section
    comment += '</details>\n\n';
  }
  
  // Add override instructions if high severity
  if (highCount > 0 && !isOverride) {
    comment += '---\n';
    comment += '**Merge Blocked**: High severity drift detected. ';
    comment += 'To override this block, comment `/driftcontrol override: <reason>` on this PR.\n';
  }
  
  comment += '\n---\n';
  comment += `📊 *Analysis completed at ${new Date().toISOString()}* • Generated by [DriftControl](https://github.com/driftcontrol/action)\n`;
  
  return comment;
}

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
  
  return null; // No specific suggestion
}

// Generate LLM-enhanced explanation
async function getLLMExplanation(change, driftType, severity, llmConfig) {
  try {
    const prompt = buildExplanationPrompt(change, driftType, severity);
    
    if (llmConfig.provider === 'openai') {
      return await getOpenAIExplanation(prompt, llmConfig);
    } else if (llmConfig.provider === 'anthropic') {
      return await getAnthropicExplanation(prompt, llmConfig);
    }
  } catch (error) {
    // Silently fall back to rule-based
    return null;
  }
}

// Build concise prompt for LLM
function buildExplanationPrompt(change, driftType, severity) {
  return `Explain this ${driftType} drift in plain English (max 2 sentences):
Change: ${change}
Severity: ${severity}
Provide a concise explanation and actionable fix suggestion.`;
}

// OpenAI API integration
async function getOpenAIExplanation(prompt, llmConfig) {
  try {
    const https = require('https');
    const data = JSON.stringify({
      model: llmConfig.model || 'gpt-3.5-turbo',
      messages: [
        { role: 'system', content: 'You are a DevOps expert providing concise drift analysis explanations.' },
        { role: 'user', content: prompt }
      ],
      max_tokens: llmConfig.maxTokens || 150,
      temperature: 0.3
    });
    
    return new Promise((resolve, reject) => {
      const req = https.request({
        hostname: 'api.openai.com',
        path: '/v1/chat/completions',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${llmConfig.apiKey}`
        }
      }, (res) => {
        let responseData = '';
        res.on('data', (chunk) => responseData += chunk);
        res.on('end', () => {
          try {
            const parsed = JSON.parse(responseData);
            resolve(parsed.choices?.[0]?.message?.content || null);
          } catch {
            resolve(null);
          }
        });
      });
      
      req.on('error', () => resolve(null));
      req.write(data);
      req.end();
    });
  } catch {
    return null;
  }
}

// Anthropic API integration
async function getAnthropicExplanation(prompt, llmConfig) {
  try {
    const https = require('https');
    const data = JSON.stringify({
      model: llmConfig.model || 'claude-3-sonnet-20240229',
      messages: [
        { role: 'user', content: prompt }
      ],
      max_tokens: llmConfig.maxTokens || 150
    });
    
    return new Promise((resolve, reject) => {
      const req = https.request({
        hostname: 'api.anthropic.com',
        path: '/v1/messages',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': llmConfig.apiKey,
          'anthropic-version': '2023-06-01'
        }
      }, (res) => {
        let responseData = '';
        res.on('data', (chunk) => responseData += chunk);
        res.on('end', () => {
          try {
            const parsed = JSON.parse(responseData);
            resolve(parsed.content?.[0]?.text || null);
          } catch {
            resolve(null);
          }
        });
      });
      
      req.on('error', () => resolve(null));
      req.write(data);
      req.end();
    });
  } catch {
    return null;
  }
}

// Generate impact summary for all changes
async function generateImpactSummary(driftResults, llmConfig) {
  try {
    if (!llmConfig || !llmConfig.enabled || driftResults.length === 0) {
      return null;
    }
    
    // Build context from all drift results
    const highSeverityChanges = driftResults.filter(r => r.severity === 'high');
    const context = {
      totalChanges: driftResults.length,
      types: [...new Set(driftResults.map(r => r.type))],
      hasHighSeverity: highSeverityChanges.length > 0,
      criticalChanges: highSeverityChanges.slice(0, 3).map(r => r.changes[0])
    };
    
    const prompt = `Summarize the impact of these changes in 2-3 sentences:
${context.totalChanges} total changes across ${context.types.join(', ')}.
${context.hasHighSeverity ? 'Critical: ' + context.criticalChanges.join(', ') : 'No critical issues.'}
Focus on business impact and deployment risks.`;
    
    if (llmConfig.provider === 'openai') {
      return await getOpenAIExplanation(prompt, llmConfig);
    } else if (llmConfig.provider === 'anthropic') {
      return await getAnthropicExplanation(prompt, llmConfig);
    }
  } catch {
    return null;
  }
}

// Build ASCII correlation graph
function buildCorrelationGraph(driftResults) {
  let graph = 'Drift Correlation Graph:\n\n';
  const drawnRelationships = new Set();
  
  driftResults.forEach(result => {
    if (result.correlations && result.correlations.length > 0) {
      result.correlations.forEach(corr => {
        if (corr.source === result) {
          // Create a unique key for this relationship to avoid duplicates
          const relKey = `${corr.source.type}:${corr.source.file}→${corr.target.type}:${corr.target.file}`;
          if (!drawnRelationships.has(relKey)) {
            drawnRelationships.add(relKey);
            
            // Format the labels
            const sourceLabel = `[${corr.source.type}] ${shortenPath(corr.source.file)}`;
            const targetLabel = `[${corr.target.type}] ${shortenPath(corr.target.file)}`;
            const confidence = Math.round((corr.confidence || 0.5) * 100);
            
            // Add the relationship line
            graph += `${sourceLabel}\n`;
            graph += `  └─${corr.relationship}(${confidence}%)→ ${targetLabel}\n`;
          }
        }
      });
    }
  });
  
  // If no relationships were drawn, indicate that
  if (drawnRelationships.size === 0) {
    return 'No correlations found';
  }
  
  return graph;
}

// Helper to shorten file paths for readability
function shortenPath(path) {
  if (!path) return 'unknown';
  
  // If path is longer than 40 chars, show .../ and last part
  if (path.length > 40) {
    const parts = path.split('/');
    if (parts.length > 2) {
      return `.../${parts[parts.length - 2]}/${parts[parts.length - 1]}`;
    }
    return `.../${parts[parts.length - 1]}`;
  }
  
  return path;
}

// Convert glob patterns to regex (consolidates logic from analyzers)
function globToRegex(glob) {
  let pattern;
  if (glob.includes('**/')) {
    const parts = glob.split('**/');
    const prefix = parts[0].replace(/\./g, '\\.');
    const suffix = parts[1]
      .replace(/\./g, '\\.')
      .replace(/\*/g, '[^/]*');
    pattern = `^${prefix}.*${suffix}$`;
  } else {
    pattern = glob
      .replace(/\./g, '\\.')
      .replace(/\*\*/g, '.*')
      .replace(/\*/g, '[^/]*')
      + '$';
  }
  return new RegExp(pattern);
}

module.exports = {
  generateCommentBody,
  generateFixSuggestion,
  getLLMExplanation,
  generateImpactSummary,
  buildCorrelationGraph,
  globToRegex
};