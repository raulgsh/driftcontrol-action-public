const { generateImpactSummary } = require('./llm');
const { generateFixSuggestion } = require('./templates');
const { buildCorrelationGraph, shortenPath } = require('./format');

/**
 * Main comment rendering logic
 */

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

module.exports = {
  generateCommentBody
};