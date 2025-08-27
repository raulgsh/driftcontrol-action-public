/**
 * LLM Integration for comment enhancement
 */

// Get LLM explanation for a specific change
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

module.exports = {
  getLLMExplanation,
  generateImpactSummary
};