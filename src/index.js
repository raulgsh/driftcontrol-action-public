const core = require('@actions/core');
const github = require('@actions/github');
const micromatch = require('micromatch');
const SqlAnalyzer = require('./sql-analyzer');
const OpenApiAnalyzer = require('./openapi-analyzer');
const IaCAnalyzer = require('./iac-analyzer');
const ConfigAnalyzer = require('./config-analyzer');
const { generateCommentBody, generateFixSuggestion } = require('./comment-generator');
const { postOrUpdateComment } = require('./github-api');
const riskScorer = require('./risk-scorer');

async function run() {
  try {
    // Get all inputs defined in action.yml
    const openApiPath = core.getInput('openapi_path');
    const sqlGlob = core.getInput('sql_glob');
    const failOnMedium = core.getInput('fail_on_medium');
    const override = core.getInput('override');
    const terraformPlanPath = core.getInput('terraform_plan_path');
    const cloudformationGlob = core.getInput('cloudformation_glob');
    const costThreshold = core.getInput('cost_threshold');
    const configYamlGlob = core.getInput('config_yaml_glob');
    const featureFlagsPath = core.getInput('feature_flags_path');
    const correlationConfigPath = core.getInput('correlation_config_path');
    
    // LLM configuration for enhanced explanations
    const llmProvider = core.getInput('llm_provider');
    const llmApiKey = core.getInput('llm_api_key');
    const llmModel = core.getInput('llm_model');
    const llmMaxTokens = parseInt(core.getInput('llm_max_tokens') || '150');
    
    const llmConfig = llmProvider && llmApiKey ? {
      enabled: true,
      provider: llmProvider,
      apiKey: llmApiKey,
      model: llmModel,
      maxTokens: llmMaxTokens
    } : null;

    // Log input values for initial setup verification
    core.info(`OpenAPI Path: ${openApiPath}`);
    core.info(`SQL Glob: ${sqlGlob}`);
    core.info(`Terraform Plan Path: ${terraformPlanPath}`);
    core.info(`CloudFormation Glob: ${cloudformationGlob}`);
    core.info(`Config YAML Glob: ${configYamlGlob}`);
    core.info(`Feature Flags Path: ${featureFlagsPath}`);
    core.info(`Cost Threshold: ${costThreshold}`);
    core.info(`Fail on Medium: ${failOnMedium}`);
    core.info(`Override: ${override}`);
    if (llmConfig) {
      core.info(`LLM Provider: ${llmProvider} (Model: ${llmModel || 'default'})`);
    }

    // Get GitHub context and authenticate
    const token = core.getInput('token') || process.env.GITHUB_TOKEN;
    if (!token) {
      throw new Error('GITHUB_TOKEN is required');
    }
    
    const octokit = github.getOctokit(token);
    const context = github.context;
    
    // Check if this is a pull request event
    if (!context.payload.pull_request) {
      core.info('Not a pull request event, skipping drift detection');
      return;
    }
    
    const { owner, repo } = context.repo;
    const pullNumber = context.payload.pull_request.number;
    
    core.info(`Analyzing PR #${pullNumber} in ${owner}/${repo}`);
    
    // Fetch PR files list via GitHub API (no full clone)
    const { data: files } = await octokit.rest.pulls.listFiles({
      owner,
      repo,
      pull_number: pullNumber
    });
    
    core.info(`Found ${files.length} changed files in PR`);
    
    // Initialize analyzers
    const sqlAnalyzer = new SqlAnalyzer();
    const openApiAnalyzer = new OpenApiAnalyzer();
    const iacAnalyzer = new IaCAnalyzer();
    const configAnalyzer = new ConfigAnalyzer();
    
    // Load correlation configuration if provided
    let correlationConfig = null;
    if (correlationConfigPath) {
      correlationConfig = await configAnalyzer.loadCorrelationConfig(octokit, owner, repo, context.payload.pull_request, correlationConfigPath);
      if (correlationConfig.loaded) {
        core.info(`Correlation config loaded with ${correlationConfig.correlationRules.length} rules`);
      }
    }
    
    // Detect OpenAPI spec file renames
    const { actualOpenApiPath, renamedFromPath } = openApiAnalyzer.detectSpecRenames(files, openApiPath);
    
    // Initialize drift detection results
    let hasHighSeverity = false;
    let hasMediumSeverity = false;
    const driftResults = [];
    
    
    // Analyze SQL migration files
    const sqlResults = await sqlAnalyzer.analyzeSqlFiles(
      files, octokit, owner, repo, context.payload.pull_request.head.sha, sqlGlob
    );
    driftResults.push(...sqlResults.driftResults);
    hasHighSeverity = hasHighSeverity || sqlResults.hasHighSeverity;
    hasMediumSeverity = hasMediumSeverity || sqlResults.hasMediumSeverity;
    
    // Analyze OpenAPI drift
    const apiResults = await openApiAnalyzer.analyzeOpenApiDrift(
      octokit, owner, repo, context.payload.pull_request, actualOpenApiPath, renamedFromPath
    );
    driftResults.push(...apiResults.driftResults);
    hasHighSeverity = hasHighSeverity || apiResults.hasHighSeverity;
    hasMediumSeverity = hasMediumSeverity || apiResults.hasMediumSeverity;
    
    // Analyze Infrastructure as Code drift
    if (terraformPlanPath || cloudformationGlob) {
      const iacResults = await iacAnalyzer.analyzeIaCFiles(
        files, octokit, owner, repo, context.payload.pull_request,
        terraformPlanPath, cloudformationGlob, costThreshold
      );
      driftResults.push(...iacResults.driftResults);
      hasHighSeverity = hasHighSeverity || iacResults.hasHighSeverity;
      hasMediumSeverity = hasMediumSeverity || iacResults.hasMediumSeverity;
    }
    
    // Analyze Configuration drift (security-first: keys only)
    if (configYamlGlob || featureFlagsPath || files.some(f => f.filename.endsWith('package.json') || f.filename.endsWith('package-lock.json') || f.filename.includes('docker-compose'))) {
      const configResults = await configAnalyzer.analyzeConfigFiles(
        files, octokit, owner, repo, context.payload.pull_request,
        configYamlGlob, featureFlagsPath
      );
      driftResults.push(...configResults.driftResults);
      hasHighSeverity = hasHighSeverity || configResults.hasHighSeverity;
      hasMediumSeverity = hasMediumSeverity || configResults.hasMediumSeverity;
      
      // Also analyze package-lock.json files specifically
      const packageLockFiles = files.filter(f => f.filename.endsWith('package-lock.json'));
      for (const file of packageLockFiles) {
        const lockResult = await configAnalyzer.analyzePackageLock(
          octokit, owner, repo, context.payload.pull_request.head.sha, context.payload.pull_request.base.sha, file.filename
        );
        if (lockResult) {
          driftResults.push(lockResult);
          if (lockResult.severity === 'high') hasHighSeverity = true;
          if (lockResult.severity === 'medium') hasMediumSeverity = true;
        }
      }
    }
    
    // Cross-layer correlation analysis
    if (driftResults.length > 1) {
      // Build correlation graph from existing results (pass correlation config)
      const correlations = correlateAcrossLayers(driftResults, files, correlationConfig);
      
      // Identify root causes
      const rootCauses = identifyRootCauses(correlations, driftResults);
      
      // Enhance results with correlation data and assess impact on severity
      driftResults.forEach(result => {
        result.correlations = correlations.filter(c => 
          c.source === result || c.target === result
        );
        result.rootCause = rootCauses.find(r => r.result === result);
        
        // Apply correlation-based severity assessment
        riskScorer.assessCorrelationImpact(result, correlations, correlationConfig);
        
        // Update severity tracking if upgraded
        if (result.severity === 'high' && !hasHighSeverity) {
          hasHighSeverity = true;
          core.info(`Correlation analysis upgraded severity to HIGH for ${result.file || result.type}`);
        } else if (result.severity === 'medium' && !hasMediumSeverity) {
          hasMediumSeverity = true;
          core.info(`Correlation analysis upgraded severity to MEDIUM for ${result.file || result.type}`);
        }
      });
      
      core.info(`Correlation analysis: found ${correlations.length} relationships and ${rootCauses.length} root causes`);
      
      // Log high-confidence correlations for debugging
      const strongCorrelations = correlations.filter(c => c.confidence > 0.7);
      if (strongCorrelations.length > 0) {
        core.info(`Strong correlations (confidence > 0.7): ${strongCorrelations.length}`);
        strongCorrelations.forEach(c => {
          core.info(`  - ${c.relationship}: ${c.source.file || c.source.type} <-> ${c.target.file || c.target.type} (confidence: ${c.confidence.toFixed(2)})`);
        });
      }
    }
    
    // Generate and post PR comment with results
    if (driftResults.length > 0) {
      const commentBody = await generateCommentBody(driftResults, override === 'true', llmConfig);
      await postOrUpdateComment(octokit, owner, repo, pullNumber, commentBody);
    } else {
      core.info('No drift detected');
      // Still post a comment to show the action ran
      const commentBody = '<!-- driftcontrol:comment -->\n## 🟢 DriftControl Analysis\n\n✅ No API or database drift detected in this PR.';
      await postOrUpdateComment(octokit, owner, repo, pullNumber, commentBody);
    }
    
    // Enhanced exit code handling with policy override reasoning
    const overrideReason = override === 'true' ? 'Manual override enabled' : null;
    
    // Apply override policy to results if enabled
    if (overrideReason) {
      driftResults.forEach(result => {
        riskScorer.applyOverride(result, overrideReason);
      });
    }
    
    // Risk-based exit code logic (transparent and configurable)
    const totalDriftCount = driftResults.length;
    const highSeverityCount = driftResults.filter(r => r.severity === 'high').length;
    const mediumSeverityCount = driftResults.filter(r => r.severity === 'medium').length;
    const lowSeverityCount = driftResults.filter(r => r.severity === 'low').length;
    
    if (hasHighSeverity && override !== 'true') {
      const severityBreakdown = [];
      if (highSeverityCount > 0) severityBreakdown.push(`${highSeverityCount} high`);
      if (mediumSeverityCount > 0) severityBreakdown.push(`${mediumSeverityCount} medium`);
      if (lowSeverityCount > 0) severityBreakdown.push(`${lowSeverityCount} low`);
      
      core.setFailed(`High severity drift detected (${totalDriftCount} total issue${totalDriftCount !== 1 ? 's' : ''}: ${severityBreakdown.join(', ')}). Blocking merge to prevent breaking changes.`);
    } else if (hasMediumSeverity && failOnMedium === 'true' && override !== 'true') {
      core.setFailed(`Medium severity drift detected (${mediumSeverityCount} issue${mediumSeverityCount !== 1 ? 's' : ''}) and fail_on_medium is enabled. Blocking merge.`);
    } else if ((hasHighSeverity || hasMediumSeverity) && override === 'true') {
      const totalIssues = highSeverityCount + mediumSeverityCount;
      core.warning(`Policy override applied: ${totalIssues} drift issue${totalIssues !== 1 ? 's' : ''} detected but merge allowed with audit trail. Reason: ${overrideReason}`);
    } else if (driftResults.length === 0) {
      core.info('No drift detected - merge allowed.');
    } else {
      core.info(`Low severity drift detected (${lowSeverityCount} issue${lowSeverityCount !== 1 ? 's' : ''}) - merge allowed.`);
    }
    
    core.info('DriftControl analysis completed successfully');
    
  } catch (error) {
    core.error(`Error: ${error.message}`);
    core.setFailed(error.message);
  }
}


// Helper function to generate stable artifact ID for consistent matching
// Normalize paths and API endpoints
const normPath = (p) => p ? p.replace(/\\/g, '/').replace(/\/+/g, '/').replace(/\/$/, '').replace(/^\.\//, '') : '';
const normApi = (ep) => {
  if (!ep) return 'api:unknown';
  const parts = ep.split(':');
  const hasMethod = parts.length > 1;
  const method = (hasMethod ? parts[0] : 'GET').toUpperCase();
  const path = normPath((hasMethod ? parts.slice(1).join(':') : ep)
    .toLowerCase()
    .replace(/\{[^}]+\}/g, m => m.toLowerCase())); // Normalize placeholders
  return `api:${method}:${path}`;
};

function getArtifactId(result) {
  if (!result) return 'unknown';
  if (result.id) return result.id; // Pre-computed if available
  
  // API: normalize method:path
  if (result.type === 'api' && result.endpoints && result.endpoints[0]) {
    return normApi(result.endpoints[0]);
  }
  
  // Database: lowercase table name
  if (result.type === 'database' && result.entities && result.entities[0]) {
    return `db:table:${result.entities[0].toLowerCase()}`;
  }
  
  // Infrastructure: resource type and ID
  if (result.type === 'infrastructure' && result.resources && result.resources[0]) {
    const resourceType = (result.resourceType || 'resource').toLowerCase();
    return `iac:${resourceType}:${result.resources[0].toLowerCase()}`;
  }
  
  // Configuration files
  if (result.type === 'configuration' && result.file) {
    return `config:${normPath(result.file)}`;
  }
  
  // File-based fallback: normalize path
  if (result.file) return `file:${normPath(result.file)}`;
  
  // Type-based fallback
  return `${result.type}:${result.name || result.severity || 'unknown'}`.toLowerCase();
}

// Canonical pair key for undirected pairs
function getPairKey(a, b) {
  const A = getArtifactId(a);
  const B = getArtifactId(b);
  return A < B ? `${A}::${B}` : `${B}::${A}`; // Canonical ordering
}

// Expand multi-item results into atomic artifacts
function expandResults(driftResults) {
  const expanded = [];
  for (const r of driftResults) {
    if (r.type === 'api' && Array.isArray(r.endpoints) && r.endpoints.length > 1) {
      r.endpoints.forEach(ep => expanded.push({ ...r, endpoints: [ep], artifactId: null }));
    } else if (r.type === 'database' && Array.isArray(r.entities) && r.entities.length > 1) {
      r.entities.forEach(t => expanded.push({ ...r, entities: [t], artifactId: null }));
    } else if (r.type === 'infrastructure' && Array.isArray(r.resources) && r.resources.length > 1) {
      r.resources.forEach(res => expanded.push({ ...r, resources: [res], artifactId: null }));
    } else {
      expanded.push(r);
    }
  }
  return expanded;
}

// Shared token matcher for rule resolution
function matchToken(result, token) {
  if (!token) return false;
  const t = String(token).toLowerCase();
  
  const candidates = [
    result.file, result.table, result.name, result.resourceId,
    result.resourceType, result.artifactId,
    ...(result.endpoints || []),
    ...(result.entities || []),
    ...(result.resources || [])
  ].filter(Boolean).map(x => String(x).toLowerCase());
  
  // Check for glob pattern
  if (token.includes('*') || token.includes('?')) {
    return candidates.some(c => micromatch.isMatch(c, t));
  }
  
  // Exact or substring match
  return candidates.some(c => c === t || c.includes(t));
}

// Resolve token to actual artifacts
function resolveTokenToArtifacts(driftResults, token) {
  if (!token) return [];
  return driftResults.filter(r => matchToken(r, token));
}

// Check if a pair involves critical changes that should not be ignored
function isCriticalPair(a, b) {
  const txt = (x) => (x?.changes || []).join(' ') + ' ' + JSON.stringify(x);
  const combined = txt(a) + ' ' + txt(b);
  
  // Destructive database operations
  const hasDbDestructive = /DROP\s+(TABLE|COLUMN)|TRUNCATE|ALTER\s+TABLE.*(SET\s+NOT\s+NULL|TYPE)/i.test(combined);
  
  // Security vulnerabilities
  const hasCve = /CVE-|GHSA-|SECURITY_VULNERABILITY|MALICIOUS_PACKAGE/i.test(combined);
  
  // Wide-open security groups
  const hasWideSg = /0\.0\.0\.0\/0|::\/0|SECURITY_GROUP_DELETION/i.test(combined);
  
  // Secret key changes
  const hasSecretChanges = /SECRET_KEY_REMOVED|SECRET_KEY_ADDED/i.test(combined);
  
  return hasDbDestructive || hasCve || hasWideSg || hasSecretChanges;
}

// Resolve rule pairs to actual artifact pairs
function resolveRulePairsToArtifacts(driftResults, rules) {
  const pairs = new Set();
  
  (rules || []).forEach(rule => {
    if (!rule.source || !rule.target || rule.type === 'ignore') return; // Skip ignore rules
    
    const sources = resolveTokenToArtifacts(driftResults, rule.source);
    const targets = resolveTokenToArtifacts(driftResults, rule.target);
    
    sources.forEach(s => {
      targets.forEach(t => {
        if (s !== t) pairs.add(getPairKey(s, t));
      });
    });
  });
  
  return pairs;
}

// Base class for pluggable correlation strategies
class CorrelationStrategy {
  constructor(name, config = {}) {
    this.name = name;
    this.weight = Math.max(0, Math.min(1, config.weight || 1.0));
    this.enabled = config.enabled !== false;
    this.budget = config.budget || 'low'; // 'low', 'medium', 'high'
  }
  
  async run({ driftResults, files, config, processedPairs, candidatePairs }) {
    // Override in implementations
    return [];
  }
}

// Apply user-defined correlation rules with safety rails
function applyUserDefinedRules(expandedResults, correlationConfig, processedPairs) {
  const correlations = [];
  if (!correlationConfig?.correlationRules) return correlations;
  
  core.info(`Applying ${correlationConfig.correlationRules.length} user-defined correlation rules`);
  
  for (const rule of correlationConfig.correlationRules) {
    // Handle ignore rules with safety rails
    if (rule.type === 'ignore') {
      const sources = resolveTokenToArtifacts(expandedResults, rule.source);
      const targets = resolveTokenToArtifacts(expandedResults, rule.target);
      
      for (const s of sources) {
        for (const t of targets) {
          if (s === t) continue;
          const key = getPairKey(s, t);
          
          // Safety rail: don't ignore critical pairs
          if (isCriticalPair(s, t)) {
            core.warning(`Ignore rule overruled for CRITICAL pair ${key} — rule kept but not applied.`);
            continue;
          }
          
          processedPairs.add(key);
          core.info(`Ignoring correlation: ${key} (${rule.reason || 'user-defined'})`);
        }
      }
      continue;
    }
    
    // Handle explicit mapping rules
    const sources = resolveTokenToArtifacts(expandedResults, rule.source);
    const targets = resolveTokenToArtifacts(expandedResults, rule.target);
    
    sources.forEach(source => {
      targets.forEach(target => {
        if (source !== target) {
          const pairKey = getPairKey(source, target);
          processedPairs.add(pairKey);
          
          correlations.push({
            source,
            target,
            relationship: rule.type,
            confidence: 1.0,
            userDefined: true,
            details: rule.description || `User-defined ${rule.type} correlation`,
            evidence: rule.evidence || [],
            rule
          });
          
          core.info(`Applied user-defined correlation: ${rule.type} between ${getArtifactId(source)} and ${getArtifactId(target)}`);
        }
      });
    });
  }
  
  return correlations;
}

// Select candidate pairs for expensive strategies
function selectCandidatePairs(preliminarySignals, rules, expandedResults, config) {
  const candidates = new Set();
  const thresholds = config?.thresholds || { correlate_min: 0.55 };
  const limits = config?.limits || { top_k_per_source: 3, max_pairs_high_cost: 100 };
  
  // Group by source
  const signalsBySource = new Map();
  preliminarySignals.forEach(signal => {
    const sourceId = getArtifactId(signal.source);
    if (!signalsBySource.has(sourceId)) signalsBySource.set(sourceId, []);
    signalsBySource.get(sourceId).push(signal);
  });
  
  // Select top-K above threshold
  signalsBySource.forEach(signals => {
    signals.sort((a, b) => b.confidence - a.confidence);
    signals.slice(0, limits.top_k_per_source).forEach(signal => {
      if (signal.confidence >= thresholds.correlate_min) {
        candidates.add(getPairKey(signal.source, signal.target));
      }
    });
  });
  
  // Add non-ignore rule pairs only
  const nonIgnoreRules = (rules || []).filter(r => r.type !== 'ignore');
  const rulePairs = resolveRulePairsToArtifacts(expandedResults, nonIgnoreRules);
  rulePairs.forEach(pair => candidates.add(pair));
  
  // Limit total
  if (candidates.size > limits.max_pairs_high_cost) {
    return new Set(Array.from(candidates).slice(0, limits.max_pairs_high_cost));
  }
  
  return candidates;
}

// Helper function to deduplicate evidence by reason, file, and line
function dedupeEvidence(evidenceArray) {
  const seen = new Set();
  const result = [];
  
  evidenceArray.forEach(e => {
    const key = JSON.stringify({ reason: e.reason, file: e.file, line: e.line });
    if (!seen.has(key)) {
      result.push(e);
      seen.add(key);
    }
  });
  
  return result;
}

// Aggregate correlations with correct weighted scoring
function aggregateCorrelations(userCorrelations, strategySignals, strategiesByName, processedPairs, config) {
  const correlationMap = new Map();
  const thresholds = config?.thresholds || { block_min: 0.80 };
  
  // Process user-defined first (explicit strategy)
  userCorrelations.forEach(corr => {
    const key = getPairKey(corr.source, corr.target);
    correlationMap.set(key, {
      ...corr,
      strategies: ['explicit'],
      scores: { explicit: 1.0 },
      weights: { explicit: 1.0 },
      finalScore: 1.0, // Monotonicity rule
      relationships: new Set([corr.relationship]),
      evidence: corr.evidence || [],
      explanation: `User-defined: ${corr.details}`
    });
    processedPairs.add(key);
  });
  
  // Aggregate strategy signals
  strategySignals.forEach((signals, strategyName) => {
    const strategy = strategiesByName[strategyName];
    if (!strategy || !strategy.enabled || !signals) return;
    
    signals.forEach(signal => {
      const key = getPairKey(signal.source, signal.target);
      if (processedPairs.has(key)) return;
      
      let correlation = correlationMap.get(key);
      if (!correlation) {
        correlation = {
          source: signal.source,
          target: signal.target,
          strategies: [],
          scores: {},
          weights: {},
          evidence: [],
          relationships: new Set()
        };
        correlationMap.set(key, correlation);
      }
      
      // Track strategy name (avoid duplicates)
      if (!correlation.strategies.includes(strategyName)) {
        correlation.strategies.push(strategyName);
        correlation.weights[strategyName] = strategy.weight;
      }
      
      // Take max confidence if strategy emits multiple signals for same pair
      const prevScore = correlation.scores[strategyName] ?? -1;
      if (signal.confidence > prevScore) {
        correlation.scores[strategyName] = signal.confidence;
        
        // Track evidence from winning signal per strategy
        correlation._evidenceByStrategy ??= {};
        const structured = (signal.evidence || []).slice(0, 2).map(e => 
          typeof e === 'string' ? { reason: e } : e
        );
        correlation._evidenceByStrategy[strategyName] = structured;
      }
      
      // Track all relationships
      correlation.relationships.add(signal.relationship);
    });
  });
  
  // Consolidate evidence from all strategies and calculate final scores
  correlationMap.forEach(corr => {
    // Consolidate evidence from winning signals per strategy
    if (corr._evidenceByStrategy) {
      const flat = Object.values(corr._evidenceByStrategy).flat();
      corr.evidence = dedupeEvidence(flat).slice(0, 5);
      delete corr._evidenceByStrategy; // Clean up temp field
    }
    // Calculate score with correct weighting
    if (corr.scores.explicit) {
      corr.finalScore = 1.0; // Monotonicity rule
    } else {
      let weightedSum = 0;
      let totalWeight = 0;
      Object.entries(corr.scores).forEach(([name, confidence]) => {
        const weight = corr.weights[name] || 1.0;
        weightedSum += confidence * weight;
        totalWeight += weight;
      });
      corr.finalScore = totalWeight > 0 ? Math.min(1.0, weightedSum / totalWeight) : 0;
    }
    
    // Format for backward compatibility
    corr.relationship = [...corr.relationships].sort().join('|');
    corr.confidence = corr.finalScore;
    
    // Build explanation
    const scoreBreakdown = corr.strategies.map(s => {
      const raw = corr.scores[s];
      const w = corr.weights[s] ?? 1;
      return `${s}:${raw.toFixed(2)}×${w.toFixed(1)}`;
    }).join(', ');
    
    corr.explanation = `${getArtifactId(corr.source)} → ${getArtifactId(corr.target)} = ${corr.finalScore.toFixed(2)} [${scoreBreakdown}]`;
  });
  
  return Array.from(correlationMap.values());
}

// Entity-based correlation strategy
class EntityCorrelationStrategy extends CorrelationStrategy {
  constructor(config) {
    super('entity', config);
  }
  
  async run({ driftResults, files, config, processedPairs, candidatePairs }) {
    const correlations = [];
    const apiChanges = driftResults.filter(r => r.type === 'api');
    const dbChanges = driftResults.filter(r => r.type === 'database');
    
    for (const api of apiChanges) {
      for (const db of dbChanges) {
        const pairKey = getPairKey(api, db);
        
        // Skip if processed
        if (processedPairs.has(pairKey)) continue;
        
        // Skip if not a candidate (for medium/high cost strategies)
        if (this.budget !== 'low' && candidatePairs && !candidatePairs.has(pairKey)) continue;
        
        // Use detectRelation for sophisticated matching
        if (detectRelation(api, db)) {
          const apiEntities = api.metadata?.entities || [];
          const dbEntities = db.metadata?.entities || [];
          
          let bestMatch = { confidence: 0 };
          apiEntities.forEach(apiEntity => {
            dbEntities.forEach(dbEntity => {
              const apiVars = generateEntityVariations(apiEntity);
              const dbVars = generateEntityVariations(dbEntity);
              const match = findBestMatch(apiVars, dbVars);
              if (match.confidence > bestMatch.confidence) {
                bestMatch = { ...match, apiEntity, dbEntity };
              }
            });
          });
          
          if (bestMatch.confidence > 0.6) {
            correlations.push({
              source: api,
              target: db,
              relationship: 'api_uses_table',
              confidence: bestMatch.confidence,
              evidence: [`API entity '${bestMatch.apiEntity}' correlates with table '${bestMatch.dbEntity}'`]
            });
          }
        }
      }
    }
    
    return correlations;
  }
}

// Operation-based correlation strategy
class OperationCorrelationStrategy extends CorrelationStrategy {
  constructor(config) {
    super('operation', config);
  }
  
  async run({ driftResults, files, config, processedPairs, candidatePairs }) {
    const correlations = [];
    const apiChanges = driftResults.filter(r => r.type === 'api');
    const dbChanges = driftResults.filter(r => r.type === 'database');
    
    for (const api of apiChanges) {
      for (const db of dbChanges) {
        const pairKey = getPairKey(api, db);
        
        if (processedPairs.has(pairKey)) continue;
        if (this.budget !== 'low' && candidatePairs && !candidatePairs.has(pairKey)) continue;
        
        const apiOps = api.metadata?.operations || [];
        const dbOps = db.metadata?.operations || [];
        
        if (apiOps.length > 0 && dbOps.length > 0) {
          const matchingOps = apiOps.filter(op => dbOps.includes(op));
          if (matchingOps.length > 0) {
            const confidence = Math.min(0.9, 0.6 + (matchingOps.length * 0.1));
            correlations.push({
              source: api,
              target: db,
              relationship: 'operation_alignment',
              confidence: confidence,
              evidence: [`Aligned operations: ${matchingOps.join(', ')}`]
            });
          }
        }
      }
    }
    
    return correlations;
  }
}

// Infrastructure correlation strategy
class InfrastructureCorrelationStrategy extends CorrelationStrategy {
  constructor(config) {
    super('infrastructure', config);
    this.budget = config.budget || 'medium';
  }
  
  async run({ driftResults, files, config, processedPairs, candidatePairs }) {
    const correlations = [];
    const iacChanges = driftResults.filter(r => r.type === 'infrastructure');
    const configChanges = driftResults.filter(r => r.type === 'configuration');
    const apiChanges = driftResults.filter(r => r.type === 'api');
    
    // Infrastructure to configuration
    for (const iac of iacChanges) {
      for (const cfg of configChanges) {
        const pairKey = getPairKey(iac, cfg);
        
        if (processedPairs.has(pairKey)) continue;
        if (this.budget !== 'low' && candidatePairs && !candidatePairs.has(pairKey)) continue;
        
        if ((iac.file?.includes('terraform') || iac.file?.includes('cloudformation')) && 
            (cfg.file?.includes('env') || cfg.file?.includes('config'))) {
          correlations.push({
            source: iac,
            target: cfg,
            relationship: 'infra_affects_config',
            confidence: 0.7,
            evidence: ['Infrastructure change may affect application configuration']
          });
        }
        
        // Check for resource dependencies
        if (iac.resources && cfg.dependencies) {
          const sharedResources = [];
          iac.resources.forEach(resource => {
            cfg.dependencies.forEach(dep => {
              const resourceVars = generateEntityVariations(resource);
              const depVars = generateEntityVariations(dep);
              const match = findBestMatch(resourceVars, depVars);
              if (match.confidence > 0.7) {
                sharedResources.push(resource);
              }
            });
          });
          
          if (sharedResources.length > 0) {
            correlations.push({
              source: iac,
              target: cfg,
              relationship: 'resource_dependency',
              confidence: 0.75,
              evidence: [`Shared resources: ${sharedResources.join(', ')}`]
            });
          }
        }
      }
      
      // Infrastructure to API
      for (const api of apiChanges) {
        const pairKey = getPairKey(iac, api);
        
        if (processedPairs.has(pairKey)) continue;
        if (this.budget !== 'low' && candidatePairs && !candidatePairs.has(pairKey)) continue;
        
        if (iac.resources) {
          const apiRelatedTerms = ['api', 'gateway', 'function', 'lambda', 'endpoint', 'service'];
          const isApiInfra = iac.resources.some(r => {
            const rLower = r.toLowerCase();
            return apiRelatedTerms.some(term => rLower.includes(term));
          });
          
          if (isApiInfra) {
            correlations.push({
              source: iac,
              target: api,
              relationship: 'infra_hosts_api',
              confidence: 0.75,
              evidence: ['Infrastructure changes affect API deployment']
            });
          }
        }
      }
    }
    
    return correlations;
  }
}

// Dependency correlation strategy
class DependencyCorrelationStrategy extends CorrelationStrategy {
  constructor(config) {
    super('dependency', config);
  }
  
  async run({ driftResults, files, config, processedPairs, candidatePairs }) {
    const correlations = [];
    const packageChanges = driftResults.filter(r => 
      r.type === 'configuration' && r.file?.includes('package')
    );
    const apiChanges = driftResults.filter(r => r.type === 'api');
    const dbChanges = driftResults.filter(r => r.type === 'database');
    
    for (const pkg of packageChanges) {
      const pkgDeps = pkg.metadata?.dependencies || [];
      
      // Link package changes to API
      for (const api of apiChanges) {
        const pairKey = getPairKey(pkg, api);
        
        if (processedPairs.has(pairKey)) continue;
        if (this.budget !== 'low' && candidatePairs && !candidatePairs.has(pairKey)) continue;
        
        if (pkgDeps.length > 0) {
          const apiDeps = pkgDeps.filter(dep => {
            const depLower = dep.toLowerCase();
            return depLower.includes('express') || depLower.includes('fastify') || 
                   depLower.includes('koa') || depLower.includes('hapi') ||
                   depLower.includes('swagger') || depLower.includes('openapi');
          });
          
          if (apiDeps.length > 0) {
            correlations.push({
              source: pkg,
              target: api,
              relationship: 'dependency_affects_api',
              confidence: 0.8,
              evidence: [`API-related dependencies changed: ${apiDeps.join(', ')}`]
            });
          }
        }
      }
      
      // Link package changes to database
      for (const db of dbChanges) {
        const pairKey = getPairKey(pkg, db);
        
        if (processedPairs.has(pairKey)) continue;
        if (this.budget !== 'low' && candidatePairs && !candidatePairs.has(pairKey)) continue;
        
        if (pkgDeps.length > 0) {
          const dbDeps = pkgDeps.filter(dep => {
            const depLower = dep.toLowerCase();
            return depLower.includes('sequelize') || depLower.includes('typeorm') ||
                   depLower.includes('prisma') || depLower.includes('knex') ||
                   depLower.includes('mongoose') || depLower.includes('pg') ||
                   depLower.includes('mysql') || depLower.includes('sqlite');
          });
          
          if (dbDeps.length > 0) {
            correlations.push({
              source: pkg,
              target: db,
              relationship: 'dependency_affects_db',
              confidence: 0.8,
              evidence: [`Database-related dependencies changed: ${dbDeps.join(', ')}`]
            });
          }
        }
      }
    }
    
    return correlations;
  }
}

// Temporal correlation strategy (disabled by default as it's noisy)
class TemporalCorrelationStrategy extends CorrelationStrategy {
  constructor(config) {
    super('temporal', config);
    this.enabled = config.enabled || false; // Disabled by default
  }
  
  async run({ driftResults, files, config, processedPairs, candidatePairs }) {
    const correlations = [];
    
    // Safe directory extraction
    const getDir = (p) => (p && p.includes('/')) ? p.slice(0, p.lastIndexOf('/')) : '';
    
    // Find drift results in the same directory
    for (let i = 0; i < driftResults.length; i++) {
      const result1 = driftResults[i];
      if (!result1.file) continue;
      
      const dir1 = getDir(result1.file);
      
      for (let j = i + 1; j < driftResults.length; j++) {
        const result2 = driftResults[j];
        if (!result2.file) continue;
        
        const pairKey = getPairKey(result1, result2);
        
        if (processedPairs.has(pairKey)) continue;
        if (this.budget !== 'low' && candidatePairs && !candidatePairs.has(pairKey)) continue;
        
        const dir2 = getDir(result2.file);
        
        if (dir1 === dir2) {
          correlations.push({
            source: result1,
            target: result2,
            relationship: 'temporal_correlation',
            confidence: 0.65,
            evidence: ['Files changed in the same directory']
          });
        }
      }
    }
    
    return correlations;
  }
}

// Main cross-layer correlation function
async function correlateAcrossLayers(driftResults, files, correlationConfig = null) {
  const processedPairs = new Set();
  const strategiesByName = {};
  
  // Expand multi-item results into atomic artifacts
  const expandedResults = expandResults(driftResults);
  
  // Build metadata and IDs for expanded results
  expandedResults.forEach(result => {
    if (!result.metadata) {
      result.metadata = extractMetadata(result, files);
    }
    result.artifactId = getArtifactId(result);
  });
  
  // Initialize strategies with config
  const strategyConfig = correlationConfig?.strategyConfig || {};
  const strategies = [
    new EntityCorrelationStrategy(strategyConfig.entity || {}),
    new OperationCorrelationStrategy(strategyConfig.operation || {}),
    new InfrastructureCorrelationStrategy(strategyConfig.infrastructure || {}),
    new DependencyCorrelationStrategy(strategyConfig.dependency || {}),
    new TemporalCorrelationStrategy(strategyConfig.temporal || { enabled: false })
  ].filter(s => s.enabled); // Only include enabled strategies
  
  strategies.forEach(s => strategiesByName[s.name] = s);
  
  // Apply user-defined rules first
  const userCorrelations = applyUserDefinedRules(expandedResults, correlationConfig, processedPairs);
  
  // Run low-cost strategies with timing
  const strategySignals = new Map();
  const lowCostStrategies = strategies.filter(s => s.budget === 'low');
  
  for (const strategy of lowCostStrategies) {
    const t0 = Date.now();
    const signals = await strategy.run({
      driftResults: expandedResults, 
      files, 
      config: correlationConfig,
      processedPairs, 
      candidatePairs: null
    });
    core.debug(`[${strategy.name}] ${signals.length} signals in ${Date.now()-t0}ms`);
    strategySignals.set(strategy.name, signals);
  }
  
  // Select candidates
  const preliminarySignals = Array.from(strategySignals.values()).flat();
  const candidatePairs = selectCandidatePairs(
    preliminarySignals,
    correlationConfig?.correlationRules,
    expandedResults,
    correlationConfig
  );
  core.debug(`Selected ${candidatePairs.size} candidate pairs for expensive strategies`);
  
  // Run expensive strategies on candidates
  const expensiveStrategies = strategies.filter(s => s.budget !== 'low');
  for (const strategy of expensiveStrategies) {
    const t0 = Date.now();
    const signals = await strategy.run({
      driftResults: expandedResults, 
      files, 
      config: correlationConfig,
      processedPairs, 
      candidatePairs
    });
    core.debug(`[${strategy.name}] ${signals.length} signals in ${Date.now()-t0}ms`);
    strategySignals.set(strategy.name, signals);
  }
  
  // Aggregate
  return aggregateCorrelations(
    userCorrelations, 
    strategySignals, 
    strategiesByName,
    processedPairs, 
    correlationConfig
  );
}

// Legacy correlation function has been removed - replaced with strategy-based system

function detectRelation(apiResult, dbResult) {
  const correlations = [];
  
  // Extract relevant data from results
  const apiPath = apiResult.file || '';
  const apiEndpoints = apiResult.endpoints || [];
  const apiMetadata = apiResult.metadata || extractMetadata(apiResult, []);
  
  const dbContent = (dbResult.changes || []).join(' ');
  const dbEntities = dbResult.entities || [];
  const dbMetadata = dbResult.metadata || extractMetadata(dbResult, []);
  
  // 1. Entity-based correlation with semantic matching
  const pathSegments = apiPath.split('/').filter(s => s && !s.includes('{') && !s.includes(':'));
  const apiPathEntities = apiEndpoints.concat(pathSegments).filter(e => e && e.length > 2);
  
  // Extract table names with confidence scoring
  const tableNames = extractTableNamesWithConfidence(dbContent);
  const allDbEntities = [...new Set([...dbEntities, ...tableNames.map(t => t.name)])];
  
  // Match using singular/plural forms and common naming patterns
  apiPathEntities.forEach(apiEntity => {
    const apiVariations = generateEntityVariations(apiEntity);
    
    allDbEntities.forEach(dbEntity => {
      const dbVariations = generateEntityVariations(dbEntity);
      const match = findBestMatch(apiVariations, dbVariations);
      
      if (match.confidence > 0.6) {
        correlations.push({
          type: 'entity_match',
          apiEntity: apiEntity,
          dbTable: dbEntity,
          confidence: match.confidence,
          reasoning: `API entity '${apiEntity}' correlates with database table '${dbEntity}'`
        });
      }
    });
  });
  
  // 2. Field-level correlation
  if (apiMetadata.fields && apiMetadata.fields.length > 0 && dbMetadata.fields && dbMetadata.fields.length > 0) {
    const fieldMatches = correlateFields(apiMetadata.fields, dbMetadata.fields);
    correlations.push(...fieldMatches);
  }
  
  // 3. Operation correlation (CRUD mapping)
  const apiOperations = detectApiOperations(apiPath, apiResult);
  const dbOperations = detectDbOperations(dbContent);
  
  if (operationsCorrelate(apiOperations, dbOperations)) {
    correlations.push({
      type: 'operation_match',
      confidence: 0.8,
      reasoning: 'API and database operations are aligned (CRUD pattern match)'
    });
  }
  
  // Return highest confidence correlation
  if (correlations.length > 0) {
    correlations.sort((a, b) => b.confidence - a.confidence);
    return correlations[0].confidence > 0.6; // Only return true for high-confidence matches
  }
  
  return false;
}

function identifyRootCauses(correlations, driftResults) {
  const rootCauses = [];
  
  // Find nodes with only outgoing edges (potential root causes)
  const incomingCount = new Map();
  const outgoingCount = new Map();
  
  driftResults.forEach(r => {
    incomingCount.set(r, 0);
    outgoingCount.set(r, 0);
  });
  
  correlations.forEach(c => {
    incomingCount.set(c.target, (incomingCount.get(c.target) || 0) + 1);
    outgoingCount.set(c.source, (outgoingCount.get(c.source) || 0) + 1);
  });
  
  // A root cause has outgoing edges but no incoming edges
  driftResults.forEach(result => {
    const incoming = incomingCount.get(result) || 0;
    const outgoing = outgoingCount.get(result) || 0;
    
    if (incoming === 0 && outgoing > 0) {
      rootCauses.push({
        result,
        type: 'root_cause',
        confidence: Math.min(0.9, 0.6 + (outgoing * 0.1)) // Higher confidence with more impacts
      });
    }
  });
  
  // If no clear root causes found, identify nodes with highest impact
  if (rootCauses.length === 0 && correlations.length > 0) {
    const impactScores = new Map();
    
    driftResults.forEach(result => {
      const outgoing = outgoingCount.get(result) || 0;
      const incoming = incomingCount.get(result) || 0;
      const score = outgoing - (incoming * 0.5); // Favor nodes with more outgoing than incoming
      impactScores.set(result, score);
    });
    
    // Find the highest impact node
    let maxScore = -1;
    let maxResult = null;
    
    impactScores.forEach((score, result) => {
      if (score > maxScore) {
        maxScore = score;
        maxResult = result;
      }
    });
    
    if (maxResult && maxScore > 0) {
      rootCauses.push({
        result: maxResult,
        type: 'likely_root_cause',
        confidence: Math.min(0.7, 0.4 + (maxScore * 0.1))
      });
    }
  }
  
  return rootCauses;
}

// Helper functions for sophisticated correlation analysis

// Extract metadata with confidence scoring
function extractMetadata(result, files) {
  const metadata = {
    entities: [],
    operations: [],
    fields: [],
    dependencies: []
  };
  
  if (result.type === 'api') {
    // Extract API entities from paths and endpoints
    if (result.file) {
      const pathParts = result.file.split('/').filter(p => p && !p.includes('.'));
      metadata.entities.push(...pathParts);
    }
    if (result.endpoints) {
      metadata.entities.push(...result.endpoints.map(e => e.replace(/^\//g, '').split('/')[0]).filter(e => e));
    }
    
    // Extract operations from API changes
    if (result.changes) {
      result.changes.forEach(change => {
        if (change.includes('POST') || change.includes('CREATE')) metadata.operations.push('create');
        if (change.includes('GET') || change.includes('READ')) metadata.operations.push('read');
        if (change.includes('PUT') || change.includes('PATCH') || change.includes('UPDATE')) metadata.operations.push('update');
        if (change.includes('DELETE')) metadata.operations.push('delete');
      });
    }
  } else if (result.type === 'database') {
    // Extract database entities
    if (result.entities) {
      metadata.entities.push(...result.entities);
    }
    
    // Extract table names from SQL content
    if (result.changes) {
      const sqlContent = result.changes.join(' ');
      const tables = extractTableNamesWithConfidence(sqlContent);
      metadata.entities.push(...tables.map(t => t.name));
      
      // Extract operations
      if (sqlContent.match(/CREATE\s+TABLE/i)) metadata.operations.push('create');
      if (sqlContent.match(/SELECT/i)) metadata.operations.push('read');
      if (sqlContent.match(/UPDATE|ALTER/i)) metadata.operations.push('update');
      if (sqlContent.match(/DELETE|DROP/i)) metadata.operations.push('delete');
    }
  } else if (result.type === 'configuration') {
    // Extract dependencies from package changes
    if (result.changes) {
      result.changes.forEach(change => {
        const depMatch = change.match(/DEPENDENCY:\s*(\S+)/);
        if (depMatch) metadata.dependencies.push(depMatch[1]);
      });
    }
  }
  
  // Remove duplicates
  metadata.entities = [...new Set(metadata.entities)];
  metadata.operations = [...new Set(metadata.operations)];
  metadata.fields = [...new Set(metadata.fields)];
  metadata.dependencies = [...new Set(metadata.dependencies)];
  
  return metadata;
}

// Extract table names with confidence scoring
function extractTableNamesWithConfidence(sqlContent) {
  const tables = new Map();
  const patterns = [
    { regex: /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"']?(\w+)[`"']?/gi, confidence: 1.0 },
    { regex: /ALTER\s+TABLE\s+[`"']?(\w+)[`"']?/gi, confidence: 0.9 },
    { regex: /DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?[`"']?(\w+)[`"']?/gi, confidence: 1.0 },
    { regex: /UPDATE\s+[`"']?(\w+)[`"']?\s+SET/gi, confidence: 0.8 },
    { regex: /INSERT\s+INTO\s+[`"']?(\w+)[`"']?/gi, confidence: 0.8 },
    { regex: /DELETE\s+FROM\s+[`"']?(\w+)[`"']?/gi, confidence: 0.8 },
    { regex: /FROM\s+[`"']?(\w+)[`"']?/gi, confidence: 0.7 },
    { regex: /JOIN\s+[`"']?(\w+)[`"']?/gi, confidence: 0.7 }
  ];
  
  patterns.forEach(pattern => {
    let match;
    while ((match = pattern.regex.exec(sqlContent)) !== null) {
      const tableName = match[1].toLowerCase();
      // Skip common SQL keywords that might be captured
      if (['select', 'from', 'where', 'and', 'or', 'as', 'on', 'set'].includes(tableName)) continue;
      
      const existing = tables.get(tableName);
      if (!existing || existing.confidence < pattern.confidence) {
        tables.set(tableName, { name: tableName, confidence: pattern.confidence });
      }
    }
  });
  
  return Array.from(tables.values());
}

// Generate entity name variations for matching
function generateEntityVariations(entity) {
  if (!entity || typeof entity !== 'string') return [];
  
  const variations = new Set();
  const base = entity.trim();
  const baseLower = base.toLowerCase();
  
  // Add base forms
  variations.add(baseLower);
  
  // Also handle original case for camelCase detection
  if (base !== baseLower) {
    // Convert camelCase to snake_case
    const snakeFromCamel = base.replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase();
    variations.add(snakeFromCamel);
  }
  
  // Singular/plural forms (use lowercase base for consistency)
  if (baseLower.endsWith('ies')) {
    // entities -> entity, categories -> category
    variations.add(baseLower.slice(0, -3) + 'y');
    // Also try just removing 's' for words like categories -> categorie
    variations.add(baseLower.slice(0, -1));
  } else if (baseLower.endsWith('es')) {
    // branches -> branch
    variations.add(baseLower.slice(0, -2));
    // Also try just removing 's'
    variations.add(baseLower.slice(0, -1));
  } else if (baseLower.endsWith('s') && !baseLower.endsWith('ss')) {
    // users -> user
    variations.add(baseLower.slice(0, -1));
  } else {
    // user -> users
    variations.add(baseLower + 's');
    variations.add(baseLower + 'es');
  }
  
  // Handle camelCase to snake_case and vice versa
  if (baseLower.includes('_')) {
    // snake_case input: convert to camelCase  
    const camelCase = baseLower.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
    variations.add(camelCase);
    // Also try without underscores
    variations.add(baseLower.replace(/_/g, ''));
  } else {
    // Try detecting word boundaries for snake_case conversion
    const snakeCase = baseLower.replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase();
    if (snakeCase !== baseLower) variations.add(snakeCase);
    
    // Try removing underscores
    const noUnderscore = baseLower.replace(/_/g, '');
    if (noUnderscore !== baseLower) variations.add(noUnderscore);
  }
  
  // Remove common prefixes/suffixes
  const prefixes = ['tbl_', 'table_', 'vw_', 'view_'];
  const suffixes = ['_table', '_tbl', '_view', '_vw'];
  
  prefixes.forEach(prefix => {
    if (base.startsWith(prefix)) {
      variations.add(base.slice(prefix.length));
    }
  });
  
  suffixes.forEach(suffix => {
    if (base.endsWith(suffix)) {
      variations.add(base.slice(0, -suffix.length));
    }
  });
  
  return Array.from(variations);
}

// Find best match between two sets of variations
function findBestMatch(variations1, variations2) {
  let bestConfidence = 0;
  let bestMatch = null;
  
  for (const v1 of variations1) {
    for (const v2 of variations2) {
      let confidence = 0;
      
      // Exact match
      if (v1 === v2) {
        confidence = 1.0;
      }
      // Substring match
      else if (v1.includes(v2) || v2.includes(v1)) {
        confidence = 0.8;
      }
      // Levenshtein distance for close matches
      else {
        const distance = levenshteinDistance(v1, v2);
        const maxLen = Math.max(v1.length, v2.length);
        const similarity = 1 - (distance / maxLen);
        if (similarity > 0.7) {
          confidence = similarity * 0.9; // Scale down slightly for fuzzy matches
        }
      }
      
      if (confidence > bestConfidence) {
        bestConfidence = confidence;
        bestMatch = { v1, v2 };
      }
    }
  }
  
  return { confidence: bestConfidence, match: bestMatch };
}

// Calculate Levenshtein distance
function levenshteinDistance(str1, str2) {
  const m = str1.length;
  const n = str2.length;
  const dp = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));
  
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (str1[i - 1] === str2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = Math.min(
          dp[i - 1][j] + 1,    // deletion
          dp[i][j - 1] + 1,    // insertion
          dp[i - 1][j - 1] + 1 // substitution
        );
      }
    }
  }
  
  return dp[m][n];
}

// Correlate fields between API and database
function correlateFields(apiFields, dbFields) {
  const correlations = [];
  
  apiFields.forEach(apiField => {
    const apiVariations = generateEntityVariations(apiField);
    
    dbFields.forEach(dbField => {
      const dbVariations = generateEntityVariations(dbField);
      const match = findBestMatch(apiVariations, dbVariations);
      
      if (match.confidence > 0.7) {
        correlations.push({
          type: 'field_match',
          apiField: apiField,
          dbField: dbField,
          confidence: match.confidence,
          reasoning: `API field '${apiField}' maps to database column '${dbField}'`
        });
      }
    });
  });
  
  return correlations;
}

// Detect API operations from path and result
function detectApiOperations(apiPath, apiResult) {
  const operations = new Set();
  
  // Check path patterns
  if (apiPath.match(/\/create|\/add|\/new/i)) operations.add('create');
  if (apiPath.match(/\/get|\/list|\/search|\/find/i)) operations.add('read');
  if (apiPath.match(/\/update|\/edit|\/modify/i)) operations.add('update');
  if (apiPath.match(/\/delete|\/remove/i)) operations.add('delete');
  
  // Check changes for operation keywords
  if (apiResult.changes) {
    apiResult.changes.forEach(change => {
      const upperChange = change.toUpperCase();
      if (upperChange.includes('POST') || upperChange.includes('CREATE')) operations.add('create');
      if (upperChange.includes('GET') || upperChange.includes('READ')) operations.add('read');
      if (upperChange.includes('PUT') || upperChange.includes('PATCH') || upperChange.includes('UPDATE')) operations.add('update');
      if (upperChange.includes('DELETE') || upperChange.includes('REMOVE')) operations.add('delete');
    });
  }
  
  return Array.from(operations);
}

// Detect database operations from SQL content
function detectDbOperations(dbContent) {
  const operations = new Set();
  const upperContent = dbContent.toUpperCase();
  
  if (upperContent.match(/CREATE\s+TABLE|INSERT\s+INTO/)) operations.add('create');
  if (upperContent.match(/SELECT\s+/)) operations.add('read');
  if (upperContent.match(/UPDATE\s+|ALTER\s+TABLE/)) operations.add('update');
  if (upperContent.match(/DELETE\s+FROM|DROP\s+TABLE|TRUNCATE/)) operations.add('delete');
  
  return Array.from(operations);
}

// Check if operations correlate
function operationsCorrelate(apiOps, dbOps) {
  if (apiOps.length === 0 || dbOps.length === 0) return false;
  
  // Check for any matching operations
  const intersection = apiOps.filter(op => dbOps.includes(op));
  return intersection.length > 0;
}

// Export helper functions for integration testing
module.exports = {
  run,
  generateCommentBody: require('./comment-generator').generateCommentBody,
  generateFixSuggestion: require('./comment-generator').generateFixSuggestion,
  postOrUpdateComment: require('./github-api').postOrUpdateComment,
  correlateAcrossLayers,
  detectRelation,
  identifyRootCauses,
  // Export new helper functions for testing
  extractMetadata,
  extractTableNamesWithConfidence,
  generateEntityVariations,
  findBestMatch,
  correlateFields,
  detectApiOperations,
  detectDbOperations,
  operationsCorrelate,
  getArtifactId,
  // New correlation engine exports
  getPairKey,
  expandResults,
  isCriticalPair,
  resolveTokenToArtifacts,
  matchToken,
  applyUserDefinedRules,
  selectCandidatePairs,
  aggregateCorrelations,
  dedupeEvidence,
  // Strategy classes
  CorrelationStrategy,
  EntityCorrelationStrategy,
  OperationCorrelationStrategy,
  InfrastructureCorrelationStrategy,
  DependencyCorrelationStrategy,
  TemporalCorrelationStrategy
};

// Only run if called directly (not imported)
if (require.main === module) {
  run();
}