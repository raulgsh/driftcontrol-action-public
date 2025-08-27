const core = require('@actions/core');
const github = require('@actions/github');
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
      // Build correlation graph from existing results
      const correlations = correlateAcrossLayers(driftResults, files);
      
      // Identify root causes
      const rootCauses = identifyRootCauses(correlations, driftResults);
      
      // Enhance results with correlation data
      driftResults.forEach(result => {
        result.correlations = correlations.filter(c => 
          c.source === result || c.target === result
        );
        result.rootCause = rootCauses.find(r => r.result === result);
      });
      
      core.info(`Correlation analysis: found ${correlations.length} relationships and ${rootCauses.length} root causes`);
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


// Cross-layer correlation helper functions
function correlateAcrossLayers(driftResults, files) {
  const correlations = [];
  
  // Link API changes to DB schema
  const apiChanges = driftResults.filter(r => r.type === 'api');
  const dbChanges = driftResults.filter(r => r.type === 'database');
  
  apiChanges.forEach(api => {
    dbChanges.forEach(db => {
      // Check if API endpoint relates to DB table
      const apiPath = api.file ? api.file.toLowerCase() : '';
      const dbContent = db.changes ? db.changes.join(' ').toLowerCase() : '';
      
      if (detectRelation(apiPath, dbContent)) {
        correlations.push({
          source: api,
          target: db,
          relationship: 'api_uses_table',
          confidence: 0.8
        });
      }
      
      // Check for matching entity names
      if (db.entities && api.endpoints) {
        const matchingEntities = db.entities.filter(entity => 
          api.endpoints.some(endpoint => endpoint.toLowerCase().includes(entity.toLowerCase()))
        );
        if (matchingEntities.length > 0) {
          correlations.push({
            source: api,
            target: db,
            relationship: 'shared_entity',
            confidence: 0.9
          });
        }
      }
    });
  });
  
  // Connect IaC to application code
  const iacChanges = driftResults.filter(r => r.type === 'infrastructure');
  const configChanges = driftResults.filter(r => r.type === 'configuration');
  
  iacChanges.forEach(iac => {
    configChanges.forEach(config => {
      // Check for environment variable relationships
      if ((iac.file && iac.file.includes('terraform')) && 
          (config.file && (config.file.includes('env') || config.file.includes('config')))) {
        correlations.push({
          source: iac,
          target: config,
          relationship: 'infra_affects_config',
          confidence: 0.7
        });
      }
      
      // Check for resource dependencies
      if (iac.resources && config.dependencies) {
        const sharedResources = iac.resources.filter(resource =>
          config.dependencies.some(dep => dep.toLowerCase().includes(resource.toLowerCase()))
        );
        if (sharedResources.length > 0) {
          correlations.push({
            source: iac,
            target: config,
            relationship: 'resource_dependency',
            confidence: 0.8
          });
        }
      }
    });
    
    // Link infrastructure to API changes
    apiChanges.forEach(api => {
      if (iac.resources && api.file) {
        // Check if infrastructure change affects API deployment
        const isApiInfra = iac.resources.some(r => 
          r.toLowerCase().includes('api') || 
          r.toLowerCase().includes('gateway') ||
          r.toLowerCase().includes('function')
        );
        if (isApiInfra) {
          correlations.push({
            source: iac,
            target: api,
            relationship: 'infra_hosts_api',
            confidence: 0.7
          });
        }
      }
    });
  });
  
  // Map dependencies
  const packageChanges = driftResults.filter(r => 
    r.type === 'configuration' && r.file && r.file.includes('package')
  );
  
  packageChanges.forEach(pkg => {
    // Link package changes to API
    apiChanges.forEach(api => {
      if (pkg.changes && pkg.changes.some(c => c.includes('DEPENDENCY'))) {
        correlations.push({
          source: pkg,
          target: api,
          relationship: 'dependency_affects_api',
          confidence: 0.6
        });
      }
    });
    
    // Link package changes to database migrations
    dbChanges.forEach(db => {
      if (pkg.changes && pkg.changes.some(c => 
        c.toLowerCase().includes('orm') || 
        c.toLowerCase().includes('database') ||
        c.toLowerCase().includes('sql'))) {
        correlations.push({
          source: pkg,
          target: db,
          relationship: 'dependency_affects_db',
          confidence: 0.6
        });
      }
    });
  });
  
  return correlations;
}

function detectRelation(apiPath, dbContent) {
  // Simple heuristic: check if API path contains table name
  const tableMatches = dbContent.match(/(\w+)[\s_]table|table[\s_]+(\w+)|drop\s+table\s+(\w+)|create\s+table\s+(\w+)/gi) || [];
  const tableNames = tableMatches.map(match => {
    const cleanMatch = match.replace(/[\s_]?table[\s_]?/gi, '').replace(/drop|create/gi, '').trim();
    return cleanMatch.toLowerCase();
  }).filter(name => name.length > 0);
  
  return tableNames.some(table => {
    // Check if API path contains the table name (singular or plural)
    const singular = table.replace(/s$/, '');
    const plural = table.endsWith('s') ? table : table + 's';
    return apiPath.includes(singular) || apiPath.includes(plural);
  });
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

// Export helper functions for integration testing
module.exports = {
  run,
  generateCommentBody: require('./comment-generator').generateCommentBody,
  generateFixSuggestion: require('./comment-generator').generateFixSuggestion,
  postOrUpdateComment: require('./github-api').postOrUpdateComment,
  correlateAcrossLayers,
  detectRelation,
  identifyRootCauses
};

// Only run if called directly (not imported)
if (require.main === module) {
  run();
}