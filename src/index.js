const core = require('@actions/core');
const github = require('@actions/github');
const SqlAnalyzer = require('./sql-analyzer');
const OpenApiAnalyzer = require('./openapi-analyzer');
const IaCAnalyzer = require('./iac-analyzer');
const ConfigAnalyzer = require('./config-analyzer');
const { generateCommentBody, generateFixSuggestion } = require('./comment-generator');
const { postOrUpdateComment } = require('./github-api');
const riskScorer = require('./risk-scorer');
const { correlateAcrossLayers, identifyRootCauses } = require('./correlation');

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
    const vulnerabilityProvider = core.getInput('vulnerability_provider') || 'static';
    
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
    
    // Initialize vulnerability provider before analysis
    await configAnalyzer.initializeVulnerabilityProvider(octokit, {
      provider: vulnerabilityProvider,
      owner: context.repo.owner,
      repo: context.repo.repo,
      baseSha: context.payload.pull_request.base.sha,
      headSha: context.payload.pull_request.head.sha
    });
    
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
    
    
    // Execute all analyzers in parallel for better performance
    const analysisPromises = [];
    
    // SQL Analysis Promise
    analysisPromises.push(
      sqlAnalyzer.analyzeSqlFiles(
        files, octokit, owner, repo, context.payload.pull_request.head.sha, sqlGlob
      )
    );
    
    // OpenAPI Analysis Promise
    analysisPromises.push(
      openApiAnalyzer.analyzeOpenApiDrift(
        octokit, owner, repo, context.payload.pull_request, actualOpenApiPath, renamedFromPath
      )
    );
    
    // IaC Analysis Promise (conditional)
    if (terraformPlanPath || cloudformationGlob) {
      analysisPromises.push(
        iacAnalyzer.analyzeIaCFiles(
          files, octokit, owner, repo, context.payload.pull_request,
          terraformPlanPath, cloudformationGlob, costThreshold
        )
      );
    }
    
    // Config Analysis Promise (conditional, includes package-lock analysis)
    if (configYamlGlob || featureFlagsPath || files.some(f => f.filename.endsWith('package.json') || f.filename.endsWith('package-lock.json') || f.filename.includes('docker-compose'))) {
      analysisPromises.push(
        configAnalyzer.analyzeConfigFiles(
          files, octokit, owner, repo, context.payload.pull_request,
          configYamlGlob, featureFlagsPath
        ).then(async (configResults) => {
          // Handle package-lock files within the same promise chain
          const packageLockFiles = files.filter(f => f.filename.endsWith('package-lock.json'));
          const lockResults = await Promise.all(
            packageLockFiles.map(file => 
              configAnalyzer.analyzePackageLock(
                octokit, owner, repo, context.payload.pull_request.head.sha, 
                context.payload.pull_request.base.sha, file.filename
              )
            )
          );
          
          // Merge lock results with config results
          const validLockResults = lockResults.filter(r => r !== null);
          configResults.driftResults.push(...validLockResults);
          validLockResults.forEach(lockResult => {
            if (lockResult.severity === 'high') configResults.hasHighSeverity = true;
            if (lockResult.severity === 'medium') configResults.hasMediumSeverity = true;
          });
          
          return configResults;
        })
      );
    }
    
    core.info(`Executing ${analysisPromises.length} analyzers in parallel...`);
    
    // Execute all analyses in parallel
    const allResults = await Promise.all(analysisPromises);
    
    core.info('All analyzers completed. Processing results...');
    
    // Process all results
    for (const result of allResults) {
      driftResults.push(...result.driftResults);
      hasHighSeverity = hasHighSeverity || result.hasHighSeverity;
      hasMediumSeverity = hasMediumSeverity || result.hasMediumSeverity;
    }
    
    // Cross-layer correlation analysis
    if (driftResults.length > 1) {
      // Build correlation graph from existing results (pass correlation config)
      const correlations = await correlateAcrossLayers(driftResults, files, correlationConfig);
      
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

// Re-export functions from correlation module for backward compatibility
const correlation = require('./correlation');

module.exports = {
  run,
  generateCommentBody: require('./comment-generator').generateCommentBody,
  generateFixSuggestion: require('./comment-generator').generateFixSuggestion,
  postOrUpdateComment: require('./github-api').postOrUpdateComment,
  
  // Re-export correlation functions
  correlateAcrossLayers: correlation.correlateAcrossLayers,
  detectRelation: correlation.detectRelation,
  identifyRootCauses: correlation.identifyRootCauses,
  
  // Re-export correlation utilities for testing
  extractMetadata: correlation.extractMetadata,
  extractTableNamesWithConfidence: correlation.extractTableNamesWithConfidence,
  generateEntityVariations: correlation.generateEntityVariations,
  findBestMatch: correlation.findBestMatch,
  correlateFields: correlation.correlateFields,
  detectApiOperations: correlation.detectApiOperations,
  detectDbOperations: correlation.detectDbOperations,
  operationsCorrelate: correlation.operationsCorrelate,
  getArtifactId: correlation.getArtifactId,
  
  // Re-export correlation engine functions
  getPairKey: correlation.getPairKey,
  expandResults: correlation.expandResults,
  isCriticalPair: correlation.isCriticalPair,
  resolveTokenToArtifacts: correlation.resolveTokenToArtifacts,
  matchToken: correlation.matchToken,
  applyUserDefinedRules: correlation.applyUserDefinedRules,
  selectCandidatePairs: correlation.selectCandidatePairs,
  aggregateCorrelations: correlation.aggregateCorrelations,
  dedupeEvidence: correlation.dedupeEvidence,
  clamp01: correlation.clamp01,
  hasFileLine: correlation.hasFileLine,
  
  // Re-export strategy classes
  CorrelationStrategy: correlation.CorrelationStrategy,
  EntityCorrelationStrategy: correlation.EntityCorrelationStrategy,
  OperationCorrelationStrategy: correlation.OperationCorrelationStrategy,
  InfrastructureCorrelationStrategy: correlation.InfrastructureCorrelationStrategy,
  DependencyCorrelationStrategy: correlation.DependencyCorrelationStrategy,
  TemporalCorrelationStrategy: correlation.TemporalCorrelationStrategy
};

// Only run if called directly (not imported)
if (require.main === module) {
  run();
}