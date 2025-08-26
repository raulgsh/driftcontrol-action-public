const core = require('@actions/core');
const github = require('@actions/github');
const SqlAnalyzer = require('./sql-analyzer');
const OpenApiAnalyzer = require('./openapi-analyzer');
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

    // Log input values for initial setup verification
    core.info(`OpenAPI Path: ${openApiPath}`);
    core.info(`SQL Glob: ${sqlGlob}`);
    core.info(`Fail on Medium: ${failOnMedium}`);
    core.info(`Override: ${override}`);

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
    
    // Generate and post PR comment with results
    if (driftResults.length > 0) {
      const commentBody = await generateCommentBody(driftResults, override === 'true');
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
    if (hasHighSeverity && override !== 'true') {
      const highSeverityCount = driftResults.filter(r => r.severity === 'high').length;
      core.setFailed(`High severity drift detected (${highSeverityCount} issue${highSeverityCount !== 1 ? 's' : ''}). Blocking merge to prevent breaking changes.`);
    } else if (hasMediumSeverity && failOnMedium === 'true' && override !== 'true') {
      const mediumSeverityCount = driftResults.filter(r => r.severity === 'medium').length;
      core.setFailed(`Medium severity drift detected (${mediumSeverityCount} issue${mediumSeverityCount !== 1 ? 's' : ''}) and fail_on_medium is enabled. Blocking merge.`);
    } else if ((hasHighSeverity || hasMediumSeverity) && override === 'true') {
      const totalIssues = driftResults.filter(r => r.severity === 'high' || r.severity === 'medium').length;
      core.warning(`Policy override applied: ${totalIssues} drift issue${totalIssues !== 1 ? 's' : ''} detected but merge allowed with audit trail. Reason: ${overrideReason}`);
    } else if (driftResults.length === 0) {
      core.info('No drift detected - merge allowed.');
    } else {
      const lowSeverityCount = driftResults.filter(r => r.severity === 'low').length;
      core.info(`Low severity drift detected (${lowSeverityCount} issue${lowSeverityCount !== 1 ? 's' : ''}) - merge allowed.`);
    }
    
    core.info('DriftControl analysis completed successfully');
    
  } catch (error) {
    core.error(`Error: ${error.message}`);
    core.setFailed(error.message);
  }
}


// Export helper functions for integration testing
module.exports = {
  run,
  generateCommentBody: require('./comment-generator').generateCommentBody,
  generateFixSuggestion: require('./comment-generator').generateFixSuggestion,
  postOrUpdateComment: require('./github-api').postOrUpdateComment
};

// Only run if called directly (not imported)
if (require.main === module) {
  run();
}