const core = require('@actions/core');
const riskScorer = require('../../risk-scorer');
const { detectSpecRenames, loadSpec, loadSpecWithFetcher } = require('./io');
const { compareSpecs } = require('./diff');

/**
 * Main OpenAPI Analyzer class
 */
class OpenApiAnalyzer {
  constructor(contentFetcher = null) {
    this.riskScorer = riskScorer;
    this.contentFetcher = contentFetcher;
  }

  // Detect OpenAPI spec file renames (add+delete pair per CLAUDE.md:55)
  detectSpecRenames(files, openApiPath) {
    return detectSpecRenames(files, openApiPath);
  }

  async analyzeOpenApiDrift(octokit, owner, repo, pullRequest, actualOpenApiPath, renamedFromPath) {
    const driftResults = [];
    let hasHighSeverity = false;
    let hasMediumSeverity = false;

    try {
      core.info(`Checking OpenAPI spec at: ${actualOpenApiPath}`);
      
      // Use ContentFetcher if available, otherwise fallback to legacy method
      const baseSpecPath = renamedFromPath || actualOpenApiPath;
      let baseSpec, baseSpecRaw, headSpec, headSpecRaw;
      
      if (this.contentFetcher) {
        const results = await Promise.all([
          loadSpecWithFetcher(this.contentFetcher, baseSpecPath, pullRequest.base.sha, 'base'),
          loadSpecWithFetcher(this.contentFetcher, actualOpenApiPath, pullRequest.head.sha, 'head')
        ]);
        
        ({ spec: baseSpec, rawContent: baseSpecRaw } = results[0]);
        ({ spec: headSpec, rawContent: headSpecRaw } = results[1]);
      } else {
        // Legacy method for backward compatibility
        ({ spec: baseSpec, rawContent: baseSpecRaw } = await loadSpec(
          octokit, owner, repo, baseSpecPath, pullRequest.base.sha, 'base'
        ));
        
        ({ spec: headSpec, rawContent: headSpecRaw } = await loadSpec(
          octokit, owner, repo, actualOpenApiPath, pullRequest.head.sha, 'head'
        ));
      }
      
      // Enhanced OpenAPI drift detection using @useoptic
      if (baseSpec || headSpec) {
        const apiChanges = await compareSpecs(baseSpec, headSpec, baseSpecRaw, headSpecRaw);
        
        // Use centralized risk scorer for consistent severity assessment
        if (apiChanges.length > 0) {
          const scoringResult = this.riskScorer.scoreChanges(apiChanges, 'API');
          
          // Update global severity tracking
          if (scoringResult.severity === 'high') {
            hasHighSeverity = true;
          } else if (scoringResult.severity === 'medium') {
            hasMediumSeverity = true;
          }
          
          driftResults.push({
            type: 'api',
            file: actualOpenApiPath,
            severity: scoringResult.severity,
            changes: apiChanges,
            reasoning: scoringResult.reasoning,
            renamed: renamedFromPath ? { from: renamedFromPath, to: actualOpenApiPath } : null
          });
        }
      }
    } catch (apiError) {
      core.warning(`Could not analyze OpenAPI spec: ${apiError.message}`);
    }

    return { driftResults, hasHighSeverity, hasMediumSeverity };
  }
}

module.exports = OpenApiAnalyzer;