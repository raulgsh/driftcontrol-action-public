const core = require('@actions/core');
const { diff } = require('@useoptic/openapi-utilities');
const SwaggerParser = require('@apidevtools/swagger-parser');
const yaml = require('yaml');
const riskScorer = require('./risk-scorer');

class OpenApiAnalyzer {
  constructor() {
    this.riskScorer = riskScorer;
  }

  // Detect OpenAPI spec file renames (add+delete pair per CLAUDE.md:55)
  detectSpecRenames(files, openApiPath) {
    let actualOpenApiPath = openApiPath;
    let renamedFromPath = null;
    
    // Check for OpenAPI spec rename scenario
    const deletedFiles = files.filter(f => f.status === 'removed');
    const addedFiles = files.filter(f => f.status === 'added');
    
    // Look for OpenAPI file extensions in renamed files
    const openApiExtensions = ['.yaml', '.yml', '.json'];
    const isOpenApiFile = (filename) => openApiExtensions.some(ext => filename.endsWith(ext));
    
    for (const deletedFile of deletedFiles) {
      if (isOpenApiFile(deletedFile.filename)) {
        // Check if there's a corresponding added file that could be a rename
        const possibleRename = addedFiles.find(f => isOpenApiFile(f.filename));
        if (possibleRename) {
          renamedFromPath = deletedFile.filename;
          actualOpenApiPath = possibleRename.filename;
          core.info(`Detected OpenAPI spec rename: ${renamedFromPath} → ${actualOpenApiPath}`);
          break;
        }
      }
    }

    return { actualOpenApiPath, renamedFromPath };
  }

  async analyzeOpenApiDrift(octokit, owner, repo, pullRequest, actualOpenApiPath, renamedFromPath) {
    const driftResults = [];
    let hasHighSeverity = false;
    let hasMediumSeverity = false;

    try {
      core.info(`Checking OpenAPI spec at: ${actualOpenApiPath}`);
      
      // Check base branch for OpenAPI spec (handle renames)
      let baseSpec = null;
      let baseSpecRaw = null;
      const baseSpecPath = renamedFromPath || actualOpenApiPath;
      
      try {
        const { data: baseData } = await octokit.rest.repos.getContent({
          owner,
          repo,
          path: baseSpecPath,
          ref: pullRequest.base.sha
        });
        baseSpecRaw = Buffer.from(baseData.content, 'base64').toString();
        
        // Parse and validate base spec
        baseSpec = await SwaggerParser.parse(JSON.parse(JSON.stringify(
          baseSpecRaw.trim().startsWith('{') ? JSON.parse(baseSpecRaw) : yaml.parse(baseSpecRaw)
        )));
        core.info(`Parsed base OpenAPI spec from: ${baseSpecPath}`);
      } catch (baseError) {
        core.info(`No valid OpenAPI spec found in base branch at ${baseSpecPath}: ${baseError.message}`);
      }
      
      // Check head branch for OpenAPI spec
      let headSpec = null;
      let headSpecRaw = null;
      
      try {
        const { data: headData } = await octokit.rest.repos.getContent({
          owner,
          repo,
          path: actualOpenApiPath,
          ref: pullRequest.head.sha
        });
        headSpecRaw = Buffer.from(headData.content, 'base64').toString();
        
        // Parse and validate head spec
        headSpec = await SwaggerParser.parse(JSON.parse(JSON.stringify(
          headSpecRaw.trim().startsWith('{') ? JSON.parse(headSpecRaw) : yaml.parse(headSpecRaw)
        )));
        core.info(`Parsed head OpenAPI spec from: ${actualOpenApiPath}`);
      } catch (headError) {
        core.info(`No valid OpenAPI spec found in head branch at ${actualOpenApiPath}: ${headError.message}`);
      }
      
      // Enhanced OpenAPI drift detection using @useoptic
      if (baseSpec || headSpec) {
        const apiChanges = [];
        
        // Handle spec deletion (HIGH severity)
        if (baseSpec && !headSpec) {
          apiChanges.push('API_DELETION: OpenAPI specification was deleted');
        }
        // Handle new spec (LOW severity)
        else if (!baseSpec && headSpec) {
          apiChanges.push('New OpenAPI specification added');
        }
        // Compare existing specs using @useoptic
        else if (baseSpec && headSpec) {
          try {
            const diffResult = diff(baseSpec, headSpec);
            
            if (diffResult && diffResult.length > 0) {
              // Analyze diff results for breaking changes
              for (const change of diffResult) {
                const changeType = change.type || 'unknown';
                const changePath = change.path || 'unknown';
                
                // Classify changes for centralized scoring
                if (changeType.includes('removed') || changeType.includes('deleted')) {
                  apiChanges.push(`BREAKING_CHANGE: Removed ${changePath}`);
                } else if (changeType.includes('required') || changeType.includes('breaking')) {
                  apiChanges.push(`BREAKING_CHANGE: ${changePath}`);
                } else if (changeType.includes('added') || changeType.includes('modified')) {
                  apiChanges.push(`Modified: ${changePath}`);
                }
              }
              
              // If no changes detected, add generic change indicator
              if (apiChanges.length === 0) {
                apiChanges.push('OpenAPI specification changes detected');
              }
            }
          } catch (diffError) {
            core.warning(`OpenAPI diff analysis failed: ${diffError.message}`);
            // Fallback to simple comparison
            if (baseSpecRaw !== headSpecRaw) {
              apiChanges.push('OpenAPI specification changes detected (detailed analysis failed)');
            }
          }
        }
        
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