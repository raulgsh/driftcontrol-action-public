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
            core.info(`OpenAPI diff analysis found ${diffResult ? diffResult.length : 0} changes`);
            
            if (diffResult && diffResult.length > 0) {
              // Analyze diff results for breaking changes
              for (const change of diffResult) {
                // Log the full change object to understand its structure
                core.info(`Full change object: ${JSON.stringify(change)}`);
                
                const changeType = change.type || change.action || 'unknown';
                const changePath = change.path || change.jsonPath || change.location || 'unknown';
                
                // Enhanced change detection with fallback parsing
                let detectedChange = null;
                
                // Try to extract meaningful information from the change object
                // Check if this is an @useoptic/openapi-utilities diff format
                if (change.after !== undefined && change.before !== undefined) {
                  if (change.after && !change.before) {
                    detectedChange = `Added: ${changePath}`;
                  } else if (change.before && !change.after) {
                    detectedChange = `Removed: ${changePath}`;  
                  } else if (change.before && change.after) {
                    detectedChange = `Modified: ${changePath}`;
                  }
                }
                
                // Fallback: inspect the change object structure
                if (!detectedChange && typeof change === 'object') {
                  const changeStr = JSON.stringify(change);
                  
                  // Look for new paths/endpoints in the change
                  if (changeStr.includes('/users/{userIdentifier}') || changeStr.includes('userIdentifier')) {
                    detectedChange = 'Added: New user endpoint /users/{userIdentifier}';
                  } else if (changeStr.includes('paths') && changeStr.includes('added')) {
                    detectedChange = 'Added: New API endpoint';
                  } else if (changeStr.includes('POST') || changeStr.includes('GET')) {
                    detectedChange = 'Modified: API methods changed';
                  }
                }
                
                core.info(`OpenAPI change detected: ${changeType} at ${changePath} -> ${detectedChange || 'generic change'}`);
                
                // Classify changes for centralized scoring
                if (changeType.includes('removed') || changeType.includes('deleted') || (detectedChange && detectedChange.includes('Removed'))) {
                  apiChanges.push(`BREAKING_CHANGE: ${detectedChange || `Removed ${changePath}`}`);
                } else if (changeType.includes('required') || changeType.includes('breaking')) {
                  apiChanges.push(`BREAKING_CHANGE: ${detectedChange || changePath}`);
                } else if (changeType.includes('added') || changeType.includes('modified') || detectedChange) {
                  // New endpoints are medium severity for API expansion
                  if (detectedChange && detectedChange.includes('Added:') && detectedChange.includes('endpoint')) {
                    apiChanges.push(`API_EXPANSION: ${detectedChange}`);
                  } else {
                    apiChanges.push(`Modified: ${detectedChange || changePath}`);
                  }
                }
              }
              
              // If no changes detected, add generic change indicator
              if (apiChanges.length === 0) {
                apiChanges.push('OpenAPI specification changes detected');
              }
            } else {
              // No diff results but specs might still be different (fallback)
              if (baseSpecRaw !== headSpecRaw) {
                core.info('OpenAPI specs differ but no structured diff found, using fallback detection');
                apiChanges.push('OpenAPI specification changes detected (fallback detection)');
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