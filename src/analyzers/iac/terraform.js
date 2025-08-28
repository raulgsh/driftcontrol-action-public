// Terraform plan analysis
const core = require('@actions/core');
const riskScorer = require('../../risk-scorer');
const utils = require('./utils');

async function analyzeTerraformPlan(octokit, owner, repo, pullRequest, terraformPath, costThreshold, contentFetcher = null) {
  try {
    core.info(`Analyzing Terraform plan drift at: ${terraformPath}`);
    
    let headPlan = null;
    let basePlan = null;
    let headError = null;
    let baseError = null;
    
    if (contentFetcher) {
      // Use ContentFetcher for batch fetching
      const results = await contentFetcher.batchFetch([
        { path: terraformPath, ref: pullRequest.head.sha, description: 'head Terraform plan' },
        { path: terraformPath, ref: pullRequest.base.sha, description: 'base Terraform plan' }
      ]);
      
      try {
        if (results[0]) {
          headPlan = JSON.parse(results[0].content);
          core.info(`Parsed head Terraform plan from: ${terraformPath}`);
        } else {
          headError = new Error('Not Found');
          core.info(`No Terraform plan found in head branch at ${terraformPath}`);
        }
      } catch (error) {
        headError = error;
        core.info(`Failed to parse head Terraform plan: ${error.message}`);
      }
      
      try {
        if (results[1]) {
          basePlan = JSON.parse(results[1].content);
          core.info(`Parsed base Terraform plan from: ${terraformPath}`);
        } else {
          baseError = new Error('Not Found');
          core.info(`No Terraform plan found in base branch at ${terraformPath}`);
        }
      } catch (error) {
        baseError = error;
        core.info(`Failed to parse base Terraform plan: ${error.message}`);
      }
    } else {
      // Legacy method for backward compatibility
      try {
        const { data: headData } = await octokit.rest.repos.getContent({
          owner,
          repo,
          path: terraformPath,
          ref: pullRequest.head.sha
        });
        const headContent = Buffer.from(headData.content, 'base64').toString();
        headPlan = JSON.parse(headContent);
        core.info(`Parsed head Terraform plan from: ${terraformPath}`);
      } catch (error) {
        headError = error;
        core.info(`No Terraform plan found in head branch at ${terraformPath}: ${error.message}`);
      }
      
      try {
        const { data: baseData } = await octokit.rest.repos.getContent({
          owner,
          repo,
          path: terraformPath,
          ref: pullRequest.base.sha
        });
        const baseContent = Buffer.from(baseData.content, 'base64').toString();
        basePlan = JSON.parse(baseContent);
        core.info(`Parsed base Terraform plan from: ${terraformPath}`);
      } catch (error) {
        baseError = error;
        core.info(`No Terraform plan found in base branch at ${terraformPath}: ${error.message}`);
      }
    }
    
    // If both fetches failed with actual errors (not just missing files), propagate the error
    if (headError && baseError && headError.message !== 'Not Found' && baseError.message !== 'Not Found') {
      throw headError; // Re-throw to trigger the warning in outer catch
    }
    
    const iacChanges = [];
    let estimatedCostIncrease = 0;
    
    // Handle plan deletion (HIGH severity)
    if (basePlan && !headPlan) {
      iacChanges.push('INFRASTRUCTURE_DELETION: Terraform plan was deleted');
    }
    // Handle new plan (analyze for risks)
    else if (!basePlan && headPlan) {
      // Analyze new plan's resource changes
      if (headPlan.resource_changes) {
        for (const resource of headPlan.resource_changes) {
          const change = resource.change || {};
          const actions = change.actions || [];
          
          if (actions.includes('create')) {
            iacChanges.push(`RESOURCE_ADDITION: ${resource.type} - ${resource.address}`);
            estimatedCostIncrease += utils.estimateResourceCost(resource.type);
            
            // Flag security-sensitive additions
            if (resource.type === 'aws_security_group' || resource.type === 'aws_security_group_rule') {
              iacChanges.push(`SECURITY_GROUP_ADDITION: ${resource.address}`);
            }
          } else if (actions.includes('delete')) {
            iacChanges.push(`RESOURCE_DELETION: ${resource.type} - ${resource.address}`);
            
            // Flag security-sensitive deletions
            if (resource.type === 'aws_security_group' || resource.type === 'aws_security_group_rule') {
              iacChanges.push(`SECURITY_GROUP_DELETION: ${resource.address}`);
            }
          } else if (actions.includes('update') || actions.includes('modify')) {
            iacChanges.push(`RESOURCE_MODIFICATION: ${resource.type} - ${resource.address}`);
            
            // Flag security-sensitive changes
            if (resource.type === 'aws_security_group' || resource.type === 'aws_security_group_rule') {
              iacChanges.push(`SECURITY_GROUP_CHANGE: ${resource.address}`);
            }
          }
        }
      }
    }
    // Compare base and head plans for drift
    else if (basePlan && headPlan) {
      // Build resource maps for comparison
      const baseResources = new Map();
      const headResources = new Map();
      
      if (basePlan.resource_changes) {
        for (const resource of basePlan.resource_changes) {
          baseResources.set(resource.address, resource);
        }
      }
      
      if (headPlan.resource_changes) {
        for (const resource of headPlan.resource_changes) {
          headResources.set(resource.address, resource);
        }
      }
      
      // Check for removed resources (exist in base but not in head)
      for (const [address, baseResource] of baseResources) {
        if (!headResources.has(address)) {
          iacChanges.push(`RESOURCE_DELETION: ${baseResource.type} - ${address}`);
          
          // Flag security-sensitive deletions
          if (baseResource.type === 'aws_security_group' || baseResource.type === 'aws_security_group_rule') {
            iacChanges.push(`SECURITY_GROUP_DELETION: ${address}`);
          }
        }
      }
      
      // Check for added resources and modifications
      for (const [address, headResource] of headResources) {
        const baseResource = baseResources.get(address);
        
        if (!baseResource) {
          // Resource added
          iacChanges.push(`RESOURCE_ADDITION: ${headResource.type} - ${address}`);
          const change = headResource.change || {};
          const actions = change.actions || [];
          if (actions.includes('create')) {
            estimatedCostIncrease += utils.estimateResourceCost(headResource.type);
          }
          
          // Flag security-sensitive additions
          if (headResource.type === 'aws_security_group' || headResource.type === 'aws_security_group_rule') {
            iacChanges.push(`SECURITY_GROUP_ADDITION: ${address}`);
          }
        } else {
          // Deep comparison of resource properties
          const change = headResource.change || {};
          const actions = change.actions || [];
          
          if (actions.includes('update') || actions.includes('modify')) {
            // Extract before and after states for comparison
            const beforeState = change.before || baseResource.change?.after || {};
            const afterState = change.after || {};
            
            // Perform detailed property comparison
            const propertyChanges = utils.compareResourceProperties(
              beforeState,
              afterState,
              address
            );
            
            // Add high-level change for risk scorer compatibility
            if (propertyChanges.length > 0) {
              iacChanges.push(`RESOURCE_MODIFICATION: ${headResource.type} - ${address}`);
              
              // Add detailed property changes
              for (const propChange of propertyChanges) {
                iacChanges.push(propChange.detailed);
                
                // Flag security-sensitive changes
                if (propChange.isSecuritySensitive) {
                  if (!iacChanges.includes(`SECURITY_GROUP_CHANGE: ${address}`)) {
                    iacChanges.push(`SECURITY_GROUP_CHANGE: ${address}`);
                  }
                }
              }
            }
          }
        }
      }
    }
    
    // Check if cost increase exceeds threshold
    if (estimatedCostIncrease > parseFloat(costThreshold)) {
      iacChanges.push(`COST_INCREASE: Estimated $${estimatedCostIncrease}/month`);
    }
    
    // Score the changes using existing risk scorer
    if (iacChanges.length > 0) {
      const scoringResult = riskScorer.scoreChanges(iacChanges, 'INFRASTRUCTURE');
      
      return {
        type: 'infrastructure',
        file: terraformPath,
        severity: scoringResult.severity,
        changes: iacChanges,
        reasoning: scoringResult.reasoning,
        costImpact: estimatedCostIncrease > 0 ? `$${estimatedCostIncrease}/month` : null
      };
    }
  } catch (error) {
    core.warning(`Terraform plan analysis failed: ${error.message}`);
  }
  
  return null;
}

async function analyzeHCLFile(octokit, owner, repo, pullRequest, filepath, contentFetcher = null) {
  try {
    core.info(`HCL analysis for ${filepath} - using basic pattern detection`);
    
    let content;
    
    if (contentFetcher) {
      const result = await contentFetcher.fetchContent(
        filepath, pullRequest.head.sha, `HCL file ${filepath}`
      );
      content = result?.content;
    } else {
      // Legacy method for backward compatibility
      const { data: headData } = await octokit.rest.repos.getContent({
        owner, repo, path: filepath, ref: pullRequest.head.sha
      });
      content = Buffer.from(headData.content, 'base64').toString();
    }
    
    if (!content) {
      core.warning(`No content found for HCL file: ${filepath}`);
      return null;
    }
    const changes = [];
    
    // Basic pattern matching for high-risk HCL patterns
    // (Full HCL parsing would require @tmccombs/hcl2-parser or similar)
    
    if (content.match(/cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"/)) {
      changes.push('HCL_SECURITY_GROUP_WORLD_OPEN');
    }
    
    if (content.match(/instance_type\s*=\s*"[ti]\d+\.(8xlarge|16xlarge|24xlarge|metal)/)) {
      changes.push('HCL_EXPENSIVE_INSTANCE_TYPE');
    }
    
    if (content.match(/deletion_protection\s*=\s*false/)) {
      changes.push('HCL_DELETION_PROTECTION_DISABLED');
    }
    
    if (content.match(/encrypted\s*=\s*false/)) {
      changes.push('HCL_ENCRYPTION_DISABLED');
    }
    
    if (content.match(/publicly_accessible\s*=\s*true/)) {
      changes.push('HCL_DATABASE_PUBLICLY_ACCESSIBLE');
    }
    
    if (content.match(/skip_final_snapshot\s*=\s*true/)) {
      changes.push('HCL_SKIP_FINAL_SNAPSHOT');
    }
    
    if (changes.length > 0) {
      const scoringResult = riskScorer.scoreChanges(changes, 'TERRAFORM_HCL');
      return {
        type: 'infrastructure',
        file: filepath,
        severity: scoringResult.severity,
        changes: changes,
        reasoning: scoringResult.reasoning,
        note: 'Basic HCL analysis - run terraform plan for comprehensive analysis'
      };
    }
  } catch (e) {
    core.warning(`HCL analysis failed: ${e.message}`);
  }
  return null;
}

module.exports = {
  analyzeTerraformPlan,
  analyzeHCLFile
};