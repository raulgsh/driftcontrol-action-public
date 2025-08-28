// Terraform plan analysis
const core = require('@actions/core');
const riskScorer = require('../../risk-scorer');
const { 
  estimateResourceCost, 
  fetchBaseAndHeadTemplates,
  buildResourceMap,
  analyzeResourceChanges,
  buildIaCResult
} = require('./utils');

async function analyzeTerraformPlan(octokit, owner, repo, pullRequest, terraformPath, costThreshold, contentFetcher = null) {
  try {
    core.info(`Analyzing Terraform plan drift at: ${terraformPath}`);
    
    // Use generic template fetching with JSON parser
    const { baseTemplate: basePlan, headTemplate: headPlan } = await fetchBaseAndHeadTemplates(
      octokit, owner, repo, terraformPath, pullRequest,
      content => JSON.parse(content),
      contentFetcher
    );
    
    let iacChanges = [];
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
            estimatedCostIncrease += estimateResourceCost(resource.type);
            
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
      // Build resource maps using shared utility
      const baseMap = buildResourceMap(basePlan, 'resource_changes');
      const headMap = buildResourceMap(headPlan, 'resource_changes');
      
      // Analyze resource changes using shared utility
      const result = analyzeResourceChanges(
        baseMap,
        headMap,
        resource => resource.type, // Terraform resource type accessor
        type => type === 'aws_security_group' || type === 'aws_security_group_rule' // Terraform security check
      );
      
      iacChanges = result.iacChanges;
      estimatedCostIncrease = result.estimatedCostIncrease;
    }
    
    // Use shared result builder
    return buildIaCResult(iacChanges, terraformPath, 'INFRASTRUCTURE', costThreshold, estimatedCostIncrease, riskScorer);
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