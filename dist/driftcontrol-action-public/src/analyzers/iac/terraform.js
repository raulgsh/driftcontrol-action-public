// Terraform plan analysis
const core = require('@actions/core');
const path = require('path');
const fs = require('fs');
const riskScorer = require('../../risk-scorer');
const { 
  estimateResourceCost, 
  fetchBaseAndHeadTemplates,
  buildResourceMap,
  analyzeResourceChanges,
  buildIaCResult,
  generateTerraformPlan,
  checkoutToTemp
} = require('./utils');

async function analyzeTerraformPlan(octokit, owner, repo, pullRequest, terraformPath, costThreshold, contentFetcher = null) {
  try {
    core.info(`Analyzing Terraform drift at: ${terraformPath}`);
    
    let basePlan, headPlan;
    let usingGeneratedPlan = false;
    
    // First try to use existing JSON plan if it's a .json file
    if (terraformPath.endsWith('.json')) {
      const { baseTemplate: basePlanJson, headTemplate: headPlanJson } = await fetchBaseAndHeadTemplates(
        octokit, owner, repo, terraformPath, pullRequest,
        content => JSON.parse(content),
        contentFetcher
      );
      basePlan = basePlanJson;
      headPlan = headPlanJson;
      core.info('Using existing JSON plan files for analysis');
    } 
    // If it's an HCL file or directory, try to generate plan
    else if (terraformPath.endsWith('.tf') || !terraformPath.includes('.')) {
      core.info('Attempting to generate Terraform plan from HCL files...');
      
      // Determine working directory
      const workingDir = terraformPath.includes('.tf') 
        ? path.dirname(terraformPath)
        : terraformPath;
      
      // Try to generate plans for both base and head in GitHub Actions environment
      if (process.env.GITHUB_ACTIONS) {
        // In GitHub Actions, we have access to the workspace
        try {
          // Checkout base branch to temp directory
          const baseTempDir = path.join('/tmp', `base-${pullRequest.base.sha.substring(0, 8)}`);
          const baseCheckout = await checkoutToTemp(octokit, owner, repo, pullRequest.base.sha, baseTempDir);
          if (baseCheckout) {
            basePlan = await generateTerraformPlan(path.join(baseTempDir, workingDir));
            // Cleanup base temp directory
            fs.rmSync(baseTempDir, { recursive: true, force: true });
          }
          
          // Checkout head branch to temp directory  
          const headTempDir = path.join('/tmp', `head-${pullRequest.head.sha.substring(0, 8)}`);
          const headCheckout = await checkoutToTemp(octokit, owner, repo, pullRequest.head.sha, headTempDir);
          if (headCheckout) {
            headPlan = await generateTerraformPlan(path.join(headTempDir, workingDir));
            // Cleanup head temp directory
            fs.rmSync(headTempDir, { recursive: true, force: true });
          }
          
          if (basePlan || headPlan) {
            usingGeneratedPlan = true;
            core.info('Successfully generated Terraform plans for analysis');
          }
        } catch (planError) {
          core.warning(`Plan generation failed: ${planError.message}`);
        }
      }
    }
    
    // If we couldn't get plans through generation or JSON, fall back to HCL analysis
    if (!basePlan && !headPlan && terraformPath.endsWith('.tf')) {
      core.info('Falling back to HCL pattern analysis');
      return await analyzeHCLFile(octokit, owner, repo, pullRequest, terraformPath, contentFetcher);
    }
    
    // Continue with existing plan analysis logic
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
    
    // Use shared result builder with note about plan generation if used
    const result = buildIaCResult(iacChanges, terraformPath, 'INFRASTRUCTURE', costThreshold, estimatedCostIncrease, riskScorer);
    
    if (result && usingGeneratedPlan) {
      result.note = 'Analysis based on auto-generated Terraform plan';
    }
    
    return result;
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