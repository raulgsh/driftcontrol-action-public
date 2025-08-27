// CloudFormation template analysis
const core = require('@actions/core');
const yaml = require('yaml');
const riskScorer = require('../../risk-scorer');
const utils = require('./utils');
const { globToRegex } = require('../../comment-generator');

async function analyzeCloudFormationTemplates(files, octokit, owner, repo, pullRequest, cloudformationGlob, costThreshold) {
  const results = [];
  
  // Convert glob to regex using shared utility
  const cfPattern = globToRegex(cloudformationGlob);
  const globRegexPattern = cfPattern.source; // For logging purposes
  const cfFiles = files.filter(file => cfPattern.test(file.filename));
  
  core.info(`CloudFormation glob: ${cloudformationGlob} -> regex: ${globRegexPattern}`);
  core.info(`CloudFormation files found: ${cfFiles.map(f => f.filename).join(', ')}`);
  
  for (const file of cfFiles) {
    try {
      core.info(`Analyzing CloudFormation template drift: ${file.filename}`);
      
      // Fetch head version of template
      let headTemplate = null;
      try {
        const { data: headData } = await octokit.rest.repos.getContent({
          owner,
          repo,
          path: file.filename,
          ref: pullRequest.head.sha
        });
        const headContent = Buffer.from(headData.content, 'base64').toString();
        headTemplate = headContent.trim().startsWith('{') 
          ? JSON.parse(headContent)
          : yaml.parse(headContent);
        core.info(`Parsed head CloudFormation template from: ${file.filename}`);
      } catch (headError) {
        core.info(`No CloudFormation template found in head branch at ${file.filename}: ${headError.message}`);
      }
      
      // Fetch base version of template
      let baseTemplate = null;
      try {
        const { data: baseData } = await octokit.rest.repos.getContent({
          owner,
          repo,
          path: file.filename,
          ref: pullRequest.base.sha
        });
        const baseContent = Buffer.from(baseData.content, 'base64').toString();
        baseTemplate = baseContent.trim().startsWith('{') 
          ? JSON.parse(baseContent)
          : yaml.parse(baseContent);
        core.info(`Parsed base CloudFormation template from: ${file.filename}`);
      } catch (baseError) {
        core.info(`No CloudFormation template found in base branch at ${file.filename}: ${baseError.message}`);
      }
      
      const iacChanges = [];
      let estimatedCostIncrease = 0;
      
      // Handle template deletion (HIGH severity)
      if (baseTemplate && !headTemplate) {
        iacChanges.push(`INFRASTRUCTURE_DELETION: CloudFormation template ${file.filename} was deleted`);
      }
      // Handle new template (analyze for risks)
      else if (!baseTemplate && headTemplate) {
        // Analyze new template's resources
        if (headTemplate.Resources) {
          for (const [logicalId, resource] of Object.entries(headTemplate.Resources)) {
            const resourceType = resource.Type;
            
            iacChanges.push(`RESOURCE_ADDITION: ${resourceType} - ${logicalId}`);
            estimatedCostIncrease += utils.estimateResourceCost(resourceType);
            
            // Flag security-sensitive additions
            if (resourceType === 'AWS::EC2::SecurityGroup' || 
                resourceType === 'AWS::EC2::SecurityGroupIngress' ||
                resourceType === 'AWS::EC2::SecurityGroupEgress') {
              iacChanges.push(`SECURITY_GROUP_ADDITION: ${logicalId}`);
            }
          }
        }
      }
      // Compare base and head templates for drift
      else if (baseTemplate && headTemplate) {
        const baseResources = baseTemplate.Resources || {};
        const headResources = headTemplate.Resources || {};
        
        // Check for removed resources (exist in base but not in head)
        for (const [logicalId, baseResource] of Object.entries(baseResources)) {
          if (!headResources[logicalId]) {
            iacChanges.push(`RESOURCE_DELETION: ${baseResource.Type} - ${logicalId}`);
            
            // Flag security-sensitive deletions
            if (baseResource.Type === 'AWS::EC2::SecurityGroup' || 
                baseResource.Type === 'AWS::EC2::SecurityGroupIngress' ||
                baseResource.Type === 'AWS::EC2::SecurityGroupEgress') {
              iacChanges.push(`SECURITY_GROUP_DELETION: ${logicalId}`);
            }
          }
        }
        
        // Check for added resources and modifications
        for (const [logicalId, headResource] of Object.entries(headResources)) {
          const baseResource = baseResources[logicalId];
          
          if (!baseResource) {
            // Resource added
            iacChanges.push(`RESOURCE_ADDITION: ${headResource.Type} - ${logicalId}`);
            estimatedCostIncrease += utils.estimateResourceCost(headResource.Type);
            
            // Flag security-sensitive additions
            if (headResource.Type === 'AWS::EC2::SecurityGroup' || 
                headResource.Type === 'AWS::EC2::SecurityGroupIngress' ||
                headResource.Type === 'AWS::EC2::SecurityGroupEgress') {
              iacChanges.push(`SECURITY_GROUP_ADDITION: ${logicalId}`);
            }
          } else {
            // Check for resource type change first
            if (baseResource.Type !== headResource.Type) {
              iacChanges.push(`RESOURCE_TYPE_CHANGE: ${logicalId} from ${baseResource.Type} to ${headResource.Type}`);
            }
            
            // Deep comparison of resource properties
            const baseProperties = baseResource.Properties || {};
            const headProperties = headResource.Properties || {};
            
            const propertyChanges = utils.compareResourceProperties(
              baseProperties,
              headProperties,
              logicalId
            );
            
            // Add changes if properties differ
            if (propertyChanges.length > 0 || baseResource.Type !== headResource.Type) {
              // Add high-level change for risk scorer
              iacChanges.push(`RESOURCE_MODIFICATION: ${headResource.Type} - ${logicalId}`);
              
              // Add detailed property changes
              for (const propChange of propertyChanges) {
                iacChanges.push(propChange.detailed);
                
                // Flag security-sensitive changes
                if (propChange.isSecuritySensitive) {
                  if (headResource.Type === 'AWS::EC2::SecurityGroup' || 
                      headResource.Type === 'AWS::EC2::SecurityGroupIngress' ||
                      headResource.Type === 'AWS::EC2::SecurityGroupEgress') {
                    if (!iacChanges.includes(`SECURITY_GROUP_CHANGE: ${logicalId}`)) {
                      iacChanges.push(`SECURITY_GROUP_CHANGE: ${logicalId}`);
                    }
                  }
                }
              }
            }
            
            // Check for deletion policy changes (CloudFormation specific)
            if (baseResource.DeletionPolicy !== headResource.DeletionPolicy) {
              iacChanges.push(`DELETION_POLICY_CHANGE: ${logicalId} from ${baseResource.DeletionPolicy || 'default'} to ${headResource.DeletionPolicy || 'default'}`);
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
        const scoringResult = riskScorer.scoreChanges(iacChanges, 'CLOUDFORMATION');
        
        results.push({
          type: 'infrastructure',
          file: file.filename,
          severity: scoringResult.severity,
          changes: iacChanges,
          reasoning: scoringResult.reasoning,
          costImpact: estimatedCostIncrease > 0 ? `$${estimatedCostIncrease}/month` : null
        });
      }
    } catch (error) {
      core.warning(`CloudFormation analysis failed for ${file.filename}: ${error.message}`);
    }
  }
  
  return results;
}

module.exports = {
  analyzeCloudFormationTemplates
};