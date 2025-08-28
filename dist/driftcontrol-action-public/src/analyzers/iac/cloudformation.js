// CloudFormation template analysis
const core = require('@actions/core');
const yaml = require('yaml');
const riskScorer = require('../../risk-scorer');
const { 
  estimateResourceCost, 
  fetchBaseAndHeadTemplates,
  buildResourceMap,
  analyzeResourceChanges,
  buildIaCResult
} = require('./utils');
const { globToRegex } = require('../../comment-generator');

async function analyzeCloudFormationTemplates(files, octokit, owner, repo, pullRequest, cloudformationGlob, costThreshold, contentFetcher = null) {
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
      
      // Use generic template fetching with YAML/JSON parser
      const { baseTemplate, headTemplate } = await fetchBaseAndHeadTemplates(
        octokit, owner, repo, file.filename, pullRequest,
        content => content.trim().startsWith('{') ? JSON.parse(content) : yaml.parse(content),
        contentFetcher
      );
      
      let iacChanges = [];
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
            estimatedCostIncrease += estimateResourceCost(resourceType);
            
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
        // Build resource maps using shared utility
        const baseMap = buildResourceMap(baseTemplate, 'Resources');
        const headMap = buildResourceMap(headTemplate, 'Resources');
        
        // Analyze resource changes using shared utility
        const result = analyzeResourceChanges(
          baseMap,
          headMap,
          resource => resource.Type, // CloudFormation resource type accessor
          type => type === 'AWS::EC2::SecurityGroup' || 
                  type === 'AWS::EC2::SecurityGroupIngress' ||
                  type === 'AWS::EC2::SecurityGroupEgress' // CloudFormation security check
        );
        
        iacChanges = result.iacChanges;
        estimatedCostIncrease = result.estimatedCostIncrease;
        
        // Check for deletion policy changes (CloudFormation specific)
        const baseResources = baseTemplate.Resources || {};
        const headResources = headTemplate.Resources || {};
        for (const [logicalId, headResource] of Object.entries(headResources)) {
          const baseResource = baseResources[logicalId];
          if (baseResource && baseResource.DeletionPolicy !== headResource.DeletionPolicy) {
            iacChanges.push(`DELETION_POLICY_CHANGE: ${logicalId} from ${baseResource.DeletionPolicy || 'default'} to ${headResource.DeletionPolicy || 'default'}`);
          }
        }
      }
      
      // Use shared result builder
      const result = buildIaCResult(iacChanges, file.filename, 'CLOUDFORMATION', costThreshold, estimatedCostIncrease, riskScorer);
      if (result) {
        results.push(result);
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