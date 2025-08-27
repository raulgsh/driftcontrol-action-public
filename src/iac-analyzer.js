const core = require('@actions/core');
const yaml = require('yaml');
const riskScorer = require('./risk-scorer');
const { globToRegex } = require('./comment-generator');

class IaCAnalyzer {
  constructor() {
    this.riskScorer = riskScorer;
  }

  async analyzeIaCFiles(files, octokit, owner, repo, pullRequest, terraformPath, cloudformationGlob, costThreshold) {
    const pullRequestHeadSha = pullRequest.head.sha;
    const pullRequestBaseSha = pullRequest.base.sha;
    const driftResults = [];
    let hasHighSeverity = false;
    let hasMediumSeverity = false;

    try {
      // Process Terraform plan if specified
      if (terraformPath && files.some(f => f.filename === terraformPath)) {
        const tfResult = await this.analyzeTerraformPlan(
          octokit, owner, repo, pullRequest, terraformPath, costThreshold
        );
        if (tfResult) {
          driftResults.push(tfResult);
          if (tfResult.severity === 'high') hasHighSeverity = true;
          if (tfResult.severity === 'medium') hasMediumSeverity = true;
        }
      }

      // Process CloudFormation templates if specified
      if (cloudformationGlob) {
        const cfResults = await this.analyzeCloudFormationTemplates(
          files, octokit, owner, repo, pullRequest, cloudformationGlob, costThreshold
        );
        for (const result of cfResults) {
          driftResults.push(result);
          if (result.severity === 'high') hasHighSeverity = true;
          if (result.severity === 'medium') hasMediumSeverity = true;
        }
      }
    } catch (error) {
      core.warning(`IaC analysis error: ${error.message}`);
    }

    return { driftResults, hasHighSeverity, hasMediumSeverity };
  }

  async analyzeTerraformPlan(octokit, owner, repo, pullRequest, terraformPath, costThreshold) {
    try {
      core.info(`Analyzing Terraform plan drift at: ${terraformPath}`);
      
      // Fetch head version of Terraform plan
      let headPlan = null;
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
      } catch (headError) {
        core.info(`No Terraform plan found in head branch at ${terraformPath}: ${headError.message}`);
      }
      
      // Fetch base version of Terraform plan
      let basePlan = null;
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
      } catch (baseError) {
        core.info(`No Terraform plan found in base branch at ${terraformPath}: ${baseError.message}`);
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
              estimatedCostIncrease += this.estimateResourceCost(resource.type);
              
              // Flag security-sensitive additions
              if (resource.type === 'aws_security_group' || resource.type === 'aws_security_group_rule') {
                iacChanges.push(`SECURITY_GROUP_ADDITION: ${resource.address}`);
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
              estimatedCostIncrease += this.estimateResourceCost(headResource.type);
            }
            
            // Flag security-sensitive additions
            if (headResource.type === 'aws_security_group' || headResource.type === 'aws_security_group_rule') {
              iacChanges.push(`SECURITY_GROUP_ADDITION: ${address}`);
            }
          } else {
            // Check for modifications (simplified comparison)
            const baseJson = JSON.stringify(baseResource.change || {});
            const headJson = JSON.stringify(headResource.change || {});
            
            if (baseJson !== headJson) {
              const change = headResource.change || {};
              const actions = change.actions || [];
              
              if (actions.includes('update')) {
                iacChanges.push(`RESOURCE_MODIFICATION: ${headResource.type} - ${address}`);
                
                // Flag security-sensitive modifications
                if (headResource.type === 'aws_security_group' || headResource.type === 'aws_security_group_rule') {
                  iacChanges.push(`SECURITY_GROUP_CHANGE: ${address}`);
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
        const scoringResult = this.riskScorer.scoreChanges(iacChanges, 'INFRASTRUCTURE');
        
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

  async analyzeCloudFormationTemplates(files, octokit, owner, repo, pullRequest, cloudformationGlob, costThreshold) {
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
              estimatedCostIncrease += this.estimateResourceCost(resourceType);
              
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
              estimatedCostIncrease += this.estimateResourceCost(headResource.Type);
              
              // Flag security-sensitive additions
              if (headResource.Type === 'AWS::EC2::SecurityGroup' || 
                  headResource.Type === 'AWS::EC2::SecurityGroupIngress' ||
                  headResource.Type === 'AWS::EC2::SecurityGroupEgress') {
                iacChanges.push(`SECURITY_GROUP_ADDITION: ${logicalId}`);
              }
            } else {
              // Check for modifications (compare resource properties)
              const baseJson = JSON.stringify(baseResource);
              const headJson = JSON.stringify(headResource);
              
              if (baseJson !== headJson) {
                // Resource type change is critical
                if (baseResource.Type !== headResource.Type) {
                  iacChanges.push(`RESOURCE_TYPE_CHANGE: ${logicalId} from ${baseResource.Type} to ${headResource.Type}`);
                } else {
                  iacChanges.push(`RESOURCE_MODIFICATION: ${headResource.Type} - ${logicalId}`);
                }
                
                // Flag security-sensitive modifications
                if (headResource.Type === 'AWS::EC2::SecurityGroup' || 
                    headResource.Type === 'AWS::EC2::SecurityGroupIngress' ||
                    headResource.Type === 'AWS::EC2::SecurityGroupEgress') {
                  iacChanges.push(`SECURITY_GROUP_CHANGE: ${logicalId}`);
                }
                
                // Check for deletion policy changes
                if (baseResource.DeletionPolicy !== headResource.DeletionPolicy) {
                  iacChanges.push(`DELETION_POLICY_CHANGE: ${logicalId} from ${baseResource.DeletionPolicy || 'default'} to ${headResource.DeletionPolicy || 'default'}`);
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
          const scoringResult = this.riskScorer.scoreChanges(iacChanges, 'CLOUDFORMATION');
          
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

  // Simple cost estimation helper (MVP - would use AWS Pricing API in production)
  estimateResourceCost(resourceType) {
    const costMap = {
      // Terraform resource types
      'aws_instance': 50,
      'aws_db_instance': 100,
      'aws_elasticache_cluster': 75,
      'aws_eks_cluster': 150,
      'aws_alb': 25,
      'aws_nat_gateway': 45,
      
      // CloudFormation resource types
      'AWS::EC2::Instance': 50,
      'AWS::RDS::DBInstance': 100,
      'AWS::ElastiCache::CacheCluster': 75,
      'AWS::EKS::Cluster': 150,
      'AWS::ElasticLoadBalancingV2::LoadBalancer': 25,
      'AWS::EC2::NatGateway': 45
    };
    
    return costMap[resourceType] || 0;
  }
}

module.exports = IaCAnalyzer;