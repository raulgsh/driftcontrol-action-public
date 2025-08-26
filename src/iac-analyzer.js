const core = require('@actions/core');
const yaml = require('yaml');
const riskScorer = require('./risk-scorer');

class IaCAnalyzer {
  constructor() {
    this.riskScorer = riskScorer;
  }

  async analyzeIaCFiles(files, octokit, owner, repo, pullRequestHeadSha, terraformPath, cloudformationGlob, costThreshold) {
    const driftResults = [];
    let hasHighSeverity = false;
    let hasMediumSeverity = false;

    try {
      // Process Terraform plan if specified
      if (terraformPath && files.some(f => f.filename === terraformPath)) {
        const tfResult = await this.analyzeTerraformPlan(
          octokit, owner, repo, pullRequestHeadSha, terraformPath, costThreshold
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
          files, octokit, owner, repo, pullRequestHeadSha, cloudformationGlob, costThreshold
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

  async analyzeTerraformPlan(octokit, owner, repo, pullRequestHeadSha, terraformPath, costThreshold) {
    try {
      core.info(`Analyzing Terraform plan at: ${terraformPath}`);
      
      // Fetch Terraform plan JSON
      const { data: fileData } = await octokit.rest.repos.getContent({
        owner,
        repo,
        path: terraformPath,
        ref: pullRequestHeadSha
      });
      
      const planContent = Buffer.from(fileData.content, 'base64').toString();
      const plan = JSON.parse(planContent);
      
      const iacChanges = [];
      let estimatedCostIncrease = 0;
      
      // Analyze resource changes
      if (plan.resource_changes) {
        for (const resource of plan.resource_changes) {
          const change = resource.change || {};
          const actions = change.actions || [];
          
          // Check for security group changes
          if (resource.type === 'aws_security_group' || resource.type === 'aws_security_group_rule') {
            if (actions.includes('delete')) {
              iacChanges.push(`SECURITY_GROUP_DELETION: ${resource.address}`);
            } else if (actions.includes('update') || actions.includes('create')) {
              iacChanges.push(`SECURITY_GROUP_CHANGE: ${resource.address}`);
            }
          }
          
          // Check for resource deletions
          if (actions.includes('delete')) {
            iacChanges.push(`RESOURCE_DELETION: ${resource.type} - ${resource.address}`);
          }
          
          // Simple cost estimation
          if (actions.includes('create')) {
            estimatedCostIncrease += this.estimateResourceCost(resource.type);
          }
        }
      }
      
      // Check if cost increase exceeds threshold
      if (estimatedCostIncrease > parseFloat(costThreshold)) {
        iacChanges.push(`COST_INCREASE: Estimated $${estimatedCostIncrease}/month`);
      }
      
      // Score the changes
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

  async analyzeCloudFormationTemplates(files, octokit, owner, repo, pullRequestHeadSha, cloudformationGlob, costThreshold) {
    const results = [];
    
    // Convert glob to regex (reuse pattern from sql-analyzer)
    let globRegexPattern;
    if (cloudformationGlob.includes('**/')) {
      const parts = cloudformationGlob.split('**/');
      const prefix = parts[0].replace(/\./g, '\\.');
      const suffix = parts[1]
        .replace(/\./g, '\\.')
        .replace(/\*/g, '[^/]*');
      globRegexPattern = `^${prefix}.*${suffix}$`;
    } else {
      globRegexPattern = cloudformationGlob
        .replace(/\./g, '\\.')
        .replace(/\*\*/g, '.*')
        .replace(/\*/g, '[^/]*')
        + '$';
    }
    
    const cfPattern = new RegExp(globRegexPattern);
    const cfFiles = files.filter(file => cfPattern.test(file.filename));
    
    core.info(`CloudFormation glob: ${cloudformationGlob} -> regex: ${globRegexPattern}`);
    core.info(`CloudFormation files found: ${cfFiles.map(f => f.filename).join(', ')}`);
    
    for (const file of cfFiles) {
      try {
        core.info(`Analyzing CloudFormation template: ${file.filename}`);
        
        // Fetch template content
        const { data: fileData } = await octokit.rest.repos.getContent({
          owner,
          repo,
          path: file.filename,
          ref: pullRequestHeadSha
        });
        
        const templateContent = Buffer.from(fileData.content, 'base64').toString();
        const template = templateContent.trim().startsWith('{') 
          ? JSON.parse(templateContent)
          : yaml.parse(templateContent);
        
        const iacChanges = [];
        let estimatedCostIncrease = 0;
        
        // Analyze CloudFormation resources
        if (template.Resources) {
          for (const [logicalId, resource] of Object.entries(template.Resources)) {
            const resourceType = resource.Type;
            
            // Check for security group changes
            if (resourceType === 'AWS::EC2::SecurityGroup' || 
                resourceType === 'AWS::EC2::SecurityGroupIngress' ||
                resourceType === 'AWS::EC2::SecurityGroupEgress') {
              
              // Check if this is a modification (would need base comparison for full detection)
              iacChanges.push(`SECURITY_GROUP_CHANGE: ${logicalId}`);
            }
            
            // Check for potential deletions (simplified - would need base comparison)
            if (resource.DeletionPolicy === 'Delete') {
              iacChanges.push(`RESOURCE_DELETION_POLICY: ${logicalId}`);
            }
            
            // Simple cost estimation for new resources
            estimatedCostIncrease += this.estimateResourceCost(resourceType);
          }
        }
        
        // Check if cost increase exceeds threshold
        if (estimatedCostIncrease > parseFloat(costThreshold)) {
          iacChanges.push(`COST_INCREASE: Estimated $${estimatedCostIncrease}/month`);
        }
        
        // Score the changes
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