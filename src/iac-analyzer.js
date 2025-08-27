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
      let headError = null;
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
      
      // Fetch base version of Terraform plan
      let basePlan = null;
      let baseError = null;
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
              estimatedCostIncrease += this.estimateResourceCost(resource.type);
              
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
              estimatedCostIncrease += this.estimateResourceCost(headResource.type);
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
              const propertyChanges = this.compareResourceProperties(
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
              // Check for resource type change first
              if (baseResource.Type !== headResource.Type) {
                iacChanges.push(`RESOURCE_TYPE_CHANGE: ${logicalId} from ${baseResource.Type} to ${headResource.Type}`);
              }
              
              // Deep comparison of resource properties
              const baseProperties = baseResource.Properties || {};
              const headProperties = headResource.Properties || {};
              
              const propertyChanges = this.compareResourceProperties(
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

  // Deep comparison of resource properties to detect granular changes
  compareResourceProperties(baseObj, headObj, resourceId, path = '') {
    const changes = [];
    const processedKeys = new Set();
    
    // Helper to format the property path
    const formatPath = (key) => {
      if (path) {
        // Handle array indices and nested properties
        if (typeof key === 'number') {
          return `${path}[${key}]`;
        }
        return `${path}.${key}`;
      }
      return key;
    };
    
    // Check for removed properties (in base but not in head)
    for (const key in baseObj) {
      processedKeys.add(key);
      const currentPath = formatPath(key);
      
      if (!(key in headObj)) {
        changes.push({
          type: 'removed',
          path: currentPath,
          oldValue: baseObj[key],
          detailed: `PROPERTY_REMOVED: ${resourceId}.${currentPath}`,
          isSecuritySensitive: this.isSecuritySensitiveProperty(currentPath, baseObj[key])
        });
      } else if (this.isArray(baseObj[key]) && this.isArray(headObj[key])) {
        // Special handling for arrays
        const arrayChanges = this.compareArrays(baseObj[key], headObj[key], resourceId, currentPath);
        changes.push(...arrayChanges);
      } else if (this.isObject(baseObj[key]) && this.isObject(headObj[key])) {
        // Recursive comparison for nested objects
        const nestedChanges = this.compareResourceProperties(baseObj[key], headObj[key], resourceId, currentPath);
        changes.push(...nestedChanges);
      } else if (baseObj[key] !== headObj[key]) {
        // Value changed
        changes.push({
          type: 'modified',
          path: currentPath,
          oldValue: baseObj[key],
          newValue: headObj[key],
          detailed: `PROPERTY_MODIFIED: ${resourceId}.${currentPath}: ${JSON.stringify(baseObj[key])} → ${JSON.stringify(headObj[key])}`,
          isSecuritySensitive: this.isSecuritySensitiveProperty(currentPath, baseObj[key], headObj[key])
        });
      }
    }
    
    // Check for added properties (in head but not in base)
    for (const key in headObj) {
      if (!processedKeys.has(key)) {
        const currentPath = formatPath(key);
        changes.push({
          type: 'added',
          path: currentPath,
          newValue: headObj[key],
          detailed: `PROPERTY_ADDED: ${resourceId}.${currentPath} = ${JSON.stringify(headObj[key])}`,
          isSecuritySensitive: this.isSecuritySensitiveProperty(currentPath, null, headObj[key])
        });
      }
    }
    
    return changes;
  }
  
  // Compare arrays intelligently based on content type
  compareArrays(baseArray, headArray, resourceId, path) {
    const changes = [];
    
    // For security rules and similar objects, use intelligent matching
    if (baseArray.length > 0 && this.isObject(baseArray[0])) {
      return this.compareObjectArrays(baseArray, headArray, resourceId, path);
    }
    
    // For simple arrays, do index-based comparison
    const maxLength = Math.max(baseArray.length, headArray.length);
    for (let i = 0; i < maxLength; i++) {
      const currentPath = `${path}[${i}]`;
      
      if (i >= baseArray.length) {
        changes.push({
          type: 'added',
          path: currentPath,
          newValue: headArray[i],
          detailed: `PROPERTY_ADDED: ${resourceId}.${currentPath} = ${JSON.stringify(headArray[i])}`,
          isSecuritySensitive: this.isSecuritySensitiveProperty(currentPath, null, headArray[i])
        });
      } else if (i >= headArray.length) {
        changes.push({
          type: 'removed',
          path: currentPath,
          oldValue: baseArray[i],
          detailed: `PROPERTY_REMOVED: ${resourceId}.${currentPath}`,
          isSecuritySensitive: this.isSecuritySensitiveProperty(currentPath, baseArray[i])
        });
      } else if (JSON.stringify(baseArray[i]) !== JSON.stringify(headArray[i])) {
        if (this.isObject(baseArray[i]) && this.isObject(headArray[i])) {
          const nestedChanges = this.compareResourceProperties(baseArray[i], headArray[i], resourceId, currentPath);
          changes.push(...nestedChanges);
        } else {
          changes.push({
            type: 'modified',
            path: currentPath,
            oldValue: baseArray[i],
            newValue: headArray[i],
            detailed: `PROPERTY_MODIFIED: ${resourceId}.${currentPath}: ${JSON.stringify(baseArray[i])} → ${JSON.stringify(headArray[i])}`,
            isSecuritySensitive: this.isSecuritySensitiveProperty(currentPath, baseArray[i], headArray[i])
          });
        }
      }
    }
    
    return changes;
  }
  
  // Intelligently compare arrays of objects (like security rules)
  compareObjectArrays(baseArray, headArray, resourceId, path) {
    const changes = [];
    
    // Create matching fingerprint (protocol/port only) for rule matching
    const getMatchingFingerprint = (obj) => {
      // For security group rules - match by protocol and ports only
      if ('from_port' in obj || 'to_port' in obj || 'FromPort' in obj || 'ToPort' in obj) {
        const protocol = obj.protocol || obj.IpProtocol || obj.Protocol || 'tcp';
        const fromPort = obj.from_port || obj.FromPort || obj.from || 0;
        const toPort = obj.to_port || obj.ToPort || obj.to || 0;
        return `${protocol}-${fromPort}-${toPort}`; // Excludes CIDR for matching
      }
      // For other objects, use JSON string as fingerprint
      return JSON.stringify(obj);
    };
    
    // Create full fingerprint (includes all properties) for detecting changes
    const getFullFingerprint = (obj) => {
      // For security group rules
      if ('from_port' in obj || 'to_port' in obj || 'FromPort' in obj || 'ToPort' in obj) {
        const protocol = obj.protocol || obj.IpProtocol || obj.Protocol || 'tcp';
        const fromPort = obj.from_port || obj.FromPort || obj.from || 0;
        const toPort = obj.to_port || obj.ToPort || obj.to || 0;
        const cidr = obj.cidr_blocks?.[0] || obj.CidrIp || obj.cidr || '';
        return `${protocol}-${fromPort}-${toPort}-${cidr}`;
      }
      // For other objects, use JSON string as fingerprint
      return JSON.stringify(obj);
    };
    
    // Helper to describe what changed between two security rules and return property-specific details
    const describeRuleChange = (baseItem, headItem, itemPath) => {
      const detailedChanges = [];
      
      // Check CIDR changes
      const baseCidrs = baseItem.cidr_blocks || (baseItem.CidrIp ? [baseItem.CidrIp] : (baseItem.cidr ? [baseItem.cidr] : []));
      const headCidrs = headItem.cidr_blocks || (headItem.CidrIp ? [headItem.CidrIp] : (headItem.cidr ? [headItem.cidr] : []));
      
      if (JSON.stringify(baseCidrs) !== JSON.stringify(headCidrs)) {
        const cidrPath = baseItem.cidr_blocks !== undefined ? 'cidr_blocks' : (baseItem.CidrIp !== undefined ? 'CidrIp' : 'cidr');
        detailedChanges.push(`PROPERTY_MODIFIED: ${resourceId}.${itemPath}.${cidrPath}: ${JSON.stringify(baseCidrs)} → ${JSON.stringify(headCidrs)}`);
      }
      
      // Check for description changes
      const baseDesc = baseItem.description || baseItem.Description || '';
      const headDesc = headItem.description || headItem.Description || '';
      if (baseDesc !== headDesc) {
        const descPath = baseItem.description !== undefined ? 'description' : 'Description';
        detailedChanges.push(`PROPERTY_MODIFIED: ${resourceId}.${itemPath}.${descPath}: ${JSON.stringify(baseDesc)} → ${JSON.stringify(headDesc)}`);
      }
      
      // If no specific property changes found, return a general modification message
      if (detailedChanges.length === 0) {
        detailedChanges.push(`PROPERTY_MODIFIED: ${resourceId}.${itemPath}: rule properties changed`);
      }
      
      return detailedChanges;
    };
    
    // Build maps with matching fingerprints
    const baseMatchMap = new Map();
    const headMatchMap = new Map();
    const processedBase = new Set();
    
    baseArray.forEach((item, index) => {
      const matchFp = getMatchingFingerprint(item);
      baseMatchMap.set(matchFp, { item, index });
    });
    
    headArray.forEach((item, index) => {
      const matchFp = getMatchingFingerprint(item);
      headMatchMap.set(matchFp, { item, index });
    });
    
    // Check for modifications and removals
    for (const [matchFp, { item: baseItem }] of baseMatchMap) {
      const headMatch = headMatchMap.get(matchFp);
      processedBase.add(matchFp);
      
      if (headMatch) {
        // Rule exists in both - check for property changes
        const baseFullFp = getFullFingerprint(baseItem);
        const headFullFp = getFullFingerprint(headMatch.item);
        
        if (baseFullFp !== headFullFp) {
          // Properties changed - report as modification
          const itemPath = `${path}[${this.describeArrayItem(baseItem)}]`;
          const detailedChanges = describeRuleChange(baseItem, headMatch.item, itemPath);
          
          // Push each detailed change as a separate change entry for compatibility with tests
          detailedChanges.forEach(detailed => {
            changes.push({
              type: 'modified',
              path: itemPath,
              oldValue: baseItem,
              newValue: headMatch.item,
              detailed: detailed,
              isSecuritySensitive: true // Security rule modifications are always sensitive
            });
          });
        }
        // If fingerprints match exactly, no change to report
      } else {
        // Rule removed entirely
        const itemPath = `${path}[${this.describeArrayItem(baseItem)}]`;
        changes.push({
          type: 'removed',
          path: itemPath,
          oldValue: baseItem,
          detailed: `PROPERTY_REMOVED: ${resourceId}.${itemPath}`,
          isSecuritySensitive: this.isSecuritySensitiveProperty(path, baseItem)
        });
      }
    }
    
    // Find truly added items (not in base at all)
    for (const [matchFp, { item: headItem }] of headMatchMap) {
      if (!baseMatchMap.has(matchFp)) {
        const itemPath = `${path}[${this.describeArrayItem(headItem)}]`;
        changes.push({
          type: 'added',
          path: itemPath,
          newValue: headItem,
          detailed: `PROPERTY_ADDED: ${resourceId}.${itemPath}: ${JSON.stringify(headItem)}`,
          isSecuritySensitive: this.isSecuritySensitiveProperty(path, null, headItem)
        });
      }
    }
    
    return changes;
  }
  
  // Create a human-readable description of an array item
  describeArrayItem(item) {
    if (typeof item === 'object' && item !== null) {
      // Security group rules
      if ('from_port' in item || 'FromPort' in item) {
        const port = item.from_port || item.FromPort || item.from;
        const protocol = item.protocol || item.IpProtocol || 'tcp';
        return `${protocol}:${port}`;
      }
      // Generic object - use first meaningful property
      const keys = Object.keys(item);
      if (keys.length > 0) {
        return `${keys[0]}:${item[keys[0]]}`;
      }
    }
    return String(item);
  }
  
  // Check if a property change is security-sensitive
  isSecuritySensitiveProperty(path, _oldValue = null, newValue = null) {
    const sensitivePatterns = [
      /security/i,
      /cidr/i,
      /ingress/i,
      /egress/i,
      /port/i,
      /public/i,
      /deletion/i,
      /policy/i,
      /role/i,
      /permission/i
    ];
    
    // Check if path contains sensitive keywords
    if (sensitivePatterns.some(pattern => pattern.test(path))) {
      return true;
    }
    
    // Check for CIDR block widening (security risk)
    if (newValue && typeof newValue === 'string' && newValue.includes('0.0.0.0/0')) {
      return true;
    }
    
    return false;
  }
  
  // Utility functions
  isObject(val) {
    return val !== null && typeof val === 'object' && !Array.isArray(val);
  }
  
  isArray(val) {
    return Array.isArray(val);
  }
}

module.exports = IaCAnalyzer;