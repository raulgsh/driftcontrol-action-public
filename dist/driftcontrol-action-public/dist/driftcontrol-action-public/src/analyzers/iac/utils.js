// IaC analysis utility functions

// Simple cost estimation helper (MVP - would use AWS Pricing API in production)
function estimateResourceCost(resourceType) {
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
function compareResourceProperties(baseObj, headObj, resourceId, path = '') {
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
        isSecuritySensitive: isSecuritySensitiveProperty(currentPath, baseObj[key])
      });
    } else if (isArray(baseObj[key]) && isArray(headObj[key])) {
      // Special handling for arrays
      const arrayChanges = compareArrays(baseObj[key], headObj[key], resourceId, currentPath);
      changes.push(...arrayChanges);
    } else if (isObject(baseObj[key]) && isObject(headObj[key])) {
      // Recursive comparison for nested objects
      const nestedChanges = compareResourceProperties(baseObj[key], headObj[key], resourceId, currentPath);
      changes.push(...nestedChanges);
    } else if (baseObj[key] !== headObj[key]) {
      // Value changed
      changes.push({
        type: 'modified',
        path: currentPath,
        oldValue: baseObj[key],
        newValue: headObj[key],
        detailed: `PROPERTY_MODIFIED: ${resourceId}.${currentPath}: ${JSON.stringify(baseObj[key])} → ${JSON.stringify(headObj[key])}`,
        isSecuritySensitive: isSecuritySensitiveProperty(currentPath, baseObj[key], headObj[key])
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
        isSecuritySensitive: isSecuritySensitiveProperty(currentPath, null, headObj[key])
      });
    }
  }
  
  return changes;
}

// Compare arrays intelligently based on content type
function compareArrays(baseArray, headArray, resourceId, path) {
  const changes = [];
  
  // For security rules and similar objects, use intelligent matching
  if (baseArray.length > 0 && isObject(baseArray[0])) {
    return compareObjectArrays(baseArray, headArray, resourceId, path);
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
        isSecuritySensitive: isSecuritySensitiveProperty(currentPath, null, headArray[i])
      });
    } else if (i >= headArray.length) {
      changes.push({
        type: 'removed',
        path: currentPath,
        oldValue: baseArray[i],
        detailed: `PROPERTY_REMOVED: ${resourceId}.${currentPath}`,
        isSecuritySensitive: isSecuritySensitiveProperty(currentPath, baseArray[i])
      });
    } else if (JSON.stringify(baseArray[i]) !== JSON.stringify(headArray[i])) {
      if (isObject(baseArray[i]) && isObject(headArray[i])) {
        const nestedChanges = compareResourceProperties(baseArray[i], headArray[i], resourceId, currentPath);
        changes.push(...nestedChanges);
      } else {
        changes.push({
          type: 'modified',
          path: currentPath,
          oldValue: baseArray[i],
          newValue: headArray[i],
          detailed: `PROPERTY_MODIFIED: ${resourceId}.${currentPath}: ${JSON.stringify(baseArray[i])} → ${JSON.stringify(headArray[i])}`,
          isSecuritySensitive: isSecuritySensitiveProperty(currentPath, baseArray[i], headArray[i])
        });
      }
    }
  }
  
  return changes;
}

// Intelligently compare arrays of objects (like security rules)
function compareObjectArrays(baseArray, headArray, resourceId, path) {
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
        const itemPath = `${path}[${describeArrayItem(baseItem)}]`;
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
      const itemPath = `${path}[${describeArrayItem(baseItem)}]`;
      changes.push({
        type: 'removed',
        path: itemPath,
        oldValue: baseItem,
        detailed: `PROPERTY_REMOVED: ${resourceId}.${itemPath}`,
        isSecuritySensitive: isSecuritySensitiveProperty(path, baseItem)
      });
    }
  }
  
  // Find truly added items (not in base at all)
  for (const [matchFp, { item: headItem }] of headMatchMap) {
    if (!baseMatchMap.has(matchFp)) {
      const itemPath = `${path}[${describeArrayItem(headItem)}]`;
      changes.push({
        type: 'added',
        path: itemPath,
        newValue: headItem,
        detailed: `PROPERTY_ADDED: ${resourceId}.${itemPath}: ${JSON.stringify(headItem)}`,
        isSecuritySensitive: isSecuritySensitiveProperty(path, null, headItem)
      });
    }
  }
  
  return changes;
}

// Create a human-readable description of an array item
function describeArrayItem(item) {
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
function isSecuritySensitiveProperty(path, oldValue = null, newValue = null) {
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
function isObject(val) {
  return val !== null && typeof val === 'object' && !Array.isArray(val);
}

function isArray(val) {
  return Array.isArray(val);
}

// Generic base/head template fetching for IaC files
async function fetchBaseAndHeadTemplates(octokit, owner, repo, filepath, pullRequest, parseFunction, contentFetcher = null) {
  const core = require('@actions/core');
  let headTemplate = null;
  let baseTemplate = null;
  let headError = null;
  let baseError = null;
  
  if (contentFetcher) {
    // Use ContentFetcher for batch fetching
    const results = await contentFetcher.batchFetch([
      { path: filepath, ref: pullRequest.head.sha, description: `head template ${filepath}` },
      { path: filepath, ref: pullRequest.base.sha, description: `base template ${filepath}` }
    ]);
    
    try {
      if (results[0]) {
        headTemplate = parseFunction(results[0].content);
        core.info(`Parsed head template from: ${filepath}`);
      } else {
        headError = new Error('Not Found');
        core.info(`No template found in head branch at ${filepath}`);
      }
    } catch (error) {
      headError = error;
      core.info(`Failed to parse head template: ${error.message}`);
    }
    
    try {
      if (results[1]) {
        baseTemplate = parseFunction(results[1].content);
        core.info(`Parsed base template from: ${filepath}`);
      } else {
        baseError = new Error('Not Found');
        core.info(`No template found in base branch at ${filepath}`);
      }
    } catch (error) {
      baseError = error;
      core.info(`Failed to parse base template: ${error.message}`);
    }
  } else {
    // Legacy method for backward compatibility
    try {
      const { data: headData } = await octokit.rest.repos.getContent({
        owner,
        repo,
        path: filepath,
        ref: pullRequest.head.sha
      });
      const headContent = Buffer.from(headData.content, 'base64').toString();
      headTemplate = parseFunction(headContent);
      core.info(`Parsed head template from: ${filepath}`);
    } catch (error) {
      headError = error;
      core.info(`No template found in head branch at ${filepath}: ${error.message}`);
    }
    
    try {
      const { data: baseData } = await octokit.rest.repos.getContent({
        owner,
        repo,
        path: filepath,
        ref: pullRequest.base.sha
      });
      const baseContent = Buffer.from(baseData.content, 'base64').toString();
      baseTemplate = parseFunction(baseContent);
      core.info(`Parsed base template from: ${filepath}`);
    } catch (error) {
      baseError = error;
      core.info(`No template found in base branch at ${filepath}: ${error.message}`);
    }
  }
  
  // If both fetches failed with actual errors (not just missing files), propagate the error
  if (headError && baseError && headError.message !== 'Not Found' && baseError.message !== 'Not Found') {
    throw headError; // Re-throw to trigger the warning in outer catch
  }
  
  return { baseTemplate, headTemplate, headError, baseError };
}

// Build resource map from template (works for both Terraform and CloudFormation)
function buildResourceMap(template, resourceAccessor) {
  if (!template) return new Map();
  
  // Handle both function accessor and string key
  const resources = typeof resourceAccessor === 'function' 
    ? resourceAccessor(template)
    : template[resourceAccessor];
    
  const map = new Map();
  
  if (!resources) return map;
  
  // Process resources based on type (array vs object)
  if (Array.isArray(resources)) {
    // Terraform style: array of resource_changes
    resources.forEach(resource => {
      if (resource.address) {
        map.set(resource.address, resource);
      }
    });
  } else if (typeof resources === 'object') {
    // CloudFormation style: Resources object
    Object.entries(resources).forEach(([logicalId, resource]) => {
      map.set(logicalId, { ...resource, address: logicalId });
    });
  }
  
  return map;
}

// Analyze resource changes between base and head maps
function analyzeResourceChanges(baseMap, headMap, getResourceType, isSecurityResource) {
  const iacChanges = [];
  let estimatedCostIncrease = 0;
  
  // Check for removed resources (exist in base but not in head)
  for (const [address, baseResource] of baseMap) {
    if (!headMap.has(address)) {
      const resourceType = getResourceType(baseResource);
      iacChanges.push(`RESOURCE_DELETION: ${resourceType} - ${address}`);
      
      // Flag security-sensitive deletions
      if (isSecurityResource(resourceType)) {
        iacChanges.push(`SECURITY_GROUP_DELETION: ${address}`);
      }
    }
  }
  
  // Check for added resources and modifications
  for (const [address, headResource] of headMap) {
    const baseResource = baseMap.get(address);
    const resourceType = getResourceType(headResource);
    
    if (!baseResource) {
      // Resource added
      iacChanges.push(`RESOURCE_ADDITION: ${resourceType} - ${address}`);
      
      // Check if this is a create action for cost estimation
      const change = headResource.change || {};
      const actions = change.actions || [];
      if (actions.includes('create') || !actions.length) { // No actions means new resource in CloudFormation
        estimatedCostIncrease += estimateResourceCost(resourceType);
      }
      
      // Flag security-sensitive additions
      if (isSecurityResource(resourceType)) {
        iacChanges.push(`SECURITY_GROUP_ADDITION: ${address}`);
      }
    } else {
      // Check for resource type change first (CloudFormation specific)
      const baseType = getResourceType(baseResource);
      if (baseType !== resourceType) {
        iacChanges.push(`RESOURCE_TYPE_CHANGE: ${address} from ${baseType} to ${resourceType}`);
      }
      
      // Deep comparison of resource properties
      const change = headResource.change || {};
      const actions = change.actions || [];
      
      if (actions.includes('update') || actions.includes('modify') || baseType !== resourceType) {
        // Extract before and after states for comparison
        const beforeState = change.before || baseResource.change?.after || baseResource.Properties || {};
        const afterState = change.after || headResource.Properties || {};
        
        // Perform detailed property comparison
        const propertyChanges = compareResourceProperties(
          beforeState,
          afterState,
          address
        );
        
        // Add high-level change for risk scorer compatibility
        if (propertyChanges.length > 0 || baseType !== resourceType) {
          iacChanges.push(`RESOURCE_MODIFICATION: ${resourceType} - ${address}`);
          
          // Add detailed property changes
          for (const propChange of propertyChanges) {
            iacChanges.push(propChange.detailed);
            
            // Flag security-sensitive changes
            if (propChange.isSecuritySensitive) {
              if (isSecurityResource(resourceType)) {
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
  
  return { iacChanges, estimatedCostIncrease };
}

// Build final IaC result object
function buildIaCResult(changes, filepath, scoringType, costThreshold, estimatedCostIncrease, riskScorer) {
  const iacChanges = [...changes];
  
  // Check if cost increase exceeds threshold
  if (estimatedCostIncrease > parseFloat(costThreshold)) {
    iacChanges.push(`COST_INCREASE: Estimated $${estimatedCostIncrease}/month`);
  }
  
  // Score the changes using existing risk scorer
  if (iacChanges.length > 0) {
    const scoringResult = riskScorer.scoreChanges(iacChanges, scoringType);
    
    return {
      type: 'infrastructure',
      file: filepath,
      severity: scoringResult.severity,
      changes: iacChanges,
      reasoning: scoringResult.reasoning,
      costImpact: estimatedCostIncrease > 0 ? `$${estimatedCostIncrease}/month` : null
    };
  }
  
  return null;
}

// Secure command execution utilities
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Secure command execution with sandboxing
function executeTerraformCommand(command, workingDir, timeout = 30000) {
  const core = require('@actions/core');
  
  try {
    // Security validation
    if (!command.startsWith('terraform')) {
      throw new Error('Only terraform commands are allowed');
    }
    
    // Check for dangerous characters
    const dangerousPatterns = [';', '&&', '||', '|', '>', '<', '`', '$', '\\'];
    if (dangerousPatterns.some(pattern => command.includes(pattern))) {
      throw new Error('Command contains unsafe characters');
    }
    
    // Create temporary directory for isolated execution
    const tempDir = path.join('/tmp', `terraform-${crypto.randomBytes(8).toString('hex')}`);
    fs.mkdirSync(tempDir, { recursive: true });
    
    // Execute with strict timeout and resource limits
    const result = execSync(command, {
      cwd: workingDir,
      timeout: timeout,
      maxBuffer: 10 * 1024 * 1024, // 10MB max output
      env: {
        ...process.env,
        TF_IN_AUTOMATION: 'true',
        TF_INPUT: 'false',
        TF_CLI_ARGS: '-no-color',
        TMPDIR: tempDir // Isolate temp files
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    
    // Cleanup temp directory
    fs.rmSync(tempDir, { recursive: true, force: true });
    
    return result.toString();
  } catch (error) {
    core.warning(`Terraform command failed: ${error.message}`);
    return null;
  }
}

// Generate Terraform plan JSON from HCL files
async function generateTerraformPlan(workingDir, targetFile = null) {
  const core = require('@actions/core');
  
  try {
    // Check if Terraform is available
    const version = executeTerraformCommand('terraform version -json', workingDir, 5000);
    if (!version) {
      core.info('Terraform CLI not available, falling back to HCL analysis');
      return null;
    }
    
    core.info('Terraform CLI detected, generating plan...');
    
    // Initialize Terraform (lightweight, no backend)
    const initResult = executeTerraformCommand(
      'terraform init -backend=false -input=false -no-color',
      workingDir,
      60000
    );
    
    if (!initResult) {
      core.warning('Terraform init failed, falling back to HCL analysis');
      return null;
    }
    
    // Generate plan with JSON output
    const planFile = path.join('/tmp', `tfplan-${Date.now()}.json`);
    const planCommand = targetFile 
      ? `terraform plan -json -out=${planFile} -target=${targetFile} -input=false`
      : `terraform plan -json -out=${planFile} -input=false`;
    
    const planResult = executeTerraformCommand(planCommand, workingDir, 120000);
    
    if (!planResult || !fs.existsSync(planFile)) {
      core.warning('Terraform plan generation failed, falling back to HCL analysis');
      return null;
    }
    
    // Convert binary plan to JSON
    const showResult = executeTerraformCommand(
      `terraform show -json ${planFile}`,
      workingDir,
      30000
    );
    
    // Cleanup plan file
    fs.unlinkSync(planFile);
    
    if (!showResult) {
      return null;
    }
    
    return JSON.parse(showResult);
  } catch (error) {
    core.warning(`Plan generation failed: ${error.message}`);
    return null;
  }
}

// Secure Git checkout to temporary directory
async function checkoutToTemp(octokit, owner, repo, sha, targetDir) {
  const core = require('@actions/core');
  
  try {
    // Create target directory
    fs.mkdirSync(targetDir, { recursive: true });
    
    // Use GitHub API to download archive
    const { data } = await octokit.rest.repos.downloadArchive({
      owner,
      repo,
      archive_format: 'tarball',
      ref: sha
    });
    
    // Save and extract archive
    const archivePath = path.join('/tmp', `${sha}.tar.gz`);
    fs.writeFileSync(archivePath, Buffer.from(data));
    
    // Extract with security constraints
    execSync(`tar -xzf ${archivePath} -C ${targetDir} --strip-components=1`, {
      timeout: 30000,
      maxBuffer: 50 * 1024 * 1024
    });
    
    // Cleanup archive
    fs.unlinkSync(archivePath);
    
    core.info(`Checked out ${sha} to ${targetDir}`);
    return true;
  } catch (error) {
    core.warning(`Failed to checkout ${sha}: ${error.message}`);
    return false;
  }
}

module.exports = {
  estimateResourceCost,
  compareResourceProperties,
  compareArrays,
  compareObjectArrays,
  describeArrayItem,
  isSecuritySensitiveProperty,
  isObject,
  isArray,
  fetchBaseAndHeadTemplates,
  buildResourceMap,
  analyzeResourceChanges,
  buildIaCResult,
  executeTerraformCommand,
  generateTerraformPlan,
  checkoutToTemp
};