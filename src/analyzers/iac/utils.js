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
function isSecuritySensitiveProperty(path, _oldValue = null, newValue = null) {
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

module.exports = {
  estimateResourceCost,
  compareResourceProperties,
  compareArrays,
  compareObjectArrays,
  describeArrayItem,
  isSecuritySensitiveProperty,
  isObject,
  isArray
};