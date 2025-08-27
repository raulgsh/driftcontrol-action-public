// Shared utilities for config analysis
const core = require('@actions/core');

// Sensitive key patterns for redaction
const sensitivePatterns = /password|secret|token|key|credential|auth|api_key|private|pwd/i;

// Security-first: Extract keys only, never values
function extractKeysOnly(obj, path = '', depth = 0) {
  const keys = [];
  const maxDepth = 10; // Prevent infinite recursion

  if (depth > maxDepth) return keys;

  if (typeof obj === 'object' && obj !== null && !Array.isArray(obj)) {
    for (const key in obj) {
      // Redact sensitive key names
      const sanitizedKey = sensitivePatterns.test(key) 
        ? `[REDACTED_${key.substring(0, 3).toUpperCase()}]` 
        : key;
      
      const fullPath = path ? `${path}.${sanitizedKey}` : sanitizedKey;
      keys.push(fullPath);
      
      // Recursively extract nested keys
      if (typeof obj[key] === 'object' && obj[key] !== null) {
        keys.push(...extractKeysOnly(obj[key], fullPath, depth + 1));
      }
    }
  } else if (Array.isArray(obj)) {
    // For arrays, just note that it's an array without exposing values
    keys.push(`${path}[]`);
  }

  return keys;
}

// Compare key sets between base and head
function compareKeys(baseKeys, headKeys) {
  const baseSet = new Set(baseKeys);
  const headSet = new Set(headKeys);
  
  const added = [...headSet].filter(k => !baseSet.has(k));
  const removed = [...baseSet].filter(k => !headSet.has(k));
  const changes = [];

  // Analyze changes
  for (const key of removed) {
    if (key.includes('[REDACTED')) {
      changes.push(`SECRET_KEY_REMOVED: ${key}`);
    } else {
      changes.push(`CONFIG_KEY_REMOVED: ${key}`);
    }
  }

  for (const key of added) {
    if (key.includes('[REDACTED')) {
      changes.push(`SECRET_KEY_ADDED: ${key}`);
    } else {
      changes.push(`CONFIG_KEY_ADDED: ${key}`);
    }
  }

  return changes;
}

// Helper method to analyze version changes
function analyzeVersionChange(oldVersion, newVersion) {
  // Remove common prefixes (^, ~, =, v)
  const clean = (v) => v.replace(/^[\^~=v]/, '');
  const oldParts = clean(oldVersion).split('.');
  const newParts = clean(newVersion).split('.');
  
  return {
    isMajor: oldParts[0] !== newParts[0],
    isMinor: oldParts[0] === newParts[0] && oldParts[1] !== newParts[1],
    isPatch: oldParts[0] === newParts[0] && oldParts[1] === newParts[1] && oldParts[2] !== newParts[2]
  };
}

// Helper method for version comparison
function compareVersions(v1, v2) {
  const parts1 = v1.split('.').map(Number);
  const parts2 = v2.split('.').map(Number);
  
  for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
    const part1 = parts1[i] || 0;
    const part2 = parts2[i] || 0;
    if (part1 < part2) return -1;
    if (part1 > part2) return 1;
  }
  return 0;
}

// Basic security vulnerability check - NOT comprehensive
function isKnownVulnerablePackage(packageName, version) {
  // IMPORTANT: This is a basic check for demonstration purposes only.
  // For comprehensive security scanning, users should integrate:
  // - npm audit (run in CI/CD pipeline)
  // - GitHub Dependabot
  // - Dedicated security tools (Snyk, WhiteSource, etc.)
  
  core.info(`Security check: ${packageName}@${version} (basic check only)`);
  
  // Known critical vulnerabilities (manually maintained)
  // This list represents only a small sample of known issues
  const criticalVulnerabilities = {
    'event-stream': { 
      reason: 'Malicious code injection - cryptocurrency theft (2018)', 
      allVersions: true,
      cve: 'npm-advisory-776'
    },
    'flatmap-stream': { 
      reason: 'Cryptocurrency mining malware', 
      allVersions: true,
      cve: 'npm-advisory-737'
    },
    'eslint-scope': { 
      reason: 'Account takeover vulnerability - malicious package published', 
      versions: ['3.7.2'],
      cve: 'npm-advisory-679'
    },
    'bootstrap': {
      reason: 'XSS vulnerability in tooltip/popover',
      maxVersion: '3.4.0',
      cve: 'CVE-2018-14041'
    },
    'lodash': {
      reason: 'Prototype pollution vulnerability',
      maxVersion: '4.17.11',
      cve: 'CVE-2019-10744'
    }
  };
  
  const vuln = criticalVulnerabilities[packageName];
  if (!vuln) return false;
  
  // Check version constraints
  if (vuln.allVersions) {
    core.warning(`KNOWN VULNERABILITY: ${packageName} - ${vuln.reason} (${vuln.cve})`);
    return true;
  }
  
  if (vuln.versions && vuln.versions.includes(version)) {
    core.warning(`KNOWN VULNERABILITY: ${packageName}@${version} - ${vuln.reason} (${vuln.cve})`);
    return true;
  }
  
  if (vuln.maxVersion) {
    // Simple version comparison
    const cleanVersion = version.replace(/^[\^~=v]/, '');
    if (compareVersions(cleanVersion, vuln.maxVersion) <= 0) {
      core.warning(`KNOWN VULNERABILITY: ${packageName}@${version} - ${vuln.reason} (${vuln.cve})`);
      return true;
    }
  }
  
  return false;
}

module.exports = {
  sensitivePatterns,
  extractKeysOnly,
  compareKeys,
  analyzeVersionChange,
  compareVersions,
  isKnownVulnerablePackage
};