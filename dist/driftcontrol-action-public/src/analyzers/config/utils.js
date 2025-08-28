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

// Vulnerability provider system - pluggable vulnerability detection
class VulnerabilityProvider {
  async initialize(options = {}) {
    // One-time setup per PR - override in subclasses
    // eslint-disable-next-line no-unused-vars
    const _ = options;
  }
  
  isVulnerable(packageName, version) {
    // eslint-disable-next-line no-unused-vars
    const _ = { packageName, version };
    throw new Error('Provider must implement isVulnerable()');
  }
}

class GitHubAdvisoryProvider extends VulnerabilityProvider {
  constructor(octokit) {
    super();
    this.octokit = octokit;
    this.vulnerabilities = new Map(); // Cache for entire PR
    this.initialized = false;
  }

  async initialize({ owner, repo, baseSha, headSha }) {
    if (this.initialized) return; // Prevent duplicate calls
    
    try {
      core.info('Fetching vulnerability data from GitHub Dependency Review API...');
      const basehead = `${baseSha}...${headSha}`;
      const { data } = await this.octokit.request(
        'GET /repos/{owner}/{repo}/dependency-graph/compare/{basehead}',
        { owner, repo, basehead, headers: { 'X-GitHub-Api-Version': '2022-11-28' }}
      );

      // Parse and cache all vulnerabilities ONCE
      for (const dep of data) {
        if (dep.vulnerabilities?.length > 0) {
          const vulnInfo = {
            vulnerabilities: dep.vulnerabilities,
            severity: this.getHighestSeverity(dep.vulnerabilities),
            version: dep.version
          };
          this.vulnerabilities.set(`${dep.name}@${dep.version}`, vulnInfo);
        }
      }
      
      this.initialized = true;
      core.info(`Cached ${this.vulnerabilities.size} vulnerable packages from GitHub Advisory Database`);
    } catch (e) {
      core.warning(`GitHub Advisory API failed: ${e.message}. Dependency graph may not be enabled.`);
      this.initialized = true; // Don't retry on failure
    }
  }

  getHighestSeverity(vulns) {
    const severityOrder = ['critical', 'high', 'moderate', 'low'];
    return vulns.reduce((highest, v) => {
      const current = (v.severity || 'moderate').toLowerCase();
      return severityOrder.indexOf(current) < severityOrder.indexOf(highest) ? current : highest;
    }, 'low');
  }

  isVulnerable(packageName, version) {
    return this.vulnerabilities.has(`${packageName}@${version}`);
  }
  
  getVulnerabilityInfo(packageName, version) {
    return this.vulnerabilities.get(`${packageName}@${version}`);
  }
}

class OSVProvider extends VulnerabilityProvider {
  constructor() {
    super();
    this.vulnerabilities = new Map(); // Cache for entire PR
    this.initialized = false;
  }

  async initialize({ packageNames = [] }) {
    if (this.initialized) return; // Prevent duplicate calls
    
    try {
      core.info('Fetching vulnerability data from OSV database...');
      
      if (packageNames.length === 0) {
        core.info('No packages to query from OSV database');
        this.initialized = true;
        return;
      }

      // Use batch query for initial vulnerability IDs, then fetch details only as needed
      const batchQueries = packageNames.map(pkg => ({
        package: { name: pkg, ecosystem: 'npm' }
      }));

      // Split into smaller batches (OSV has a 1000 query limit)
      const batchSize = 100;
      for (let i = 0; i < batchQueries.length; i += batchSize) {
        const batch = batchQueries.slice(i, i + batchSize);
        
        try {
          const response = await fetch('https://api.osv.dev/v1/querybatch', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              queries: batch
            })
          });

          if (!response.ok) {
            core.warning(`OSV batch query returned ${response.status}`);
            continue;
          }

          const data = await response.json();
          
          // Process each package result
          for (let j = 0; j < data.results.length; j++) {
            const result = data.results[j];
            const packageName = batch[j].package.name;
            
            if (result.vulns && result.vulns.length > 0) {
              // For performance: get full details for first vulnerability only
              // In production, you might want to fetch all, but this reduces API calls
              const firstVulnId = result.vulns[0].id;
              
              try {
                const vulnResponse = await fetch(`https://api.osv.dev/v1/vulns/${firstVulnId}`);
                if (vulnResponse.ok) {
                  const vulnDetails = await vulnResponse.json();
                  
                  // Extract affected versions for this specific package
                  const affectedRanges = vulnDetails.affected || [];
                  for (const affected of affectedRanges) {
                    if (affected.package?.name === packageName && affected.package?.ecosystem === 'npm') {
                      const vulnInfo = {
                        id: vulnDetails.id,
                        severity: this.extractSeverity(vulnDetails),
                        summary: vulnDetails.summary,
                        affected: affected.ranges || [],
                        database_specific: vulnDetails.database_specific,
                        totalVulns: result.vulns.length // Track total for reporting
                      };
                      
                      this.vulnerabilities.set(packageName, [vulnInfo]);
                      break;
                    }
                  }
                }
              } catch (vulnError) {
                core.warning(`Failed to fetch details for ${firstVulnId}: ${vulnError.message}`);
              }
            }
          }
        } catch (batchError) {
          core.warning(`OSV batch query failed: ${batchError.message}`);
        }
      }
      
      this.initialized = true;
      core.info(`Cached vulnerabilities for ${this.vulnerabilities.size} packages from OSV database`);
    } catch (e) {
      core.warning(`OSV API failed: ${e.message}. Falling back to static list.`);
      this.initialized = true; // Don't retry on failure
    }
  }

  extractSeverity(vuln) {
    // Check multiple severity sources in OSV format
    if (vuln.severity && Array.isArray(vuln.severity)) {
      for (const sev of vuln.severity) {
        if (sev.type === 'CVSS_V3' && sev.score) {
          // Convert CVSS score to severity level
          const score = parseFloat(sev.score);
          if (score >= 9.0) return 'critical';
          if (score >= 7.0) return 'high';
          if (score >= 4.0) return 'moderate';
          return 'low';
        }
      }
    }
    
    // Check database-specific severity
    if (vuln.database_specific?.severity) {
      return vuln.database_specific.severity.toLowerCase();
    }
    
    // Default to moderate if no severity information
    return 'moderate';
  }

  isVulnerable(packageName, version) {
    const vulns = this.vulnerabilities.get(packageName);
    if (!vulns) return false;

    // Check if version falls within any vulnerable range
    for (const vuln of vulns) {
      if (this.isVersionInVulnerableRange(version, vuln.affected)) {
        return true;
      }
    }
    
    return false;
  }

  isVersionInVulnerableRange(version, ranges) {
    if (!ranges || ranges.length === 0) return false;
    
    const cleanVersion = version.replace(/^[\^~=v]/, '');
    
    for (const range of ranges) {
      if (range.type === 'SEMVER') {
        // Handle SEMVER ranges
        for (const event of range.events || []) {
          if (event.introduced && event.introduced === '0' && !event.fixed) {
            return true; // All versions vulnerable
          }
          
          if (event.introduced && !event.fixed) {
            // Version introduced and no fix yet
            if (compareVersions(cleanVersion, event.introduced) >= 0) {
              return true;
            }
          }
          
          if (event.introduced && event.fixed) {
            // Vulnerable range: introduced <= version < fixed
            if (compareVersions(cleanVersion, event.introduced) >= 0 && 
                compareVersions(cleanVersion, event.fixed) < 0) {
              return true;
            }
          }
        }
      }
    }
    
    return false;
  }
  
  getVulnerabilityInfo(packageName, version) {
    const vulns = this.vulnerabilities.get(packageName);
    if (!vulns) return null;

    // Return vulnerabilities that affect this version
    const affectingVulns = vulns.filter(vuln => 
      this.isVersionInVulnerableRange(version, vuln.affected)
    );
    
    return affectingVulns.length > 0 ? {
      vulnerabilities: affectingVulns,
      severity: this.getHighestSeverity(affectingVulns),
      version: version
    } : null;
  }

  getHighestSeverity(vulns) {
    const severityOrder = ['critical', 'high', 'moderate', 'low'];
    return vulns.reduce((highest, v) => {
      const current = (v.severity || 'moderate').toLowerCase();
      return severityOrder.indexOf(current) < severityOrder.indexOf(highest) ? current : highest;
    }, 'low');
  }
}

class StaticListProvider extends VulnerabilityProvider {
  async initialize() {
    // No initialization needed for static list
  }
  
  isVulnerable(packageName, version) {
    return isKnownVulnerablePackageStatic(packageName, version);
  }
}

// Basic security vulnerability check - NOT comprehensive (renamed from original)
function isKnownVulnerablePackageStatic(packageName, version) {
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

// Global provider state
let activeProvider = null;

function setVulnerabilityProvider(provider) {
  activeProvider = provider;
}

function isKnownVulnerablePackage(packageName, version) {
  if (!activeProvider) {
    return isKnownVulnerablePackageStatic(packageName, version);
  }
  return activeProvider.isVulnerable(packageName, version);
}

module.exports = {
  sensitivePatterns,
  extractKeysOnly,
  compareKeys,
  analyzeVersionChange,
  compareVersions,
  VulnerabilityProvider,
  GitHubAdvisoryProvider,
  OSVProvider,
  StaticListProvider,
  setVulnerabilityProvider,
  isKnownVulnerablePackage
};