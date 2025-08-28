// Package-lock analysis
const core = require('@actions/core');
const riskScorer = require('../../../risk-scorer');
const { analyzeVersionChange, isKnownVulnerablePackage } = require('../utils');

// Normalize lockfile data to consistent format regardless of version
function normalizeLockfileData(lockData) {
  const version = lockData.lockfileVersion || 1;
  const normalized = {
    version,
    dependencies: {}
  };
  
  if (version === 1) {
    // v1: Use dependencies directly (flat structure)
    normalized.dependencies = lockData.dependencies || {};
  } else if (version >= 2) {
    // v2/v3: Convert packages format to flat dependencies
    const packages = lockData.packages || {};
    for (const [path, info] of Object.entries(packages)) {
      // Skip root package entry (empty string key)
      if (path && path.startsWith('node_modules/')) {
        const name = path.replace('node_modules/', '');
        normalized.dependencies[name] = info;
      }
    }
    // v2 also has dependencies for backward compatibility - merge if present
    if (version === 2 && lockData.dependencies) {
      // Packages data takes precedence over legacy dependencies
      normalized.dependencies = { ...lockData.dependencies, ...normalized.dependencies };
    }
  }
  
  core.info(`Normalized lockfile v${version}: ${Object.keys(normalized.dependencies).length} dependencies`);
  return normalized;
}

// Analyze package-lock.json for transitive dependency changes
async function analyzePackageLock(octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, lockPath) {
  try {
    core.info(`Analyzing package-lock.json: ${lockPath}`);
    
    // Fetch current version
    const { data: headData } = await octokit.rest.repos.getContent({
      owner,
      repo,
      path: lockPath,
      ref: pullRequestHeadSha
    });
    
    const headContent = Buffer.from(headData.content, 'base64').toString();
    const headLock = JSON.parse(headContent);
    
    // Fetch base version
    let baseLock = null;
    try {
      const { data: baseData } = await octokit.rest.repos.getContent({
        owner,
        repo,
        path: lockPath,
        ref: pullRequestBaseSha
      });
      
      const baseContent = Buffer.from(baseData.content, 'base64').toString();
      baseLock = JSON.parse(baseContent);
    } catch (e) {
      core.info(`No base version found for package-lock.json`);
    }
    
    const changes = [];
    
    if (!baseLock) {
      changes.push('NEW_LOCK_FILE: package-lock.json created');
    } else {
      // Normalize both lockfiles to consistent format for reliable comparison
      const normalizedBase = normalizeLockfileData(baseLock);
      const normalizedHead = normalizeLockfileData(headLock);

      // Log version changes as potential compatibility issue
      if (normalizedBase.version !== normalizedHead.version) {
        core.warning(`Lockfile version changed from v${normalizedBase.version} to v${normalizedHead.version} - may indicate npm upgrade`);
        changes.push(`LOCKFILE_VERSION_CHANGE: v${normalizedBase.version} → v${normalizedHead.version}`);
      }

      const baseDependencies = normalizedBase.dependencies;
      const headDependencies = normalizedHead.dependencies;
      
      let transitiveChanges = 0;
      let vulnerablePackages = [];
      
      // Check for changed transitive dependencies
      for (const [name, info] of Object.entries(headDependencies)) {
        const baseDep = baseDependencies[name];
        if (!baseDep) {
          transitiveChanges++;
          // Check for vulnerabilities in new dependencies
          if (isKnownVulnerablePackage(name, info.version)) {
            vulnerablePackages.push(name);
          }
        } else if (baseDep.version !== info.version) {
          transitiveChanges++;
          const versionChange = analyzeVersionChange(baseDep.version, info.version);
          if (versionChange.isMajor) {
            changes.push(`TRANSITIVE_MAJOR_BUMP: ${name}`);
          }
        }
      }
      
      if (transitiveChanges > 0) {
        changes.push(`TRANSITIVE_DEPENDENCIES_CHANGED: ${transitiveChanges} packages`);
      }
      
      for (const vuln of vulnerablePackages) {
        changes.push(`SECURITY_VULNERABILITY: ${vuln} (transitive)`);
      }
      
      if (vulnerablePackages.length > 0) {
        changes.push(`SECURITY_RECOMMENDATION: Run 'npm audit fix' to resolve transitive vulnerabilities`);
      }
      
      // Check integrity changes (potential security issue)
      const integrityMismatches = [];
      for (const [name, info] of Object.entries(headDependencies)) {
        const baseDep = baseDependencies[name];
        if (baseDep && baseDep.integrity && info.integrity && baseDep.integrity !== info.integrity && baseDep.version === info.version) {
          integrityMismatches.push(name);
        }
      }
      
      if (integrityMismatches.length > 0) {
        changes.push(`INTEGRITY_MISMATCH: ${integrityMismatches.length} packages have different checksums`);
      }
    }
    
    if (changes.length > 0) {
      const scoringResult = riskScorer.scoreChanges(changes, 'PACKAGE_LOCK');
      
      return {
        type: 'configuration',
        file: lockPath,
        severity: scoringResult.severity,
        changes: changes,
        reasoning: scoringResult.reasoning
      };
    }
  } catch (error) {
    core.warning(`package-lock.json analysis failed: ${error.message}`);
  }
  
  return null;
}

module.exports = {
  analyzePackageLock
};