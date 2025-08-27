// YAML and configuration analysis
const core = require('@actions/core');
const yaml = require('yaml');
const riskScorer = require('../../risk-scorer');
const { globToRegex } = require('../../comment-generator');
const { extractKeysOnly, compareKeys, analyzeVersionChange, isKnownVulnerablePackage } = require('./utils');

async function analyzeYamlConfigs(files, octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, configYamlGlob) {
  const results = [];
  
  // Convert glob to regex using shared utility
  const configPattern = globToRegex(configYamlGlob);
  const configFiles = files.filter(file => configPattern.test(file.filename));

  for (const file of configFiles) {
    try {
      core.info(`Analyzing config file: ${file.filename}`);
      
      // Fetch head version
      const { data: headData } = await octokit.rest.repos.getContent({
        owner,
        repo,
        path: file.filename,
        ref: pullRequestHeadSha
      });
      
      const headContent = Buffer.from(headData.content, 'base64').toString();
      const headConfig = yaml.parse(headContent);
      const headKeys = extractKeysOnly(headConfig);
      
      // Try to fetch base version
      let baseKeys = [];
      try {
        const { data: baseData } = await octokit.rest.repos.getContent({
          owner,
          repo,
          path: file.filename,
          ref: pullRequestBaseSha  // Base branch commit
        });
        
        const baseContent = Buffer.from(baseData.content, 'base64').toString();
        const baseConfig = yaml.parse(baseContent);
        baseKeys = extractKeysOnly(baseConfig);
      } catch (e) {
        // File might be new
        core.info(`No base version found for ${file.filename}`);
      }
      
      const changes = compareKeys(baseKeys, headKeys);
      
      if (changes.length > 0) {
        const scoringResult = riskScorer.scoreChanges(changes, 'CONFIGURATION');
        
        results.push({
          type: 'configuration',
          file: file.filename,
          severity: scoringResult.severity,
          changes: changes,
          reasoning: scoringResult.reasoning,
          keyCount: { base: baseKeys.length, head: headKeys.length }
        });
      }
    } catch (error) {
      core.warning(`Config analysis failed for ${file.filename}: ${error.message}`);
    }
  }
  
  return results;
}

async function analyzeFeatureFlags(octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, featureFlagsPath) {
  try {
    core.info(`Analyzing feature flags at: ${featureFlagsPath}`);
    
    // Fetch current version
    const { data: headData } = await octokit.rest.repos.getContent({
      owner,
      repo,
      path: featureFlagsPath,
      ref: pullRequestHeadSha
    });
    
    const headContent = Buffer.from(headData.content, 'base64').toString();
    const headFlags = headContent.endsWith('.json') 
      ? JSON.parse(headContent)
      : yaml.parse(headContent);
    
    const headKeys = extractKeysOnly(headFlags);
    
    // Fetch base version
    let baseKeys = [];
    try {
      const { data: baseData } = await octokit.rest.repos.getContent({
        owner,
        repo,
        path: featureFlagsPath,
        ref: pullRequestBaseSha
      });
      
      const baseContent = Buffer.from(baseData.content, 'base64').toString();
      const baseFlags = baseContent.endsWith('.json')
        ? JSON.parse(baseContent)
        : yaml.parse(baseContent);
      
      baseKeys = extractKeysOnly(baseFlags);
    } catch (e) {
      core.info(`No base version found for feature flags`);
    }
    
    const changes = compareKeys(baseKeys, headKeys);
    
    // Mark all feature flag changes
    const flagChanges = changes.map(c => 
      c.replace('CONFIG_KEY_', 'FEATURE_FLAG_')
    );
    
    if (flagChanges.length > 0) {
      const scoringResult = riskScorer.scoreChanges(flagChanges, 'FEATURE_FLAGS');
      
      return {
        type: 'configuration',
        file: featureFlagsPath,
        severity: scoringResult.severity,
        changes: flagChanges,
        reasoning: scoringResult.reasoning,
        keyCount: { base: baseKeys.length, head: headKeys.length }
      };
    }
  } catch (error) {
    core.warning(`Feature flags analysis failed: ${error.message}`);
  }
  
  return null;
}

async function analyzePackageJson(octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, packagePath) {
  try {
    core.info(`Analyzing package.json: ${packagePath}`);
    
    // Fetch current version
    const { data: headData } = await octokit.rest.repos.getContent({
      owner,
      repo,
      path: packagePath,
      ref: pullRequestHeadSha
    });
    
    const headContent = Buffer.from(headData.content, 'base64').toString();
    const headPackage = JSON.parse(headContent);
    
    // Fetch base version
    let basePackage = null;
    try {
      const { data: baseData } = await octokit.rest.repos.getContent({
        owner,
        repo,
        path: packagePath,
        ref: pullRequestBaseSha
      });
      
      const baseContent = Buffer.from(baseData.content, 'base64').toString();
      basePackage = JSON.parse(baseContent);
    } catch (e) {
      core.info(`No base version found for package.json`);
    }
    
    const changes = [];
    
    // Check for added/removed dependencies
    const baseDeps = basePackage ? {
      ...basePackage.dependencies,
      ...basePackage.devDependencies
    } : {};
    
    const headDeps = {
      ...headPackage.dependencies,
      ...headPackage.devDependencies
    };
    
    // Check for removed dependencies
    for (const [name, version] of Object.entries(baseDeps)) {
      if (!headDeps[name]) {
        changes.push(`DEPENDENCY_REMOVED: ${name}`);
      }
    }
    
    // Check for added dependencies and version changes
    for (const [name, version] of Object.entries(headDeps)) {
      if (!baseDeps[name]) {
        changes.push(`DEPENDENCY_ADDED: ${name}`);
        // Check if it's a known vulnerable package
        if (isKnownVulnerablePackage(name, version)) {
          changes.push(`SECURITY_VULNERABILITY: ${name}`);
          changes.push(`SECURITY_RECOMMENDATION: Run 'npm audit' for comprehensive vulnerability scanning`);
        }
      } else if (baseDeps[name] !== version) {
        // Analyze version change
        const versionChange = analyzeVersionChange(baseDeps[name], version);
        if (versionChange.isMajor) {
          changes.push(`MAJOR_VERSION_BUMP: ${name}`);
        } else if (versionChange.isMinor) {
          changes.push(`MINOR_VERSION_BUMP: ${name}`);
        } else {
          changes.push(`PATCH_VERSION_UPDATE: ${name}`);
        }
      }
    }
    
    // Check for license changes (if license field exists)
    if (basePackage && basePackage.license !== headPackage.license) {
      changes.push(`LICENSE_CHANGE: ${basePackage.license || 'none'} -> ${headPackage.license || 'none'}`);
    }
    
    if (changes.length > 0) {
      const scoringResult = riskScorer.scoreChanges(changes, 'PACKAGE_JSON');
      
      return {
        type: 'configuration',
        file: packagePath,
        severity: scoringResult.severity,
        changes: changes,
        reasoning: scoringResult.reasoning
      };
    }
  } catch (error) {
    core.warning(`package.json analysis failed: ${error.message}`);
  }
  
  return null;
}

module.exports = {
  analyzeYamlConfigs,
  analyzeFeatureFlags,
  analyzePackageJson
};