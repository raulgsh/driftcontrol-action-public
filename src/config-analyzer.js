const core = require('@actions/core');
const yaml = require('yaml');
const riskScorer = require('./risk-scorer');

class ConfigAnalyzer {
  constructor() {
    this.riskScorer = riskScorer;
    // Sensitive key patterns for redaction
    this.sensitivePatterns = /password|secret|token|key|credential|auth|api_key|private|pwd/i;
  }

  async analyzeConfigFiles(files, octokit, owner, repo, pullRequestHeadSha, configYamlGlob, featureFlagsPath) {
    const driftResults = [];
    let hasHighSeverity = false;
    let hasMediumSeverity = false;

    try {
      // Analyze general config YAML files
      if (configYamlGlob) {
        const yamlResults = await this.analyzeYamlConfigs(
          files, octokit, owner, repo, pullRequestHeadSha, configYamlGlob
        );
        for (const result of yamlResults) {
          driftResults.push(result);
          if (result.severity === 'high') hasHighSeverity = true;
          if (result.severity === 'medium') hasMediumSeverity = true;
        }
      }

      // Analyze feature flags file
      if (featureFlagsPath && files.some(f => f.filename === featureFlagsPath)) {
        const flagResult = await this.analyzeFeatureFlags(
          octokit, owner, repo, pullRequestHeadSha, featureFlagsPath
        );
        if (flagResult) {
          driftResults.push(flagResult);
          if (flagResult.severity === 'high') hasHighSeverity = true;
          if (flagResult.severity === 'medium') hasMediumSeverity = true;
        }
      }

      // Analyze package.json changes
      const packageJsonFiles = files.filter(f => f.filename.endsWith('package.json'));
      for (const file of packageJsonFiles) {
        const packageResult = await this.analyzePackageJson(
          octokit, owner, repo, pullRequestHeadSha, file.filename
        );
        if (packageResult) {
          driftResults.push(packageResult);
          if (packageResult.severity === 'high') hasHighSeverity = true;
          if (packageResult.severity === 'medium') hasMediumSeverity = true;
        }
      }

      // Analyze docker-compose files
      const dockerComposeFiles = files.filter(f => 
        f.filename.includes('docker-compose') && (f.filename.endsWith('.yml') || f.filename.endsWith('.yaml'))
      );
      for (const file of dockerComposeFiles) {
        const dockerResult = await this.analyzeDockerCompose(
          octokit, owner, repo, pullRequestHeadSha, file.filename
        );
        if (dockerResult) {
          driftResults.push(dockerResult);
          if (dockerResult.severity === 'high') hasHighSeverity = true;
          if (dockerResult.severity === 'medium') hasMediumSeverity = true;
        }
      }
    } catch (error) {
      core.warning(`Config analysis error: ${error.message}`);
    }

    return { driftResults, hasHighSeverity, hasMediumSeverity };
  }

  // Security-first: Extract keys only, never values
  extractKeysOnly(obj, path = '', depth = 0) {
    const keys = [];
    const maxDepth = 10; // Prevent infinite recursion

    if (depth > maxDepth) return keys;

    if (typeof obj === 'object' && obj !== null && !Array.isArray(obj)) {
      for (const key in obj) {
        // Redact sensitive key names
        const sanitizedKey = this.sensitivePatterns.test(key) 
          ? `[REDACTED_${key.substring(0, 3).toUpperCase()}]` 
          : key;
        
        const fullPath = path ? `${path}.${sanitizedKey}` : sanitizedKey;
        keys.push(fullPath);
        
        // Recursively extract nested keys
        if (typeof obj[key] === 'object' && obj[key] !== null) {
          keys.push(...this.extractKeysOnly(obj[key], fullPath, depth + 1));
        }
      }
    } else if (Array.isArray(obj)) {
      // For arrays, just note that it's an array without exposing values
      keys.push(`${path}[]`);
    }

    return keys;
  }

  // Compare key sets between base and head
  compareKeys(baseKeys, headKeys) {
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

  async analyzeYamlConfigs(files, octokit, owner, repo, pullRequestHeadSha, configYamlGlob) {
    const results = [];
    
    // Convert glob to regex (reuse pattern from sql-analyzer)
    let globRegexPattern;
    if (configYamlGlob.includes('**/')) {
      const parts = configYamlGlob.split('**/');
      const prefix = parts[0].replace(/\./g, '\\.');
      const suffix = parts[1]
        .replace(/\./g, '\\.')
        .replace(/\*/g, '[^/]*');
      globRegexPattern = `^${prefix}.*${suffix}$`;
    } else {
      globRegexPattern = configYamlGlob
        .replace(/\./g, '\\.')
        .replace(/\*\*/g, '.*')
        .replace(/\*/g, '[^/]*')
        + '$';
    }
    
    const configPattern = new RegExp(globRegexPattern);
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
        const headKeys = this.extractKeysOnly(headConfig);
        
        // Try to fetch base version
        let baseKeys = [];
        try {
          const { data: baseData } = await octokit.rest.repos.getContent({
            owner,
            repo,
            path: file.filename,
            ref: 'HEAD~1'  // Previous commit
          });
          
          const baseContent = Buffer.from(baseData.content, 'base64').toString();
          const baseConfig = yaml.parse(baseContent);
          baseKeys = this.extractKeysOnly(baseConfig);
        } catch (e) {
          // File might be new
          core.info(`No base version found for ${file.filename}`);
        }
        
        const changes = this.compareKeys(baseKeys, headKeys);
        
        if (changes.length > 0) {
          const scoringResult = this.riskScorer.scoreChanges(changes, 'CONFIGURATION');
          
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

  async analyzeFeatureFlags(octokit, owner, repo, pullRequestHeadSha, featureFlagsPath) {
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
      
      const headKeys = this.extractKeysOnly(headFlags);
      
      // Fetch base version
      let baseKeys = [];
      try {
        const { data: baseData } = await octokit.rest.repos.getContent({
          owner,
          repo,
          path: featureFlagsPath,
          ref: 'HEAD~1'
        });
        
        const baseContent = Buffer.from(baseData.content, 'base64').toString();
        const baseFlags = baseContent.endsWith('.json')
          ? JSON.parse(baseContent)
          : yaml.parse(baseContent);
        
        baseKeys = this.extractKeysOnly(baseFlags);
      } catch (e) {
        core.info(`No base version found for feature flags`);
      }
      
      const changes = this.compareKeys(baseKeys, headKeys);
      
      // Mark all feature flag changes
      const flagChanges = changes.map(c => 
        c.replace('CONFIG_KEY_', 'FEATURE_FLAG_')
      );
      
      if (flagChanges.length > 0) {
        const scoringResult = this.riskScorer.scoreChanges(flagChanges, 'FEATURE_FLAGS');
        
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

  async analyzePackageJson(octokit, owner, repo, pullRequestHeadSha, packagePath) {
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
      
      // Extract only dependency and script keys (not versions)
      const headKeys = [
        ...Object.keys(headPackage.dependencies || {}).map(k => `dependencies.${k}`),
        ...Object.keys(headPackage.devDependencies || {}).map(k => `devDependencies.${k}`),
        ...Object.keys(headPackage.scripts || {}).map(k => `scripts.${k}`)
      ];
      
      // Fetch base version
      let baseKeys = [];
      try {
        const { data: baseData } = await octokit.rest.repos.getContent({
          owner,
          repo,
          path: packagePath,
          ref: 'HEAD~1'
        });
        
        const baseContent = Buffer.from(baseData.content, 'base64').toString();
        const basePackage = JSON.parse(baseContent);
        
        baseKeys = [
          ...Object.keys(basePackage.dependencies || {}).map(k => `dependencies.${k}`),
          ...Object.keys(basePackage.devDependencies || {}).map(k => `devDependencies.${k}`),
          ...Object.keys(basePackage.scripts || {}).map(k => `scripts.${k}`)
        ];
      } catch (e) {
        core.info(`No base version found for package.json`);
      }
      
      const changes = [];
      const baseSet = new Set(baseKeys);
      const headSet = new Set(headKeys);
      
      const added = [...headSet].filter(k => !baseSet.has(k));
      const removed = [...baseSet].filter(k => !headSet.has(k));
      
      for (const key of removed) {
        changes.push(`DEPENDENCY_REMOVED: ${key}`);
      }
      
      for (const key of added) {
        changes.push(`DEPENDENCY_ADDED: ${key}`);
      }
      
      if (changes.length > 0) {
        const scoringResult = this.riskScorer.scoreChanges(changes, 'PACKAGE_JSON');
        
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

  async analyzeDockerCompose(octokit, owner, repo, pullRequestHeadSha, composePath) {
    try {
      core.info(`Analyzing docker-compose: ${composePath}`);
      
      // Fetch current version
      const { data: headData } = await octokit.rest.repos.getContent({
        owner,
        repo,
        path: composePath,
        ref: pullRequestHeadSha
      });
      
      const headContent = Buffer.from(headData.content, 'base64').toString();
      const headCompose = yaml.parse(headContent);
      
      // Extract service and volume keys only
      const headKeys = [
        ...Object.keys(headCompose.services || {}).map(k => `services.${k}`),
        ...Object.keys(headCompose.volumes || {}).map(k => `volumes.${k}`),
        ...Object.keys(headCompose.networks || {}).map(k => `networks.${k}`)
      ];
      
      // Fetch base version
      let baseKeys = [];
      try {
        const { data: baseData } = await octokit.rest.repos.getContent({
          owner,
          repo,
          path: composePath,
          ref: 'HEAD~1'
        });
        
        const baseContent = Buffer.from(baseData.content, 'base64').toString();
        const baseCompose = yaml.parse(baseContent);
        
        baseKeys = [
          ...Object.keys(baseCompose.services || {}).map(k => `services.${k}`),
          ...Object.keys(baseCompose.volumes || {}).map(k => `volumes.${k}`),
          ...Object.keys(baseCompose.networks || {}).map(k => `networks.${k}`)
        ];
      } catch (e) {
        core.info(`No base version found for docker-compose`);
      }
      
      const changes = [];
      const baseSet = new Set(baseKeys);
      const headSet = new Set(headKeys);
      
      const added = [...headSet].filter(k => !baseSet.has(k));
      const removed = [...baseSet].filter(k => !headSet.has(k));
      
      for (const key of removed) {
        changes.push(`CONTAINER_REMOVED: ${key}`);
      }
      
      for (const key of added) {
        changes.push(`CONTAINER_ADDED: ${key}`);
      }
      
      if (changes.length > 0) {
        const scoringResult = this.riskScorer.scoreChanges(changes, 'DOCKER_COMPOSE');
        
        return {
          type: 'configuration',
          file: composePath,
          severity: scoringResult.severity,
          changes: changes,
          reasoning: scoringResult.reasoning
        };
      }
    } catch (error) {
      core.warning(`docker-compose analysis failed: ${error.message}`);
    }
    
    return null;
  }
}

module.exports = ConfigAnalyzer;