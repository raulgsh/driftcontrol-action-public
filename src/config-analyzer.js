const core = require('@actions/core');
const yaml = require('yaml');
const riskScorer = require('./risk-scorer');
const { globToRegex } = require('./comment-generator');

class ConfigAnalyzer {
  constructor() {
    this.riskScorer = riskScorer;
    // Sensitive key patterns for redaction
    this.sensitivePatterns = /password|secret|token|key|credential|auth|api_key|private|pwd/i;
  }

  // Load user-defined correlation configuration from .github/driftcontrol.yml
  async loadCorrelationConfig(octokit, owner, repo, pullRequest, correlationConfigPath) {
    // Try multiple refs in order: PR head, PR base, default branch
    const tryRefs = [pullRequest.head.sha, pullRequest.base.sha, undefined];
    let configData = null;
    let loadedRef = null;
    
    for (const ref of tryRefs) {
      try {
        const params = { owner, repo, path: correlationConfigPath };
        if (ref) params.ref = ref;
        
        core.info(`Trying to load correlation config from: ${correlationConfigPath} at ${ref || 'default branch'}`);
        const { data } = await octokit.rest.repos.getContent(params);
        configData = data;
        loadedRef = ref || 'default';
        break;
      } catch (error) {
        if (error.status === 404) {
          continue; // Try next ref
        }
        throw error; // Propagate other errors
      }
    }
    
    if (!configData) {
      core.info(`No correlation config found at ${correlationConfigPath} in any branch - using heuristic correlation only`);
      return {
        correlationRules: [],
        strategyConfig: {},
        thresholds: {},
        limits: {},
        configPath: correlationConfigPath,
        loaded: false
      };
    }
    
    try {
      core.info(`Successfully loaded config from ${loadedRef === 'default' ? 'default branch' : `ref ${loadedRef}`}`);
      
      // Handle large files - if content is missing, try download_url
      let configContent;
      if (configData.content) {
        configContent = Buffer.from(configData.content, 'base64').toString();
      } else if (configData.download_url) {
        core.info('Config file is large, fetching via download URL');
        const response = await fetch(configData.download_url);
        configContent = await response.text();
      } else {
        throw new Error('Unable to fetch config content');
      }
      
      // Parse YAML with error handling
      let config;
      try {
        config = yaml.parse(configContent);
      } catch (yamlError) {
        core.warning(`Invalid YAML in correlation config: ${yamlError.message}`);
        return {
          correlationRules: [],
          configPath: correlationConfigPath,
          loaded: false,
          error: `Invalid YAML: ${yamlError.message}`
        };
      }
      
      // Validate and normalize correlation rules
      const correlationRules = [];
      
      if (config.correlation_rules && Array.isArray(config.correlation_rules)) {
        for (const rule of config.correlation_rules) {
          // Validate rule structure
          if (!rule.type) {
            core.warning(`Correlation rule missing type: ${JSON.stringify(rule)}`);
            continue;
          }
          
          // Normalize rule with confidence 1.0 for user-defined rules
          const normalizedRule = {
            ...rule,
            confidence: 1.0, // User-defined rules have maximum confidence
            userDefined: true
          };
          
          // Handle different rule formats
          if (rule.type === 'api_to_db') {
            // Support both simple and method-aware API rules
            if (rule.api && typeof rule.api === 'object') {
              // Method-aware format: { method: 'GET', route: '/v1/users' }
              normalizedRule.source = `${rule.api.method || 'ANY'}:${rule.api.route}`;
              normalizedRule.apiMethod = rule.api.method;
              normalizedRule.apiRoute = rule.api.route;
            } else {
              // Simple format: api_endpoint: '/v1/users'
              normalizedRule.source = rule.api_endpoint || rule.source;
              normalizedRule.apiRoute = rule.api_endpoint;
            }
            normalizedRule.target = rule.db_table || rule.target;
          } else if (rule.type === 'iac_to_config') {
            normalizedRule.source = rule.iac_resource_id || rule.source;
            normalizedRule.target = rule.config_file || rule.target;
          } else {
            // Generic rule types (including 'ignore')
            normalizedRule.source = rule.source;
            normalizedRule.target = rule.target;
          }
          
          correlationRules.push(normalizedRule);
          core.info(`Loaded ${rule.type} correlation rule: ${normalizedRule.source} -> ${normalizedRule.target}`);
        }
      }
      
      core.info(`Successfully loaded ${correlationRules.length} correlation rules from config`);
      
      // Parse strategy configuration
      let strategyConfig = {};
      if (config.strategy_weights) {
        Object.entries(config.strategy_weights).forEach(([name, value]) => {
          if (typeof value === 'object') {
            strategyConfig[name] = {
              weight: Math.max(0, Math.min(1, value.weight || 1.0)), // Clamp to [0,1]
              enabled: value.enabled !== false,
              budget: value.budget || 'low'
            };
          } else {
            // Simple numeric weight for backward compatibility
            strategyConfig[name] = {
              weight: Math.max(0, Math.min(1, value)),
              enabled: true,
              budget: 'low'
            };
          }
        });
        core.info(`Loaded strategy weights: ${JSON.stringify(strategyConfig)}`);
      }
      
      // Parse thresholds with clamping
      let thresholds = {};
      if (config.thresholds) {
        const correlateMin = Math.max(0, Math.min(1, config.thresholds.correlate_min || 0.55));
        const blockMin = Math.max(0, Math.min(1, config.thresholds.block_min || 0.80));
        
        // Sanity check: correlate_min should be <= block_min
        if (correlateMin > blockMin) {
          core.warning(`Invalid thresholds: correlate_min (${correlateMin}) > block_min (${blockMin}). Using defaults.`);
          thresholds = { correlate_min: 0.55, block_min: 0.80 };
        } else {
          thresholds = { correlate_min: correlateMin, block_min: blockMin };
        }
        core.info(`Loaded thresholds: ${JSON.stringify(thresholds)}`);
      }
      
      // Parse limits
      let limits = {};
      if (config.limits) {
        limits = {
          top_k_per_source: Math.max(1, config.limits.top_k_per_source || 3),
          max_pairs_high_cost: Math.max(1, config.limits.max_pairs_high_cost || 100)
        };
        core.info(`Loaded limits: ${JSON.stringify(limits)}`);
      }
      
      return {
        correlationRules,
        strategyConfig,
        thresholds,
        limits,
        configPath: correlationConfigPath,
        loaded: true
      };
      
    } catch (error) {
      // Config file is optional - not finding it is not an error
      if (error.status === 404) {
        core.info(`No correlation config found at ${correlationConfigPath} - using heuristic correlation only`);
      } else {
        core.warning(`Failed to load correlation config: ${error.message}`);
      }
      
      return {
        correlationRules: [],
        configPath: correlationConfigPath,
        loaded: false
      };
    }
  }

  async analyzeConfigFiles(files, octokit, owner, repo, pullRequest, configYamlGlob, featureFlagsPath) {
    const pullRequestHeadSha = pullRequest.head.sha;
    const pullRequestBaseSha = pullRequest.base.sha;
    const driftResults = [];
    let hasHighSeverity = false;
    let hasMediumSeverity = false;

    try {
      // Analyze general config YAML files
      if (configYamlGlob) {
        const yamlResults = await this.analyzeYamlConfigs(
          files, octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, configYamlGlob
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
          octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, featureFlagsPath
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
          octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, file.filename
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
          octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, file.filename
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

  async analyzeYamlConfigs(files, octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, configYamlGlob) {
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
        const headKeys = this.extractKeysOnly(headConfig);
        
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

  async analyzeFeatureFlags(octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, featureFlagsPath) {
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
          ref: pullRequestBaseSha
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

  async analyzePackageJson(octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, packagePath) {
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
          if (this.isKnownVulnerablePackage(name, version)) {
            changes.push(`SECURITY_VULNERABILITY: ${name}`);
            changes.push(`SECURITY_RECOMMENDATION: Run 'npm audit' for comprehensive vulnerability scanning`);
          }
        } else if (baseDeps[name] !== version) {
          // Analyze version change
          const versionChange = this.analyzeVersionChange(baseDeps[name], version);
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

  // Helper method to analyze version changes
  analyzeVersionChange(oldVersion, newVersion) {
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
  
  // Basic security vulnerability check - NOT comprehensive
  isKnownVulnerablePackage(packageName, version) {
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
      if (this.compareVersions(cleanVersion, vuln.maxVersion) <= 0) {
        core.warning(`KNOWN VULNERABILITY: ${packageName}@${version} - ${vuln.reason} (${vuln.cve})`);
        return true;
      }
    }
    
    return false;
  }
  
  // Helper method for version comparison
  compareVersions(v1, v2) {
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
  
  // Analyze package-lock.json for transitive dependency changes
  async analyzePackageLock(octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, lockPath) {
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
        // Compare lock file versions
        const baseDependencies = baseLock.dependencies || baseLock.packages || {};
        const headDependencies = headLock.dependencies || headLock.packages || {};
        
        let transitiveChanges = 0;
        let vulnerablePackages = [];
        
        // Check for changed transitive dependencies
        for (const [name, info] of Object.entries(headDependencies)) {
          const baseDep = baseDependencies[name];
          if (!baseDep) {
            transitiveChanges++;
            // Check for vulnerabilities in new dependencies
            if (this.isKnownVulnerablePackage(name, info.version)) {
              vulnerablePackages.push(name);
            }
          } else if (baseDep.version !== info.version) {
            transitiveChanges++;
            const versionChange = this.analyzeVersionChange(baseDep.version, info.version);
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
        const scoringResult = this.riskScorer.scoreChanges(changes, 'PACKAGE_LOCK');
        
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
  
  async analyzeDockerCompose(octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, composePath) {
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
          ref: pullRequestBaseSha
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