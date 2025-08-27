// Main config analyzer orchestration
const core = require('@actions/core');
const yaml = require('yaml');
const riskScorer = require('../../risk-scorer');
const yamlAnalysis = require('./yaml');
const packageLockAnalysis = require('./package-lock');
const dockerComposeAnalysis = require('./docker-compose');
const { 
  extractKeysOnly, 
  compareKeys, 
  analyzeVersionChange, 
  compareVersions, 
  isKnownVulnerablePackage 
} = require('./utils');

class ConfigAnalyzer {
  constructor() {
    this.riskScorer = riskScorer;
    // Sensitive key patterns for redaction
    this.sensitivePatterns = /password|secret|token|key|credential|auth|api_key|private|pwd/i;
    
    // Expose utility methods for backward compatibility and testing
    this.extractKeysOnly = extractKeysOnly;
    this.compareKeys = compareKeys;
    this.analyzeVersionChange = analyzeVersionChange;
    this.compareVersions = compareVersions;
    this.isKnownVulnerablePackage = isKnownVulnerablePackage;
    
    // Expose analysis methods for testing
    this.analyzePackageJson = yamlAnalysis.analyzePackageJson;
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
      // Analyze YAML configuration files
      if (configYamlGlob) {
        const yamlResults = await yamlAnalysis.analyzeYamlConfigs(
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
        const ffResult = await yamlAnalysis.analyzeFeatureFlags(
          octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, featureFlagsPath
        );
        if (ffResult) {
          driftResults.push(ffResult);
          if (ffResult.severity === 'high') hasHighSeverity = true;
          if (ffResult.severity === 'medium') hasMediumSeverity = true;
        }
      }

      // Analyze package.json files
      const packageJsonFiles = files.filter(f => f.filename.endsWith('package.json') && f.filename !== 'package-lock.json');
      for (const file of packageJsonFiles) {
        const pkgResult = await yamlAnalysis.analyzePackageJson(
          octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, file.filename
        );
        if (pkgResult) {
          driftResults.push(pkgResult);
          if (pkgResult.severity === 'high') hasHighSeverity = true;
          if (pkgResult.severity === 'medium') hasMediumSeverity = true;
        }
      }

      // Analyze docker-compose files
      const dockerComposeFiles = files.filter(f => f.filename.includes('docker-compose'));
      for (const file of dockerComposeFiles) {
        const dockerResult = await dockerComposeAnalysis.analyzeDockerCompose(
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

  // Delegate package-lock analysis to specialized module
  async analyzePackageLock(octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, lockPath) {
    return packageLockAnalysis.analyzePackageLock(
      octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, lockPath
    );
  }
}

module.exports = ConfigAnalyzer;