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
  constructor(contentFetcher = null) {
    this.riskScorer = riskScorer;
    this.contentFetcher = contentFetcher;
    
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
    
    // Initialize vulnerability provider
    this.vulnerabilityProvider = null;
  }

  // Load complete DriftControl configuration from .github/driftcontrol.yml
  async loadDriftControlConfig(octokit, owner, repo, pullRequest, correlationConfigPath) {
    // Try multiple refs in order: PR head, PR base, default branch
    const tryRefs = [pullRequest.head.sha, pullRequest.base.sha, undefined];
    let configData = null;
    let loadedRef = null;
    
    for (const ref of tryRefs) {
      try {
        core.info(`Trying to load correlation config from: ${correlationConfigPath} at ${ref || 'default branch'}`);
        
        if (this.contentFetcher) {
          const result = await this.contentFetcher.fetchContentSafe(
            correlationConfigPath, ref, `correlation config at ${ref || 'default branch'}`
          );
          if (result) {
            configData = result.rawData;
            loadedRef = ref || 'default';
            break;
          }
        } else {
          // Legacy method for backward compatibility  
          const params = { owner, repo, path: correlationConfigPath };
          if (ref) params.ref = ref;
          
          const { data } = await octokit.rest.repos.getContent(params);
          configData = data;
          loadedRef = ref || 'default';
          break;
        }
      } catch (error) {
        if (error.status === 404) {
          continue; // Try next ref
        }
        throw error; // Propagate other errors
      }
    }
    
    if (!configData) {
      core.info(`No DriftControl config found at ${correlationConfigPath} in any branch - using defaults`);
      return {
        correlationRules: [],
        strategyConfig: {},
        thresholds: {},
        limits: {},
        analysis: {},
        risk: {},
        llm: {},
        vulnerability: {},
        configPath: correlationConfigPath,
        loaded: false
      };
    }
    
    try {
      core.info(`Successfully loaded config from ${loadedRef === 'default' ? 'default branch' : `ref ${loadedRef}`}`);
      
      // Handle large files - if content is missing, try download_url
      let configContent;
      if (this.contentFetcher && configData.content) {
        // ContentFetcher already provided the content as a string
        configContent = Buffer.from(configData.content, 'base64').toString();
      } else if (configData.content) {
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
      
      // Parse analysis configuration
      let analysis = {};
      if (config.analysis) {
        analysis = {
          openapi_path: config.analysis.openapi_path,
          sql_glob: config.analysis.sql_glob,
          terraform_plan_path: config.analysis.terraform_plan_path,
          cloudformation_glob: config.analysis.cloudformation_glob,
          config_yaml_glob: config.analysis.config_yaml_glob,
          feature_flags_path: config.analysis.feature_flags_path,
          kubernetes_glob: config.analysis.kubernetes_glob,
          env_files: config.analysis.env_files
        };
        core.info(`Loaded analysis configuration: ${Object.keys(analysis).length} settings`);
      }
      
      // Parse risk configuration
      let risk = {};
      if (config.risk) {
        risk = {
          fail_on_medium: config.risk.fail_on_medium,
          cost_threshold: config.risk.cost_threshold,
          override: config.risk.override
        };
        core.info(`Loaded risk configuration: ${Object.keys(risk).length} settings`);
      }
      
      // Parse LLM configuration
      let llm = {};
      if (config.llm) {
        llm = {
          provider: config.llm.provider,
          model: config.llm.model,
          max_tokens: config.llm.max_tokens
        };
        core.info(`Loaded LLM configuration: ${Object.keys(llm).length} settings`);
      }
      
      // Parse vulnerability configuration
      let vulnerability = {};
      if (config.vulnerability) {
        vulnerability = {
          provider: config.vulnerability.provider
        };
        core.info(`Loaded vulnerability configuration: ${Object.keys(vulnerability).length} settings`);
      }
      
      return {
        correlationRules,
        strategyConfig,
        thresholds,
        limits,
        analysis,
        risk,
        llm,
        vulnerability,
        configPath: correlationConfigPath,
        loaded: true
      };
      
    } catch (error) {
      // Config file is optional - not finding it is not an error
      if (error.status === 404) {
        core.info(`No correlation config found at ${correlationConfigPath} - using heuristic correlation only`);
      } else {
        core.warning(`Failed to load DriftControl config: ${error.message}`);
      }
      
      return {
        correlationRules: [],
        analysis: {},
        risk: {},
        llm: {},
        vulnerability: {},
        configPath: correlationConfigPath,
        loaded: false
      };
    }
  }

  async initializeVulnerabilityProvider(octokit, config = {}) {
    const { provider = 'static', owner, repo, baseSha, headSha, packageNames } = config;
    
    if (provider === 'osv') {
      const { OSVProvider, setVulnerabilityProvider } = require('./utils');
      this.vulnerabilityProvider = new OSVProvider();
      
      // Initialize with package names from PR context
      await this.vulnerabilityProvider.initialize({ packageNames: packageNames || [] });
      
      setVulnerabilityProvider(this.vulnerabilityProvider);
      core.info('Using OSV vulnerability database for comprehensive security scanning');
    } else if (provider === 'github' && octokit) {
      const { GitHubAdvisoryProvider, setVulnerabilityProvider } = require('./utils');
      this.vulnerabilityProvider = new GitHubAdvisoryProvider(octokit);
      
      // Critical: Initialize ONCE with PR context
      await this.vulnerabilityProvider.initialize({ owner, repo, baseSha, headSha });
      
      setVulnerabilityProvider(this.vulnerabilityProvider);
      core.info('Using GitHub Advisory Database for vulnerability detection');
    } else {
      const { StaticListProvider, setVulnerabilityProvider } = require('./utils');
      this.vulnerabilityProvider = new StaticListProvider();
      await this.vulnerabilityProvider.initialize();
      setVulnerabilityProvider(this.vulnerabilityProvider);
      core.info('Using static vulnerability list (fallback)');
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

      // Analyze .env files
      const envFiles = files.filter(f => f.filename.endsWith('.env'));
      for (const file of envFiles) {
        const envResult = await this.analyzeEnvFile(
          octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, file.filename
        );
        if (envResult) {
          driftResults.push(envResult);
          if (envResult.severity === 'high') hasHighSeverity = true;
          if (envResult.severity === 'medium') hasMediumSeverity = true;
        }
      }

      // Analyze .properties files
      const propertiesFiles = files.filter(f => f.filename.endsWith('.properties'));
      for (const file of propertiesFiles) {
        const propResult = await this.analyzePropertiesFile(
          octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, file.filename
        );
        if (propResult) {
          driftResults.push(propResult);
          if (propResult.severity === 'high') hasHighSeverity = true;
          if (propResult.severity === 'medium') hasMediumSeverity = true;
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

  async analyzeEnvFile(octokit, owner, repo, headSha, baseSha, filepath) {
    try {
      let headContent, baseContent;
      
      if (this.contentFetcher) {
        const results = await this.contentFetcher.batchFetch([
          { path: filepath, ref: headSha, description: `env file ${filepath} (head)` },
          { path: filepath, ref: baseSha, description: `env file ${filepath} (base)` }
        ]);
        
        headContent = results[0]?.content;
        baseContent = results[1]?.content;
      } else {
        // Legacy method for backward compatibility
        const { data: headData } = await octokit.rest.repos.getContent({
          owner, repo, path: filepath, ref: headSha
        });
        headContent = Buffer.from(headData.content, 'base64').toString();
        
        try {
          const { data: baseData } = await octokit.rest.repos.getContent({
            owner, repo, path: filepath, ref: baseSha
          });
          baseContent = Buffer.from(baseData.content, 'base64').toString();
        } catch (e) {
          // New file
        }
      }
      
      if (!headContent) {
        core.warning(`No content found for env file: ${filepath}`);
        return null;
      }
      
      const headVars = this.parseEnvFile(headContent);
      const baseVars = baseContent ? this.parseEnvFile(baseContent) : {};
      
      const changes = [];
      const headKeys = Object.keys(headVars);
      const baseKeys = Object.keys(baseVars);
      
      // Check for sensitive keys being added/removed
      headKeys.filter(k => !baseKeys.includes(k)).forEach(k => {
        if (this.sensitivePatterns.test(k)) {
          changes.push(`ENV_SECRET_ADDED: ${k}`);
        } else {
          changes.push(`ENV_VAR_ADDED: ${k}`);
        }
      });
      
      baseKeys.filter(k => !headKeys.includes(k)).forEach(k => {
        if (this.sensitivePatterns.test(k)) {
          changes.push(`ENV_SECRET_REMOVED: ${k}`);
        }
      });
      
      if (changes.length > 0) {
        const scoringResult = this.riskScorer.scoreChanges(changes, 'ENV_FILE');
        return {
          type: 'configuration',
          file: filepath,
          severity: scoringResult.severity,
          changes: changes,
          reasoning: scoringResult.reasoning
        };
      }
    } catch (e) {
      core.warning(`Env file analysis failed: ${e.message}`);
    }
    return null;
  }

  parseEnvFile(content) {
    const vars = {};
    content.split('\n').forEach(line => {
      if (line && !line.startsWith('#')) {
        const [key] = line.split('=');
        if (key) vars[key.trim()] = true; // Only track keys, not values
      }
    });
    return vars;
  }

  async analyzePropertiesFile(octokit, owner, repo, headSha, baseSha, filepath) {
    try {
      let headContent, baseContent;
      
      if (this.contentFetcher) {
        const results = await this.contentFetcher.batchFetch([
          { path: filepath, ref: headSha, description: `properties file ${filepath} (head)` },
          { path: filepath, ref: baseSha, description: `properties file ${filepath} (base)` }
        ]);
        
        headContent = results[0]?.content;
        baseContent = results[1]?.content;
      } else {
        // Legacy method for backward compatibility
        const { data: headData } = await octokit.rest.repos.getContent({
          owner, repo, path: filepath, ref: headSha
        });
        headContent = Buffer.from(headData.content, 'base64').toString();
        
        try {
          const { data: baseData } = await octokit.rest.repos.getContent({
            owner, repo, path: filepath, ref: baseSha
          });
          baseContent = Buffer.from(baseData.content, 'base64').toString();
        } catch (e) {
          // New file
        }
      }
      
      if (!headContent) {
        core.warning(`No content found for properties file: ${filepath}`);
        return null;
      }
      
      const headProps = this.parsePropertiesFile(headContent);
      const baseProps = baseContent ? this.parsePropertiesFile(baseContent) : {};
      
      const changes = [];
      const headKeys = Object.keys(headProps);
      const baseKeys = Object.keys(baseProps);
      
      // Check for sensitive properties being added/removed
      headKeys.filter(k => !baseKeys.includes(k)).forEach(k => {
        if (this.sensitivePatterns.test(k)) {
          changes.push(`PROPERTIES_SECRET_ADDED: ${k}`);
        } else {
          changes.push(`PROPERTIES_KEY_ADDED: ${k}`);
        }
      });
      
      baseKeys.filter(k => !headKeys.includes(k)).forEach(k => {
        if (this.sensitivePatterns.test(k)) {
          changes.push(`PROPERTIES_SECRET_REMOVED: ${k}`);
        }
      });
      
      if (changes.length > 0) {
        const scoringResult = this.riskScorer.scoreChanges(changes, 'PROPERTIES_FILE');
        return {
          type: 'configuration',
          file: filepath,
          severity: scoringResult.severity,
          changes: changes,
          reasoning: scoringResult.reasoning
        };
      }
    } catch (e) {
      core.warning(`Properties file analysis failed: ${e.message}`);
    }
    return null;
  }

  parsePropertiesFile(content) {
    const props = {};
    content.split('\n').forEach(line => {
      const trimmed = line.trim();
      // Skip comments and empty lines
      if (trimmed && !trimmed.startsWith('#') && !trimmed.startsWith('!')) {
        // Handle both = and : separators, and line continuations
        const match = trimmed.match(/^([^=:\s]+)\s*[=:]\s*/);
        if (match) {
          props[match[1]] = true; // Only track keys, not values
        }
      }
    });
    return props;
  }

  // Backward compatibility method - delegates to loadDriftControlConfig
  async loadCorrelationConfig(octokit, owner, repo, pullRequest, correlationConfigPath) {
    const config = await this.loadDriftControlConfig(octokit, owner, repo, pullRequest, correlationConfigPath);
    // Return only correlation-related properties for backward compatibility
    return {
      correlationRules: config.correlationRules,
      strategyConfig: config.strategyConfig,
      thresholds: config.thresholds,
      limits: config.limits,
      configPath: config.configPath,
      loaded: config.loaded
    };
  }

  async initializeVulnerabilityProvider(octokit, config = {}) {
    const { provider = 'static', owner, repo, baseSha, headSha, packageNames } = config;
    
    if (provider === 'osv') {
      const { OSVProvider, setVulnerabilityProvider } = require('./utils');
      this.vulnerabilityProvider = new OSVProvider();
      
      // Initialize with package names from PR context
      await this.vulnerabilityProvider.initialize({ packageNames: packageNames || [] });
      
      setVulnerabilityProvider(this.vulnerabilityProvider);
      core.info('Using OSV vulnerability database for comprehensive security scanning');
    } else if (provider === 'github' && octokit) {
      const { GitHubAdvisoryProvider, setVulnerabilityProvider } = require('./utils');
      this.vulnerabilityProvider = new GitHubAdvisoryProvider(octokit);
      
      // Critical: Initialize ONCE with PR context
      await this.vulnerabilityProvider.initialize({ owner, repo, baseSha, headSha });
      
      setVulnerabilityProvider(this.vulnerabilityProvider);
      core.info('Using GitHub Advisory Database for vulnerability detection');
    } else {
      const { StaticListProvider, setVulnerabilityProvider } = require('./utils');
      this.vulnerabilityProvider = new StaticListProvider();
      await this.vulnerabilityProvider.initialize();
      setVulnerabilityProvider(this.vulnerabilityProvider);
      core.info('Using static vulnerability list (fallback)');
    }
  }
}

module.exports = ConfigAnalyzer;