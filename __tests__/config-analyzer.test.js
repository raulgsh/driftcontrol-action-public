const ConfigAnalyzer = require('../src/config-analyzer');
const core = require('@actions/core');

// Mock @actions/core
jest.mock('@actions/core', () => ({
  info: jest.fn(),
  warning: jest.fn(),
  error: jest.fn(),
  setFailed: jest.fn()
}));

describe('Config Analyzer', () => {
  let analyzer;
  let mockOctokit;
  
  beforeEach(() => {
    analyzer = new ConfigAnalyzer();
    jest.clearAllMocks();
    
    // Mock octokit
    mockOctokit = {
      rest: {
        repos: {
          getContent: jest.fn()
        }
      }
    };
  });

  describe('Security Features', () => {
    it('should redact sensitive key names', () => {
      const config = {
        database: {
          host: 'localhost',
          password: 'secret123',
          api_key: 'key123',
          token: 'token123'
        }
      };
      
      const keys = analyzer.extractKeysOnly(config);
      
      expect(keys).toContain('database.host');
      expect(keys).toContain('database.[REDACTED_PAS]');
      expect(keys).toContain('database.[REDACTED_API]');
      expect(keys).toContain('database.[REDACTED_TOK]');
      expect(keys).not.toContain('database.password');
      expect(keys).not.toContain('secret123');
    });

    it('should extract keys only without values', () => {
      const config = {
        app: {
          name: 'MyApp',
          version: '1.0.0',
          settings: {
            debug: true,
            port: 3000
          }
        }
      };
      
      const keys = analyzer.extractKeysOnly(config);
      
      expect(keys).toContain('app');
      expect(keys).toContain('app.name');
      expect(keys).toContain('app.version');
      expect(keys).toContain('app.settings');
      expect(keys).toContain('app.settings.debug');
      expect(keys).toContain('app.settings.port');
      
      // Should not contain any values
      expect(keys).not.toContain('MyApp');
      expect(keys).not.toContain('1.0.0');
      expect(keys).not.toContain(true);
      expect(keys).not.toContain(3000);
    });
  });

  describe('analyzeConfigFiles', () => {
    it('should return empty results when no config files present', async () => {
      const files = [
        { filename: 'src/index.js', status: 'modified' }
      ];
      
      const result = await analyzer.analyzeConfigFiles(
        files, mockOctokit, 'owner', 'repo', 'sha123', '', ''
      );
      
      expect(result.driftResults).toEqual([]);
      expect(result.hasHighSeverity).toBe(false);
      expect(result.hasMediumSeverity).toBe(false);
    });

    it('should detect feature flag changes', async () => {
      const files = [
        { filename: 'config/features.json', status: 'modified' }
      ];
      
      const headFeatures = {
        newFeature: true,
        oldFeature: false,
        betaFeature: true
      };
      
      const baseFeatures = {
        oldFeature: false,
        removedFeature: true
      };
      
      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(headFeatures)).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(baseFeatures)).toString('base64') }
        });
      
      const result = await analyzer.analyzeConfigFiles(
        files, mockOctokit, 'owner', 'repo', 'sha123', '', 'config/features.json'
      );
      
      expect(result.driftResults.length).toBe(1);
      expect(result.driftResults[0].changes).toContain('FEATURE_FLAG_ADDED: newFeature');
      expect(result.driftResults[0].changes).toContain('FEATURE_FLAG_REMOVED: removedFeature');
    });

    it('should detect package.json dependency changes', async () => {
      const files = [
        { filename: 'package.json', status: 'modified' }
      ];
      
      const headPackage = {
        dependencies: {
          'express': '^4.0.0',
          'axios': '^1.0.0'
        },
        devDependencies: {
          'jest': '^29.0.0'
        }
      };
      
      const basePackage = {
        dependencies: {
          'express': '^4.0.0'
        },
        devDependencies: {
          'jest': '^29.0.0',
          'eslint': '^8.0.0'
        }
      };
      
      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(headPackage)).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(basePackage)).toString('base64') }
        });
      
      const result = await analyzer.analyzeConfigFiles(
        files, mockOctokit, 'owner', 'repo', 'sha123', '', ''
      );
      
      expect(result.driftResults.length).toBe(1);
      expect(result.driftResults[0].changes).toContain('DEPENDENCY_ADDED: axios');
      expect(result.driftResults[0].changes).toContain('DEPENDENCY_REMOVED: eslint');
    });

    it('should detect docker-compose service changes', async () => {
      const files = [
        { filename: 'docker-compose.yml', status: 'modified' }
      ];
      
      const headCompose = `
version: '3.8'
services:
  web:
    image: nginx
  api:
    image: node
volumes:
  data:
`;
      
      const baseCompose = `
version: '3.8'
services:
  web:
    image: nginx
  db:
    image: postgres
volumes:
  data:
`;
      
      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(headCompose).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(baseCompose).toString('base64') }
        });
      
      const result = await analyzer.analyzeConfigFiles(
        files, mockOctokit, 'owner', 'repo', 'sha123', '', ''
      );
      
      expect(result.driftResults.length).toBe(1);
      expect(result.driftResults[0].changes).toContain('CONTAINER_ADDED: services.api');
      expect(result.driftResults[0].changes).toContain('CONTAINER_REMOVED: services.db');
    });

    it('should handle analysis errors gracefully', async () => {
      const files = [
        { filename: 'config.yml', status: 'modified' }
      ];
      
      mockOctokit.rest.repos.getContent.mockRejectedValue(new Error('API error'));
      
      const result = await analyzer.analyzeConfigFiles(
        files, mockOctokit, 'owner', 'repo', 'sha123', '**/*.yml', ''
      );
      
      expect(result.driftResults).toEqual([]);
      expect(result.hasHighSeverity).toBe(false);
      expect(result.hasMediumSeverity).toBe(false);
    });
  });

  describe('compareKeys', () => {
    it('should detect added and removed keys', () => {
      const baseKeys = ['app.name', 'app.version', 'database.host'];
      const headKeys = ['app.name', 'app.description', 'database.host', 'database.port'];
      
      const changes = analyzer.compareKeys(baseKeys, headKeys);
      
      expect(changes).toContain('CONFIG_KEY_REMOVED: app.version');
      expect(changes).toContain('CONFIG_KEY_ADDED: app.description');
      expect(changes).toContain('CONFIG_KEY_ADDED: database.port');
    });

    it('should detect secret key changes as high severity', () => {
      const baseKeys = ['app.name', 'app.[REDACTED_PAS]'];
      const headKeys = ['app.name', 'app.[REDACTED_TOK]'];
      
      const changes = analyzer.compareKeys(baseKeys, headKeys);
      
      expect(changes).toContain('SECRET_KEY_REMOVED: app.[REDACTED_PAS]');
      expect(changes).toContain('SECRET_KEY_ADDED: app.[REDACTED_TOK]');
    });
  });

  describe('analyzeVersionChange', () => {
    it('should detect major version changes', () => {
      const result = analyzer.analyzeVersionChange('1.0.0', '2.0.0');
      expect(result.isMajor).toBe(true);
      expect(result.isMinor).toBe(false);
      expect(result.isPatch).toBe(false);
    });

    it('should detect minor version changes', () => {
      const result = analyzer.analyzeVersionChange('1.0.0', '1.1.0');
      expect(result.isMajor).toBe(false);
      expect(result.isMinor).toBe(true);
      expect(result.isPatch).toBe(false);
    });

    it('should detect patch version changes', () => {
      const result = analyzer.analyzeVersionChange('1.0.0', '1.0.1');
      expect(result.isMajor).toBe(false);
      expect(result.isMinor).toBe(false);
      expect(result.isPatch).toBe(true);
    });

    it('should handle version prefixes (^, ~, =, v)', () => {
      expect(analyzer.analyzeVersionChange('^1.0.0', '^2.0.0').isMajor).toBe(true);
      expect(analyzer.analyzeVersionChange('~1.0.0', '~1.1.0').isMinor).toBe(true);
      expect(analyzer.analyzeVersionChange('=1.0.0', '=1.0.1').isPatch).toBe(true);
      expect(analyzer.analyzeVersionChange('v1.0.0', 'v2.0.0').isMajor).toBe(true);
    });

    it('should handle mixed prefixes', () => {
      expect(analyzer.analyzeVersionChange('^1.0.0', '~2.0.0').isMajor).toBe(true);
      expect(analyzer.analyzeVersionChange('~1.0.0', '1.1.0').isMinor).toBe(true);
    });
  });

  describe('isKnownVulnerablePackage', () => {
    it('should detect known malicious packages', () => {
      expect(analyzer.isKnownVulnerablePackage('event-stream', '3.3.4')).toBe(true);
      expect(analyzer.isKnownVulnerablePackage('flatmap-stream', '0.1.1')).toBe(true);
    });

    it('should detect specific vulnerable versions', () => {
      expect(analyzer.isKnownVulnerablePackage('eslint-scope', '3.7.2')).toBe(true);
      expect(analyzer.isKnownVulnerablePackage('eslint-scope', '3.7.3')).toBe(false);
    });

    it('should detect packages with version constraints', () => {
      expect(analyzer.isKnownVulnerablePackage('bootstrap', '3.3.0')).toBe(false);
      expect(analyzer.isKnownVulnerablePackage('lodash', '4.17.10')).toBe(false);
    });

    it('should return false for safe packages', () => {
      expect(analyzer.isKnownVulnerablePackage('express', '4.18.0')).toBe(false);
      expect(analyzer.isKnownVulnerablePackage('react', '18.0.0')).toBe(false);
    });
  });

  describe('analyzePackageJson enhanced', () => {
    it('should detect major version bumps', async () => {
      const files = [
        { filename: 'package.json', status: 'modified' }
      ];
      
      const headPackage = {
        dependencies: {
          'express': '^5.0.0'
        }
      };
      
      const basePackage = {
        dependencies: {
          'express': '^4.0.0'
        }
      };
      
      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(headPackage)).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(basePackage)).toString('base64') }
        });
      
      const result = await analyzer.analyzeConfigFiles(
        files, mockOctokit, 'owner', 'repo', 'sha123', '', ''
      );
      
      expect(result.driftResults.length).toBe(1);
      expect(result.driftResults[0].changes).toContain('MAJOR_VERSION_BUMP: express');
      expect(result.hasHighSeverity).toBe(true);
    });

    it('should detect minor version bumps', async () => {
      const files = [
        { filename: 'package.json', status: 'modified' }
      ];
      
      const headPackage = {
        dependencies: {
          'express': '^4.18.0'
        }
      };
      
      const basePackage = {
        dependencies: {
          'express': '^4.17.0'
        }
      };
      
      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(headPackage)).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(basePackage)).toString('base64') }
        });
      
      const result = await analyzer.analyzeConfigFiles(
        files, mockOctokit, 'owner', 'repo', 'sha123', '', ''
      );
      
      expect(result.driftResults.length).toBe(1);
      expect(result.driftResults[0].changes).toContain('MINOR_VERSION_BUMP: express');
      expect(result.hasMediumSeverity).toBe(true);
    });

    it('should detect security vulnerabilities', async () => {
      const files = [
        { filename: 'package.json', status: 'modified' }
      ];
      
      const headPackage = {
        dependencies: {
          'event-stream': '3.3.4'
        }
      };
      
      const basePackage = {
        dependencies: {}
      };
      
      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(headPackage)).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(basePackage)).toString('base64') }
        });
      
      const result = await analyzer.analyzeConfigFiles(
        files, mockOctokit, 'owner', 'repo', 'sha123', '', ''
      );
      
      expect(result.driftResults.length).toBe(1);
      expect(result.driftResults[0].changes).toContain('DEPENDENCY_ADDED: event-stream');
      expect(result.driftResults[0].changes).toContain('SECURITY_VULNERABILITY: event-stream');
      expect(result.hasHighSeverity).toBe(true);
    });

    it('should detect license changes', async () => {
      const files = [
        { filename: 'package.json', status: 'modified' }
      ];
      
      const headPackage = {
        license: 'GPL-3.0',
        dependencies: {}
      };
      
      const basePackage = {
        license: 'MIT',
        dependencies: {}
      };
      
      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(headPackage)).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(basePackage)).toString('base64') }
        });
      
      const result = await analyzer.analyzeConfigFiles(
        files, mockOctokit, 'owner', 'repo', 'sha123', '', ''
      );
      
      expect(result.driftResults.length).toBe(1);
      expect(result.driftResults[0].changes).toContain('LICENSE_CHANGE: MIT -> GPL-3.0');
      expect(result.hasMediumSeverity).toBe(true);
    });
  });

  describe('analyzePackageLock', () => {
    it('should detect new lock file creation', async () => {
      const headLock = {
        lockfileVersion: 2,
        dependencies: {
          'express': {
            version: '4.18.0',
            integrity: 'sha512-abc123'
          }
        }
      };
      
      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(headLock)).toString('base64') }
        })
        .mockRejectedValueOnce(new Error('Not found'));
      
      const result = await analyzer.analyzePackageLock(
        mockOctokit, 'owner', 'repo', 'sha123', 'package-lock.json'
      );
      
      expect(result.changes).toContain('NEW_LOCK_FILE: package-lock.json created');
      expect(result.severity).toBe('medium');
    });

    it('should detect transitive dependency changes', async () => {
      const headLock = {
        dependencies: {
          'express': {
            version: '4.18.0',
            integrity: 'sha512-abc123'
          },
          'lodash': {
            version: '4.17.21',
            integrity: 'sha512-def456'
          }
        }
      };
      
      const baseLock = {
        dependencies: {
          'express': {
            version: '4.18.0',
            integrity: 'sha512-abc123'
          }
        }
      };
      
      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(headLock)).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(baseLock)).toString('base64') }
        });
      
      const result = await analyzer.analyzePackageLock(
        mockOctokit, 'owner', 'repo', 'sha123', 'package-lock.json'
      );
      
      expect(result.changes).toContain('TRANSITIVE_DEPENDENCIES_CHANGED: 1 packages');
    });

    it('should detect transitive major version bumps', async () => {
      const headLock = {
        dependencies: {
          'express': {
            version: '5.0.0',
            integrity: 'sha512-abc123'
          }
        }
      };
      
      const baseLock = {
        dependencies: {
          'express': {
            version: '4.18.0',
            integrity: 'sha512-def456'
          }
        }
      };
      
      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(headLock)).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(baseLock)).toString('base64') }
        });
      
      const result = await analyzer.analyzePackageLock(
        mockOctokit, 'owner', 'repo', 'sha123', 'package-lock.json'
      );
      
      expect(result.changes).toContain('TRANSITIVE_MAJOR_BUMP: express');
      expect(result.severity).toBe('high');
    });

    it('should detect integrity mismatches', async () => {
      const headLock = {
        dependencies: {
          'express': {
            version: '4.18.0',
            integrity: 'sha512-CHANGED'
          }
        }
      };
      
      const baseLock = {
        dependencies: {
          'express': {
            version: '4.18.0',
            integrity: 'sha512-ORIGINAL'
          }
        }
      };
      
      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(headLock)).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(baseLock)).toString('base64') }
        });
      
      const result = await analyzer.analyzePackageLock(
        mockOctokit, 'owner', 'repo', 'sha123', 'package-lock.json'
      );
      
      expect(result.changes).toContain('INTEGRITY_MISMATCH: 1 packages have different checksums');
      expect(result.severity).toBe('high');
    });

    it('should detect vulnerable transitive dependencies', async () => {
      const headLock = {
        dependencies: {
          'event-stream': {
            version: '3.3.4',
            integrity: 'sha512-malicious'
          }
        }
      };
      
      const baseLock = {
        dependencies: {}
      };
      
      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(headLock)).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(baseLock)).toString('base64') }
        });
      
      const result = await analyzer.analyzePackageLock(
        mockOctokit, 'owner', 'repo', 'sha123', 'package-lock.json'
      );
      
      expect(result.changes).toContain('SECURITY_VULNERABILITY: event-stream (transitive)');
      expect(result.severity).toBe('high');
    });

    it('should handle package-lock.json with packages field (npm v7+)', async () => {
      const headLock = {
        lockfileVersion: 3,
        packages: {
          'node_modules/express': {
            version: '4.18.0',
            integrity: 'sha512-abc123'
          }
        }
      };
      
      const baseLock = {
        lockfileVersion: 3,
        packages: {}
      };
      
      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(headLock)).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(baseLock)).toString('base64') }
        });
      
      const result = await analyzer.analyzePackageLock(
        mockOctokit, 'owner', 'repo', 'sha123', 'package-lock.json'
      );
      
      expect(result.changes).toContain('TRANSITIVE_DEPENDENCIES_CHANGED: 1 packages');
    });

    it('should handle errors gracefully', async () => {
      mockOctokit.rest.repos.getContent.mockRejectedValue(new Error('API error'));
      
      const result = await analyzer.analyzePackageLock(
        mockOctokit, 'owner', 'repo', 'sha123', 'package-lock.json'
      );
      
      expect(result).toBeNull();
      expect(core.warning).toHaveBeenCalledWith('package-lock.json analysis failed: API error');
    });
  });

  describe('module exports', () => {
    it('should export ConfigAnalyzer class', () => {
      expect(ConfigAnalyzer).toBeDefined();
      expect(typeof ConfigAnalyzer).toBe('function');
    });
  });
});