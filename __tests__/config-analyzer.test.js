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
      expect(result.driftResults[0].changes).toContain('DEPENDENCY_ADDED: dependencies.axios');
      expect(result.driftResults[0].changes).toContain('DEPENDENCY_REMOVED: devDependencies.eslint');
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

  describe('module exports', () => {
    it('should export ConfigAnalyzer class', () => {
      expect(ConfigAnalyzer).toBeDefined();
      expect(typeof ConfigAnalyzer).toBe('function');
    });
  });
});