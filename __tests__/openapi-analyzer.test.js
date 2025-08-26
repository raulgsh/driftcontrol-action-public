const OpenApiAnalyzer = require('../src/openapi-analyzer');

// Mock dependencies
jest.mock('@actions/core');
jest.mock('@apidevtools/swagger-parser');
jest.mock('@useoptic/openapi-utilities');
jest.mock('js-yaml');

const core = require('@actions/core');
const SwaggerParser = require('@apidevtools/swagger-parser');
const { diff } = require('@useoptic/openapi-utilities');
const yaml = require('js-yaml');

describe('OpenApiAnalyzer', () => {
  let analyzer;
  let mockOctokit;
  let mockRiskScorer;

  beforeEach(() => {
    // Clear all mocks
    jest.clearAllMocks();

    // Create fresh instance
    analyzer = new OpenApiAnalyzer();

    // Mock octokit
    mockOctokit = {
      rest: {
        repos: {
          getContent: jest.fn()
        }
      }
    };

    // Mock core methods
    core.info = jest.fn();
    core.warning = jest.fn();

    // Mock SwaggerParser
    SwaggerParser.parse = jest.fn();

    // Mock optic diff
    diff.mockReset();

    // Mock js-yaml
    yaml.parse = jest.fn().mockReturnValue({ openapi: '3.0.0' });

    // Mock the risk scorer
    mockRiskScorer = {
      scoreChanges: jest.fn()
    };
    analyzer.riskScorer = mockRiskScorer;
  });

  describe('constructor', () => {
    test('should create instance with riskScorer', () => {
      const newAnalyzer = new OpenApiAnalyzer();
      expect(newAnalyzer.riskScorer).toBeDefined();
    });
  });

  describe('detectSpecRenames', () => {
    test('should detect OpenAPI spec rename from YAML to YAML', () => {
      const files = [
        { filename: 'api/old-spec.yaml', status: 'removed' },
        { filename: 'api/new-spec.yaml', status: 'added' },
        { filename: 'src/index.js', status: 'modified' }
      ];

      const result = analyzer.detectSpecRenames(files, 'api/new-spec.yaml');

      expect(result.actualOpenApiPath).toBe('api/new-spec.yaml');
      expect(result.renamedFromPath).toBe('api/old-spec.yaml');
      expect(core.info).toHaveBeenCalledWith('Detected OpenAPI spec rename: api/old-spec.yaml → api/new-spec.yaml');
    });

    test('should detect OpenAPI spec rename from JSON to YAML', () => {
      const files = [
        { filename: 'openapi.json', status: 'removed' },
        { filename: 'openapi.yaml', status: 'added' }
      ];

      const result = analyzer.detectSpecRenames(files, 'openapi.yaml');

      expect(result.actualOpenApiPath).toBe('openapi.yaml');
      expect(result.renamedFromPath).toBe('openapi.json');
    });

    test('should detect OpenAPI spec rename from YAML to JSON', () => {
      const files = [
        { filename: 'spec.yml', status: 'removed' },
        { filename: 'spec.json', status: 'added' }
      ];

      const result = analyzer.detectSpecRenames(files, 'spec.json');

      expect(result.actualOpenApiPath).toBe('spec.json');
      expect(result.renamedFromPath).toBe('spec.yml');
    });

    test('should return original path when no rename detected', () => {
      const files = [
        { filename: 'src/index.js', status: 'modified' },
        { filename: 'README.md', status: 'added' }
      ];

      const result = analyzer.detectSpecRenames(files, 'openapi.yaml');

      expect(result.actualOpenApiPath).toBe('openapi.yaml');
      expect(result.renamedFromPath).toBeNull();
      expect(core.info).not.toHaveBeenCalled();
    });

    test('should handle multiple deleted files and find correct rename', () => {
      const files = [
        { filename: 'old-docs.md', status: 'removed' },
        { filename: 'api/v1/spec.yaml', status: 'removed' },
        { filename: 'config.json', status: 'removed' },
        { filename: 'api/v2/spec.yaml', status: 'added' }
      ];

      const result = analyzer.detectSpecRenames(files, 'api/v2/spec.yaml');

      expect(result.actualOpenApiPath).toBe('api/v2/spec.yaml');
      expect(result.renamedFromPath).toBe('api/v1/spec.yaml');
    });

    test('should handle case where deleted OpenAPI file exists but no added OpenAPI file', () => {
      const files = [
        { filename: 'openapi.yaml', status: 'removed' },
        { filename: 'src/index.js', status: 'added' }
      ];

      const result = analyzer.detectSpecRenames(files, 'openapi.yaml');

      expect(result.actualOpenApiPath).toBe('openapi.yaml');
      expect(result.renamedFromPath).toBeNull();
    });

    test('should support all OpenAPI extensions', () => {
      const extensions = ['.yaml', '.yml', '.json'];
      
      extensions.forEach(ext => {
        const files = [
          { filename: `old-spec${ext}`, status: 'removed' },
          { filename: `new-spec${ext}`, status: 'added' }
        ];

        const result = analyzer.detectSpecRenames(files, `new-spec${ext}`);

        expect(result.renamedFromPath).toBe(`old-spec${ext}`);
      });
    });
  });

  describe('analyzeOpenApiDrift', () => {
    const basePullRequest = {
      base: { sha: 'base-sha' },
      head: { sha: 'head-sha' }
    };

    test('should return empty results when neither base nor head spec exists', async () => {
      mockOctokit.rest.repos.getContent
        .mockRejectedValueOnce(new Error('File not found'))
        .mockRejectedValueOnce(new Error('File not found'));

      const result = await analyzer.analyzeOpenApiDrift(
        mockOctokit, 'owner', 'repo', basePullRequest, 'openapi.yaml', null
      );

      expect(result.driftResults).toEqual([]);
      expect(result.hasHighSeverity).toBe(false);
      expect(result.hasMediumSeverity).toBe(false);
    });

    test('should detect API deletion (base exists, head does not)', async () => {
      const baseSpecContent = JSON.stringify({
        openapi: '3.0.0',
        info: { title: 'Test API', version: '1.0.0' },
        paths: { '/users': { get: {} } }
      });

      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(baseSpecContent).toString('base64') }
        })
        .mockRejectedValueOnce(new Error('File not found'));

      SwaggerParser.parse.mockResolvedValueOnce({ openapi: '3.0.0' });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'high',
        reasoning: ['Contains destructive or breaking operations']
      });

      const result = await analyzer.analyzeOpenApiDrift(
        mockOctokit, 'owner', 'repo', basePullRequest, 'openapi.yaml', null
      );

      expect(result.hasHighSeverity).toBe(true);
      expect(result.driftResults).toHaveLength(1);
      expect(result.driftResults[0].changes).toContain('API_DELETION: OpenAPI specification was deleted');
    });

    test('should detect new API spec (head exists, base does not)', async () => {
      const headSpecContent = JSON.stringify({
        openapi: '3.0.0',
        info: { title: 'New API', version: '1.0.0' },
        paths: { '/users': { get: {} } }
      });

      mockOctokit.rest.repos.getContent
        .mockRejectedValueOnce(new Error('Base file not found'))
        .mockResolvedValueOnce({
          data: { content: Buffer.from(headSpecContent).toString('base64') }
        });

      SwaggerParser.parse.mockResolvedValueOnce({ openapi: '3.0.0' });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'low',
        reasoning: ['Contains backward-compatible changes']
      });

      const result = await analyzer.analyzeOpenApiDrift(
        mockOctokit, 'owner', 'repo', basePullRequest, 'openapi.yaml', null
      );

      expect(result.hasHighSeverity).toBe(false);
      expect(result.driftResults).toHaveLength(1);
      expect(result.driftResults[0].changes).toContain('New OpenAPI specification added');
    });

    test('should compare specs using @useoptic diff when both exist', async () => {
      const baseSpec = {
        openapi: '3.0.0',
        info: { title: 'API', version: '1.0.0' },
        paths: { '/users': { get: {} } }
      };

      const headSpec = {
        openapi: '3.0.0',
        info: { title: 'API', version: '1.0.0' },
        paths: { 
          '/users': { get: {}, post: {} },
          '/posts': { get: {} }
        }
      };

      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(baseSpec)).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(headSpec)).toString('base64') }
        });

      SwaggerParser.parse
        .mockResolvedValueOnce(baseSpec)
        .mockResolvedValueOnce(headSpec);

      diff.mockReturnValue([
        { type: 'added', path: '/users.post' },
        { type: 'added', path: '/posts.get' }
      ]);

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'low',
        reasoning: ['Contains backward-compatible changes']
      });

      const result = await analyzer.analyzeOpenApiDrift(
        mockOctokit, 'owner', 'repo', basePullRequest, 'openapi.yaml', null
      );

      expect(diff).toHaveBeenCalledWith(baseSpec, headSpec);
      expect(result.driftResults).toHaveLength(1);
      expect(result.driftResults[0].changes).toContain('Modified: /users.post');
      expect(result.driftResults[0].changes).toContain('Modified: /posts.get');
    });

    test('should detect breaking changes from diff results', async () => {
      const baseSpec = { openapi: '3.0.0', paths: { '/users': { get: {} } } };
      const headSpec = { openapi: '3.0.0', paths: {} };

      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(baseSpec)).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(headSpec)).toString('base64') }
        });

      SwaggerParser.parse
        .mockResolvedValueOnce(baseSpec)
        .mockResolvedValueOnce(headSpec);

      diff.mockReturnValue([
        { type: 'removed', path: '/users' },
        { type: 'breaking', path: '/posts.schema' }
      ]);

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'high',
        reasoning: ['Contains destructive or breaking operations']
      });

      const result = await analyzer.analyzeOpenApiDrift(
        mockOctokit, 'owner', 'repo', basePullRequest, 'openapi.yaml', null
      );

      expect(result.hasHighSeverity).toBe(true);
      expect(result.driftResults[0].changes).toContain('BREAKING_CHANGE: Removed /users');
      expect(result.driftResults[0].changes).toContain('BREAKING_CHANGE: /posts.schema');
    });

    test('should handle YAML spec files correctly', async () => {
      const yamlSpec = `
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users:
    get: {}
      `;

      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(yamlSpec).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(yamlSpec).toString('base64') }
        });

      SwaggerParser.parse
        .mockResolvedValueOnce({ openapi: '3.0.0' })
        .mockResolvedValueOnce({ openapi: '3.0.0' });

      diff.mockReturnValue([]);

      await analyzer.analyzeOpenApiDrift(
        mockOctokit, 'owner', 'repo', basePullRequest, 'openapi.yaml', null
      );

      // Should parse YAML content correctly
      expect(SwaggerParser.parse).toHaveBeenCalledTimes(2);
    });

    test('should handle diff analysis failure gracefully', async () => {
      const baseSpec = { openapi: '3.0.0', paths: { '/old': {} } };
      const headSpec = { openapi: '3.0.0', paths: { '/new': {} } };

      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(baseSpec)).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(headSpec)).toString('base64') }
        });

      SwaggerParser.parse
        .mockResolvedValueOnce(baseSpec)
        .mockResolvedValueOnce(headSpec);

      diff.mockImplementation(() => {
        throw new Error('Diff analysis failed');
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'medium',
        reasoning: ['Analysis failed but changes detected'],
        changes: ['OpenAPI specification changes detected (detailed analysis failed)']
      });

      const result = await analyzer.analyzeOpenApiDrift(
        mockOctokit, 'owner', 'repo', basePullRequest, 'openapi.yaml', null
      );

      expect(core.warning).toHaveBeenCalledWith('OpenAPI diff analysis failed: Diff analysis failed');
      expect(result.driftResults).toHaveLength(1);
      expect(result.driftResults[0].changes).toContain('OpenAPI specification changes detected (detailed analysis failed)');
    });

    test('should handle spec rename scenario correctly', async () => {
      const specContent = JSON.stringify({ openapi: '3.0.0', paths: { '/test': {} } });

      // First call for base spec (renamed from path)
      // Second call for head spec (actual path)
      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(specContent).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(specContent).toString('base64') }
        });

      SwaggerParser.parse
        .mockResolvedValueOnce({ openapi: '3.0.0' })
        .mockResolvedValueOnce({ openapi: '3.0.0' });

      diff.mockReturnValue([
        { type: 'added', path: '/test' }
      ]);

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'low',
        reasoning: ['Minor changes detected'],
        changes: ['Modified: /test']
      });

      const result = await analyzer.analyzeOpenApiDrift(
        mockOctokit, 'owner', 'repo', basePullRequest, 'new-spec.yaml', 'old-spec.yaml'
      );

      // Should call getContent with renamed path for base
      expect(mockOctokit.rest.repos.getContent).toHaveBeenCalledWith({
        owner: 'owner',
        repo: 'repo',
        path: 'old-spec.yaml',
        ref: 'base-sha'
      });

      // Should call getContent with actual path for head
      expect(mockOctokit.rest.repos.getContent).toHaveBeenCalledWith({
        owner: 'owner',
        repo: 'repo',
        path: 'new-spec.yaml',
        ref: 'head-sha'
      });

      expect(result.driftResults).toHaveLength(1);
      expect(result.driftResults[0]).toHaveProperty('renamed');
      expect(result.driftResults[0].renamed).toEqual({
        from: 'old-spec.yaml',
        to: 'new-spec.yaml'
      });
    });

    test('should handle SwaggerParser errors gracefully', async () => {
      const invalidSpec = '{ invalid json';

      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(invalidSpec).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(invalidSpec).toString('base64') }
        });

      SwaggerParser.parse.mockRejectedValue(new Error('Invalid OpenAPI spec'));

      const result = await analyzer.analyzeOpenApiDrift(
        mockOctokit, 'owner', 'repo', basePullRequest, 'openapi.yaml', null
      );

      expect(core.info).toHaveBeenCalledWith(expect.stringContaining('No valid OpenAPI spec found in base branch at openapi.yaml:'));
      expect(core.info).toHaveBeenCalledWith(expect.stringContaining('No valid OpenAPI spec found in head branch at openapi.yaml:'));
      expect(result.driftResults).toEqual([]);
    });

    test('should handle file not found errors', async () => {
      mockOctokit.rest.repos.getContent.mockRejectedValue(new Error('File not found'));

      const result = await analyzer.analyzeOpenApiDrift(
        mockOctokit, 'owner', 'repo', basePullRequest, 'nonexistent.yaml', null
      );

      expect(core.info).toHaveBeenCalledWith('No valid OpenAPI spec found in base branch at nonexistent.yaml: File not found');
      expect(core.info).toHaveBeenCalledWith('No valid OpenAPI spec found in head branch at nonexistent.yaml: File not found');
      expect(result.driftResults).toEqual([]);
    });

    test('should handle network errors gracefully', async () => {
      mockOctokit.rest.repos.getContent.mockRejectedValue(new Error('Network error'));

      const result = await analyzer.analyzeOpenApiDrift(
        mockOctokit, 'owner', 'repo', basePullRequest, 'openapi.yaml', null
      );

      expect(core.info).toHaveBeenCalledWith('No valid OpenAPI spec found in base branch at openapi.yaml: Network error');
      expect(core.info).toHaveBeenCalledWith('No valid OpenAPI spec found in head branch at openapi.yaml: Network error');
      expect(result.driftResults).toEqual([]);
    });

    test('should detect no changes when specs are identical', async () => {
      const identicalSpec = { openapi: '3.0.0', paths: { '/test': {} } };

      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(identicalSpec)).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(identicalSpec)).toString('base64') }
        });

      SwaggerParser.parse
        .mockResolvedValueOnce(identicalSpec)
        .mockResolvedValueOnce(identicalSpec);

      diff.mockReturnValue([]);

      const result = await analyzer.analyzeOpenApiDrift(
        mockOctokit, 'owner', 'repo', basePullRequest, 'openapi.yaml', null
      );

      expect(result.driftResults).toEqual([]);
    });

    test('should include file information in drift results', async () => {
      const baseSpec = { openapi: '3.0.0' };
      const headSpec = { openapi: '3.0.0', paths: { '/new': {} } };

      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(baseSpec)).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(headSpec)).toString('base64') }
        });

      SwaggerParser.parse
        .mockResolvedValueOnce(baseSpec)
        .mockResolvedValueOnce(headSpec);

      diff.mockReturnValue([{ type: 'added', path: '/new' }]);

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'low',
        reasoning: ['Contains backward-compatible changes']
      });

      const result = await analyzer.analyzeOpenApiDrift(
        mockOctokit, 'owner', 'repo', basePullRequest, 'my-api.yaml', null
      );

      expect(result.driftResults[0]).toEqual({
        type: 'api',
        file: 'my-api.yaml',
        severity: 'low',
        changes: ['Modified: /new'],
        reasoning: ['Contains backward-compatible changes'],
        renamed: null
      });
    });

    test('should handle empty diff results', async () => {
      const baseSpec = { openapi: '3.0.0' };
      const headSpec = { openapi: '3.0.0' };

      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(baseSpec)).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(headSpec)).toString('base64') }
        });

      SwaggerParser.parse
        .mockResolvedValueOnce(baseSpec)
        .mockResolvedValueOnce(headSpec);

      // Diff returns empty array but specs have different raw content
      diff.mockReturnValue([]);

      const result = await analyzer.analyzeOpenApiDrift(
        mockOctokit, 'owner', 'repo', basePullRequest, 'openapi.yaml', null
      );

      // Should not create drift results for identical content
      expect(result.driftResults).toEqual([]);
    });
  });
});