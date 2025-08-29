const OpenApiAnalyzer = require('../src/openapi-analyzer');

// Mock dependencies
jest.mock('@actions/core');
jest.mock('@apidevtools/swagger-parser');
jest.mock('@useoptic/openapi-utilities');
jest.mock('js-yaml');

// Mock ContentFetcher for simpler testing
class MockContentFetcher {
  constructor() {
    this.fetchContent = jest.fn();
    this.fetchContentSafe = jest.fn();
    this.batchFetch = jest.fn();
  }
}

const core = require('@actions/core');
const SwaggerParser = require('@apidevtools/swagger-parser');
const { diff } = require('@useoptic/openapi-utilities');
const yaml = require('js-yaml');

describe('OpenApiAnalyzer', () => {
  let analyzer;
  let mockOctokit;
  let mockContentFetcher;
  let mockRiskScorer;

  beforeEach(() => {
    // Clear all mocks
    jest.clearAllMocks();

    // Create mock content fetcher
    mockContentFetcher = new MockContentFetcher();

    // Create fresh instance with mock content fetcher
    analyzer = new OpenApiAnalyzer(mockContentFetcher);

    // Mock octokit (for legacy fallback tests)
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

    test('should accept contentFetcher in constructor', () => {
      const contentFetcher = new MockContentFetcher();
      const newAnalyzer = new OpenApiAnalyzer(contentFetcher);
      expect(newAnalyzer.contentFetcher).toBe(contentFetcher);
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
      // With ContentFetcher, testing is much simpler - just mock the loadSpec returns
      mockContentFetcher.batchFetch.mockResolvedValue([null, null]);

      const result = await analyzer.analyzeOpenApiDrift(
        mockOctokit, 'owner', 'repo', basePullRequest, 'openapi.yaml', null
      );

      expect(result.driftResults).toEqual([]);
      expect(result.hasHighSeverity).toBe(false);
      expect(result.hasMediumSeverity).toBe(false);
    });

    test('should fallback to legacy method when no contentFetcher', async () => {
      // Test backward compatibility
      const legacyAnalyzer = new OpenApiAnalyzer(); // No contentFetcher
      
      mockOctokit.rest.repos.getContent
        .mockRejectedValueOnce(new Error('File not found'))
        .mockRejectedValueOnce(new Error('File not found'));

      const result = await legacyAnalyzer.analyzeOpenApiDrift(
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

      // Mock ContentFetcher to return base spec and null for head
      mockContentFetcher.fetchContent
        .mockResolvedValueOnce({ content: baseSpecContent }) // base spec exists
        .mockResolvedValueOnce(null); // head spec doesn't exist

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

      // Mock ContentFetcher to return null for base and spec for head
      mockContentFetcher.fetchContent
        .mockResolvedValueOnce(null) // base spec doesn't exist
        .mockResolvedValueOnce({ content: headSpecContent }); // head spec exists

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

      // Mock ContentFetcher to return both specs
      mockContentFetcher.fetchContent
        .mockResolvedValueOnce({ content: JSON.stringify(baseSpec) })
        .mockResolvedValueOnce({ content: JSON.stringify(headSpec) });

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

      // The diff is called within compareSpecs function, not directly
      expect(result.driftResults).toHaveLength(1);
      expect(result.driftResults[0].severity).toBe('low');
    });

    test('should detect breaking changes from diff results', async () => {
      const baseSpec = { openapi: '3.0.0', paths: { '/users': { get: {} } } };
      const headSpec = { openapi: '3.0.0', paths: {} };

      // Mock ContentFetcher to return both specs
      mockContentFetcher.fetchContent
        .mockResolvedValueOnce({ content: JSON.stringify(baseSpec) })
        .mockResolvedValueOnce({ content: JSON.stringify(headSpec) });

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
      expect(result.driftResults).toHaveLength(1);
      expect(result.driftResults[0].severity).toBe('high');
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

      // Mock ContentFetcher to return YAML specs
      mockContentFetcher.fetchContent
        .mockResolvedValueOnce({ content: yamlSpec })
        .mockResolvedValueOnce({ content: yamlSpec });

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

      // Mock ContentFetcher to return both specs
      mockContentFetcher.fetchContent
        .mockResolvedValueOnce({ content: JSON.stringify(baseSpec) })
        .mockResolvedValueOnce({ content: JSON.stringify(headSpec) });

      SwaggerParser.parse
        .mockResolvedValueOnce(baseSpec)
        .mockResolvedValueOnce(headSpec);

      diff.mockImplementation(() => {
        throw new Error('Diff analysis failed');
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'medium',
        reasoning: ['Analysis failed but changes detected']
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

      // Mock ContentFetcher to return specs for both paths
      mockContentFetcher.fetchContent
        .mockResolvedValueOnce({ content: specContent }) // base spec (renamed from)
        .mockResolvedValueOnce({ content: specContent }); // head spec (actual path)

      SwaggerParser.parse
        .mockResolvedValueOnce({ openapi: '3.0.0' })
        .mockResolvedValueOnce({ openapi: '3.0.0' });

      diff.mockReturnValue([
        { type: 'added', path: '/test' }
      ]);

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'low',
        reasoning: ['Minor changes detected']
      });

      const result = await analyzer.analyzeOpenApiDrift(
        mockOctokit, 'owner', 'repo', basePullRequest, 'new-spec.yaml', 'old-spec.yaml'
      );

      // Should fetch content from both paths
      expect(mockContentFetcher.fetchContent).toHaveBeenCalledTimes(2);
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

      expect(core.info).toHaveBeenCalledWith('Checking OpenAPI spec at: openapi.yaml');
      expect(result.driftResults).toEqual([]);
    });

    test('should handle file not found errors', async () => {
      mockOctokit.rest.repos.getContent.mockRejectedValue(new Error('File not found'));

      const result = await analyzer.analyzeOpenApiDrift(
        mockOctokit, 'owner', 'repo', basePullRequest, 'nonexistent.yaml', null
      );

      expect(core.info).toHaveBeenCalledWith('Checking OpenAPI spec at: nonexistent.yaml');
      expect(result.driftResults).toEqual([]);
    });

    test('should handle network errors gracefully', async () => {
      mockOctokit.rest.repos.getContent.mockRejectedValue(new Error('Network error'));

      const result = await analyzer.analyzeOpenApiDrift(
        mockOctokit, 'owner', 'repo', basePullRequest, 'openapi.yaml', null
      );

      expect(core.info).toHaveBeenCalledWith('Checking OpenAPI spec at: openapi.yaml');
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

      // Mock ContentFetcher to return both specs
      mockContentFetcher.fetchContent
        .mockResolvedValueOnce({ content: JSON.stringify(baseSpec) })
        .mockResolvedValueOnce({ content: JSON.stringify(headSpec) });

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

      expect(result.driftResults).toHaveLength(1);
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