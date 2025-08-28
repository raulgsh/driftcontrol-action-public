const { 
  run, 
  generateCommentBody, 
  generateFixSuggestion, 
  postOrUpdateComment,
  extractMetadata,
  generateEntityVariations,
  findBestMatch,
  detectApiOperations,
  detectDbOperations,
  operationsCorrelate,
  identifyRootCauses
} = require('../src/index');

// Mock all external dependencies
jest.mock('@actions/core');
jest.mock('@actions/github');
jest.mock('@apidevtools/swagger-parser');
jest.mock('@useoptic/openapi-utilities');

const core = require('@actions/core');
const github = require('@actions/github');
const SwaggerParser = require('@apidevtools/swagger-parser');
const { diff } = require('@useoptic/openapi-utilities');

describe('Integration Tests', () => {
  let mockOctokit;
  let mockContext;

  beforeEach(() => {
    // Clear all mocks
    jest.clearAllMocks();

    // Mock environment variables (extending pattern from github-api.test.js)
    process.env.GITHUB_TOKEN = 'fake-github-token';
    process.env.GITHUB_REPOSITORY = 'test-owner/test-repo';
    process.env.GITHUB_EVENT_PATH = '/fake/event.json';

    // Mock core methods
    core.getInput = jest.fn();
    core.info = jest.fn();
    core.warning = jest.fn();
    core.error = jest.fn();
    core.setFailed = jest.fn();

    // Mock octokit
    mockOctokit = {
      rest: {
        repos: {
          getContent: jest.fn()
        },
        pulls: {
          listFiles: jest.fn()
        },
        issues: {
          listComments: jest.fn(),
          createComment: jest.fn(),
          updateComment: jest.fn()
        }
      }
    };

    // Mock GitHub context (extending pattern from github-api.test.js)
    mockContext = {
      payload: {
        pull_request: {
          number: 123,
          base: { sha: 'base-sha' },
          head: { sha: 'head-sha' }
        },
        repository: {
          name: 'test-repo',
          owner: { login: 'test-owner' }
        }
      },
      repo: {
        owner: 'test-owner',
        repo: 'test-repo'
      }
    };

    // Mock github.getOctokit and context
    github.getOctokit = jest.fn().mockReturnValue(mockOctokit);
    github.context = mockContext;

    // Mock SwaggerParser
    SwaggerParser.parse = jest.fn();

    // Mock optic diff
    diff.mockReset();

    // Setup default input values
    core.getInput.mockImplementation((name) => {
      const inputs = {
        'github-token': 'fake-token',
        'token': 'fake-token',  // Add token input that index.js looks for
        'openapi_path': 'openapi.yaml',
        'sql_glob': '**/*.sql',
        'fail_on_medium': 'false',
        'override': 'false'
      };
      return inputs[name] || '';
    });

    // Setup default octokit mocking (extending pattern from openapi-analyzer.test.js)
    mockOctokit.rest.pulls.listFiles.mockResolvedValue({
      data: []
    });
    mockOctokit.rest.repos.getContent.mockRejectedValue(new Error('File not found'));
    mockOctokit.rest.issues.listComments.mockResolvedValue({ data: [] });
    mockOctokit.rest.issues.createComment.mockResolvedValue({ 
      data: { id: 1, body: 'Test comment' } 
    });
  });

  describe('End-to-End Workflow', () => {
    test('should prevent false positive correlations with improved matching', () => {
      // Test case that would previously create false positives
      // /users/products endpoint should NOT correlate with both users and products tables
      const apiResult = {
        type: 'api',
        file: '/users/products',
        endpoints: ['/users/products'],
        changes: ['GET /users/products']
      };
      
      const dbResultUsers = {
        type: 'database',
        entities: ['users'],
        changes: ['CREATE TABLE users']
      };
      
      const dbResultProducts = {
        type: 'database', 
        entities: ['products'],
        changes: ['CREATE TABLE products']
      };
      
      // Extract metadata
      const apiMeta = extractMetadata(apiResult, []);
      const dbUsersMeta = extractMetadata(dbResultUsers, []);
      const dbProductsMeta = extractMetadata(dbResultProducts, []);
      
      // Test entity variations
      const userProductsVars = generateEntityVariations('user_products');
      const usersVars = generateEntityVariations('users');
      const productsVars = generateEntityVariations('products');
      
      // Match should be weak for both
      const matchUsers = findBestMatch(userProductsVars, usersVars);
      const matchProducts = findBestMatch(userProductsVars, productsVars);
      
      // Both should have low confidence (substring matches but not strong)
      expect(matchUsers.confidence).toBeLessThan(0.9);
      expect(matchProducts.confidence).toBeLessThan(0.9);
      
      // The combined path should match better with a junction table
      const userProductsTableVars = generateEntityVariations('user_products');
      const matchJunction = findBestMatch(userProductsVars, userProductsTableVars);
      expect(matchJunction.confidence).toBeGreaterThan(0.9); // Should be exact match
    });
    
    test('should correctly correlate singular and plural entity forms', () => {
      // Test that 'user' API correlates with 'users' table
      const variations1 = generateEntityVariations('user');
      const variations2 = generateEntityVariations('users');
      const match = findBestMatch(variations1, variations2);
      
      expect(match.confidence).toBeGreaterThan(0.8);
      expect(variations1).toContain('user');
      expect(variations1).toContain('users');
      expect(variations2).toContain('user');
      expect(variations2).toContain('users');
    });
    
    test('should handle snake_case and camelCase conversions', () => {
      // Test case conversion matching
      const camelVars = generateEntityVariations('userProfile');
      const snakeVars = generateEntityVariations('user_profile');
      const match = findBestMatch(camelVars, snakeVars);
      
      // Should have high confidence match (not necessarily 1.0 due to lowercase handling)
      expect(match.confidence).toBeGreaterThan(0.8);
      
      // Check that variations include the right transformations
      // userProfile should generate user_profile
      expect(camelVars.some(v => v === 'user_profile' || v === 'userprofile')).toBe(true);
      // user_profile should generate userprofile (without underscore)
      expect(snakeVars).toContain('userprofile');
    });
    
    test('should complete full analysis with no drift detected', async () => {
      // Setup: No SQL files, no OpenAPI changes
      mockOctokit.rest.pulls.listFiles.mockResolvedValue({
        data: [
          { filename: 'src/index.js', status: 'modified' },
          { filename: 'README.md', status: 'added' }
        ]
      });

      mockOctokit.rest.repos.getContent.mockRejectedValue(new Error('File not found'));
      mockOctokit.rest.issues.listComments.mockResolvedValue({ data: [] });
      mockOctokit.rest.issues.createComment.mockResolvedValue({ data: { id: 1 } });

      await run();

      expect(core.info).toHaveBeenCalledWith('No drift detected');
      expect(mockOctokit.rest.issues.createComment).toHaveBeenCalledWith({
        owner: 'test-owner',
        repo: 'test-repo',
        issue_number: 123,
        body: expect.stringContaining('No API or database drift detected')
      });
      expect(core.setFailed).not.toHaveBeenCalled();
    });

    test('should detect and report high severity SQL drift', async () => {
      // Setup: SQL file with DROP TABLE
      mockOctokit.rest.pulls.listFiles.mockResolvedValue({
        data: [
          { filename: 'migrations/001_drop_users.sql', status: 'added' }
        ]
      });

      mockOctokit.rest.repos.getContent.mockResolvedValue({
        data: { content: Buffer.from('DROP TABLE users;').toString('base64') }
      });

      mockOctokit.rest.issues.listComments.mockResolvedValue({ data: [] });
      mockOctokit.rest.issues.createComment.mockResolvedValue({ data: { id: 1 } });

      core.getInput.mockImplementation((name) => {
        const inputs = {
          'github-token': 'fake-token',
          'token': 'fake-token',
          'sql_glob': '**/*.sql',
          'fail_on_medium': 'false',
          'override': 'false'
        };
        return inputs[name] || '';
      });

      await run();

      expect(core.setFailed).toHaveBeenCalledWith(
        expect.stringContaining('High severity drift detected')
      );
      expect(mockOctokit.rest.issues.createComment).toHaveBeenCalledWith({
        owner: 'test-owner',
        repo: 'test-repo',
        issue_number: 123,
        body: expect.stringContaining('HIGH Severity Issues')
      });
    });

    test('should detect and report OpenAPI breaking changes', async () => {
      const baseSpec = {
        openapi: '3.0.0',
        paths: { '/users': { get: {} }, '/posts': { get: {} } }
      };
      const headSpec = {
        openapi: '3.0.0',
        paths: { '/users': { get: {} } }
      };

      mockOctokit.rest.pulls.listFiles.mockResolvedValue({
        data: [{ filename: 'openapi.yaml', status: 'modified' }]
      });

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
        { type: 'removed', path: '/posts' }
      ]);

      mockOctokit.rest.issues.listComments.mockResolvedValue({ data: [] });
      mockOctokit.rest.issues.createComment.mockResolvedValue({ data: { id: 1 } });

      core.getInput.mockImplementation((name) => {
        const inputs = {
          'github-token': 'fake-token',
          'token': 'fake-token',
          'openapi_path': 'openapi.yaml',
          'fail_on_medium': 'false',
          'override': 'false'
        };
        return inputs[name] || '';
      });

      await run();

      expect(core.setFailed).toHaveBeenCalledWith(
        expect.stringContaining('High severity drift detected')
      );
      expect(mockOctokit.rest.issues.createComment).toHaveBeenCalledWith({
        owner: 'test-owner',
        repo: 'test-repo',
        issue_number: 123,
        body: expect.stringContaining('BREAKING_CHANGE')
      });
    });

    test('should handle override scenario correctly', async () => {
      core.getInput.mockImplementation((name) => {
        const inputs = {
          'github-token': 'fake-token',
          'token': 'fake-token',
          'openapi_path': 'openapi.yaml',
          'sql_glob': '**/*.sql',
          'fail_on_medium': 'false',
          'override': 'true'
        };
        return inputs[name] || '';
      });

      // Setup: High severity SQL drift
      mockOctokit.rest.pulls.listFiles.mockResolvedValue({
        data: [{ filename: 'migrations/drop.sql', status: 'added' }]
      });

      mockOctokit.rest.repos.getContent.mockResolvedValue({
        data: { content: Buffer.from('DROP TABLE users;').toString('base64') }
      });

      mockOctokit.rest.issues.listComments.mockResolvedValue({ data: [] });
      mockOctokit.rest.issues.createComment.mockResolvedValue({ data: { id: 1 } });

      await run();

      expect(core.warning).toHaveBeenCalledWith(
        expect.stringContaining('Policy override applied')
      );
      expect(core.setFailed).not.toHaveBeenCalled();
      expect(mockOctokit.rest.issues.createComment).toHaveBeenCalledWith({
        owner: 'test-owner',
        repo: 'test-repo',
        issue_number: 123,
        body: expect.stringContaining('Policy Override Active')
      });
    });

    test('should handle mixed SQL and OpenAPI drift', async () => {
      const baseSpec = { openapi: '3.0.0', paths: { '/users': { get: {} } } };
      const headSpec = { openapi: '3.0.0', paths: { '/users': { get: {}, post: {} } } };

      mockOctokit.rest.pulls.listFiles.mockResolvedValue({
        data: [
          { filename: 'migrations/add_column.sql', status: 'added' },
          { filename: 'openapi.yaml', status: 'modified' }
        ]
      });

      // SQL file content (low severity)
      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from('ALTER TABLE users ADD COLUMN email VARCHAR(255);').toString('base64') }
        })
        // OpenAPI base
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(baseSpec)).toString('base64') }
        })
        // OpenAPI head
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(headSpec)).toString('base64') }
        });

      SwaggerParser.parse
        .mockResolvedValueOnce(baseSpec)
        .mockResolvedValueOnce(headSpec);

      diff.mockReturnValue([
        { type: 'added', path: '/users.post' }
      ]);

      mockOctokit.rest.issues.listComments.mockResolvedValue({ data: [] });
      mockOctokit.rest.issues.createComment.mockResolvedValue({ data: { id: 1 } });

      core.getInput.mockImplementation((name) => {
        const inputs = {
          'github-token': 'fake-token',
          'token': 'fake-token',
          'openapi_path': 'openapi.yaml',
          'sql_glob': '**/*.sql',
          'fail_on_medium': 'false',
          'override': 'false'
        };
        return inputs[name] || '';
      });

      await run();

      // Verify drift was detected and comment was created
      expect(mockOctokit.rest.issues.createComment).toHaveBeenCalledWith({
        owner: 'test-owner',
        repo: 'test-repo',
        issue_number: 123,
        body: expect.stringContaining('drift issue')
      });
    });

    test('should handle OpenAPI spec rename correctly', async () => {
      const specContent = { openapi: '3.0.0', paths: { '/test': {} } };

      mockOctokit.rest.pulls.listFiles.mockResolvedValue({
        data: [
          { filename: 'old-api.yaml', status: 'removed' },
          { filename: 'new-api.yaml', status: 'added' }
        ]
      });

      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(specContent)).toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(specContent)).toString('base64') }
        });

      SwaggerParser.parse
        .mockResolvedValueOnce(specContent)
        .mockResolvedValueOnce(specContent);

      diff.mockReturnValue([]);

      mockOctokit.rest.issues.listComments.mockResolvedValue({ data: [] });
      mockOctokit.rest.issues.createComment.mockResolvedValue({ data: { id: 1 } });

      // Override default openapi-path to match the new file
      core.getInput.mockImplementation((name) => {
        const inputs = {
          'github-token': 'fake-token',
          'token': 'fake-token',
          'openapi_path': 'new-api.yaml',
          'sql_glob': '**/*.sql',
          'fail_on_medium': 'false',
          'override': 'false'
        };
        return inputs[name] || '';
      });

      await run();

      expect(core.info).toHaveBeenCalledWith('Detected OpenAPI spec rename: old-api.yaml → new-api.yaml');
    });

    test('should fail on medium severity when configured', async () => {
      core.getInput.mockImplementation((name) => {
        const inputs = {
          'github-token': 'fake-token',
          'token': 'fake-token',
          'openapi_path': 'openapi.yaml',
          'sql_glob': '**/*.sql',
          'fail_on_medium': 'true',
          'override': 'false'
        };
        return inputs[name] || '';
      });

      // Setup: Medium severity change (TYPE NARROWING)
      mockOctokit.rest.pulls.listFiles.mockResolvedValue({
        data: [{ filename: 'migrations/alter.sql', status: 'added' }]
      });

      mockOctokit.rest.repos.getContent.mockResolvedValue({
        data: { content: Buffer.from('ALTER COLUMN user_id TYPE INT;').toString('base64') }
      });

      mockOctokit.rest.issues.listComments.mockResolvedValue({ data: [] });
      mockOctokit.rest.issues.createComment.mockResolvedValue({ data: { id: 1 } });

      await run();

      // Should detect medium severity and fail when fail_on_medium is enabled
      expect(core.setFailed).toHaveBeenCalledWith(
        expect.stringContaining('Medium severity drift detected')
      );
    });

    test('should update existing comment instead of creating new one', async () => {
      const existingCommentId = 456;

      mockOctokit.rest.pulls.listFiles.mockResolvedValue({
        data: [{ filename: 'migrations/add.sql', status: 'added' }]
      });

      mockOctokit.rest.repos.getContent.mockResolvedValue({
        data: { content: Buffer.from('ALTER TABLE users ADD COLUMN name VARCHAR(100);').toString('base64') }
      });

      mockOctokit.rest.issues.listComments.mockResolvedValue({
        data: [
          { id: 1, body: 'Some other comment' },
          { id: existingCommentId, body: '<!-- driftcontrol:comment -->\nOld report' }
        ]
      });

      mockOctokit.rest.issues.updateComment.mockResolvedValue({
        data: { id: existingCommentId }
      });

      await run();

      expect(mockOctokit.rest.issues.updateComment).toHaveBeenCalledWith({
        owner: 'test-owner',
        repo: 'test-repo',
        comment_id: existingCommentId,
        body: expect.stringContaining('DriftControl Analysis')
      });
      expect(mockOctokit.rest.issues.createComment).not.toHaveBeenCalled();
      expect(core.info).toHaveBeenCalledWith('Updated existing DriftControl comment');
    });

    test('should handle GitHub API errors gracefully', async () => {
      mockOctokit.rest.pulls.listFiles.mockRejectedValue(new Error('GitHub API Error'));

      await run();

      expect(core.error).toHaveBeenCalledWith('Error: GitHub API Error');
      expect(core.setFailed).toHaveBeenCalledWith('GitHub API Error');
    });

    test('should skip DML-only SQL files', async () => {
      mockOctokit.rest.pulls.listFiles.mockResolvedValue({
        data: [{ filename: 'data/insert_users.sql', status: 'added' }]
      });

      mockOctokit.rest.repos.getContent.mockResolvedValue({
        data: { content: Buffer.from('INSERT INTO users (name) VALUES (\'John\');').toString('base64') }
      });

      mockOctokit.rest.issues.listComments.mockResolvedValue({ data: [] });
      mockOctokit.rest.issues.createComment.mockResolvedValue({ data: { id: 1 } });

      core.getInput.mockImplementation((name) => {
        const inputs = {
          'github-token': 'fake-token',
          'token': 'fake-token',
          'sql_glob': '**/*.sql'
        };
        return inputs[name] || '';
      });

      await run();

      expect(core.info).toHaveBeenCalledWith('Skipping DML-only migration: data/insert_users.sql');
      expect(core.info).toHaveBeenCalledWith('No drift detected');
    });
  });

  describe('Module Integration', () => {
    test('should integrate all modules correctly for complex scenario', async () => {
      const baseSpec = { openapi: '3.0.0', paths: { '/users': { get: {} } } };
      const headSpec = { openapi: '3.0.0', paths: { '/users': { get: {}, delete: {} } } };

      mockOctokit.rest.pulls.listFiles.mockResolvedValue({
        data: [
          { filename: 'migrations/001_drop_table.sql', status: 'added' },
          { filename: 'migrations/002_add_column.sql', status: 'added' },
          { filename: 'api.yaml', status: 'modified' }
        ]
      });

      // Mock file contents
      mockOctokit.rest.repos.getContent
        // First SQL file (high severity)
        .mockResolvedValueOnce({
          data: { content: Buffer.from('DROP TABLE old_users;').toString('base64') }
        })
        // Second SQL file (low severity)
        .mockResolvedValueOnce({
          data: { content: Buffer.from('ALTER TABLE users ADD COLUMN email VARCHAR(255);').toString('base64') }
        })
        // API base
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(baseSpec)).toString('base64') }
        })
        // API head
        .mockResolvedValueOnce({
          data: { content: Buffer.from(JSON.stringify(headSpec)).toString('base64') }
        });

      SwaggerParser.parse
        .mockResolvedValueOnce(baseSpec)
        .mockResolvedValueOnce(headSpec);

      diff.mockReturnValue([
        { type: 'removed', path: '/users.delete' } // This should be detected as breaking
      ]);

      mockOctokit.rest.issues.listComments.mockResolvedValue({ data: [] });
      mockOctokit.rest.issues.createComment.mockResolvedValue({ data: { id: 1 } });

      core.getInput.mockImplementation((name) => {
        const inputs = {
          'github-token': 'fake-token',
          'token': 'fake-token',
          'openapi_path': 'api.yaml',
          'sql_glob': '**/*.sql',
          'fail_on_medium': 'false',
          'override': 'false'
        };
        return inputs[name] || '';
      });

      await run();

      // Should detect multiple high severity issues - updated format includes breakdown
      expect(core.setFailed).toHaveBeenCalledWith(
        expect.stringContaining('High severity drift detected (2 total issues')
      );

      const createCommentCall = mockOctokit.rest.issues.createComment.mock.calls[0];
      const commentBody = createCommentCall[0].body;

      // Verify all drift types are included (actual output shows 2 high severity issues)
      expect(commentBody).toContain('2 drift issues detected');
      expect(commentBody).toContain('🔴 2 High severity');
      expect(commentBody).toContain('DROP TABLE: old_users');
      expect(commentBody).toContain('BREAKING_CHANGE');
      expect(commentBody).toContain('DATABASE Drift');
      expect(commentBody).toContain('API Drift');
    });

    test('should verify exported functions work correctly', () => {
      // Test that all exported functions are available
      expect(typeof run).toBe('function');
      expect(typeof generateCommentBody).toBe('function');
      expect(typeof generateFixSuggestion).toBe('function');
      expect(typeof postOrUpdateComment).toBe('function');
    });

    test('should handle missing required inputs gracefully', async () => {
      // Mock inputs to return empty, including token
      core.getInput.mockImplementation((name) => {
        return ''; // All inputs return empty string
      });
      
      // Remove environment token
      const originalToken = process.env.GITHUB_TOKEN;
      delete process.env.GITHUB_TOKEN;

      try {
        await run();
        expect(core.setFailed).toHaveBeenCalledWith('GITHUB_TOKEN is required');
      } finally {
        // Restore token for other tests
        if (originalToken) {
          process.env.GITHUB_TOKEN = originalToken;
        }
      }
    });

    test('should validate all components work with real-world data patterns', async () => {
      // Complex SQL with multiple operations
      const complexSql = `
        -- Drop old table
        DROP TABLE IF EXISTS legacy_users;
        
        -- Create new table with constraints
        CREATE TABLE users (
          id SERIAL PRIMARY KEY,
          email VARCHAR(255) NOT NULL UNIQUE,
          created_at TIMESTAMP DEFAULT NOW()
        );
        
        -- Add index
        CREATE INDEX idx_users_email ON users(email);
      `;

      const realWorldSpec = {
        openapi: '3.0.0',
        info: { title: 'User API', version: '2.0.0' },
        paths: {
          '/users': {
            get: { responses: { '200': { description: 'Users list' } } },
            post: { 
              requestBody: { 
                required: true,
                content: { 'application/json': { schema: { type: 'object' } } }
              }
            }
          },
          '/auth': {
            post: { responses: { '200': { description: 'Auth token' } } }
          }
        }
      };

      mockOctokit.rest.pulls.listFiles.mockResolvedValue({
        data: [{ filename: 'db/migrations/20231201_users.sql', status: 'added' }]
      });

      mockOctokit.rest.repos.getContent.mockResolvedValue({
        data: { content: Buffer.from(complexSql).toString('base64') }
      });

      mockOctokit.rest.issues.listComments.mockResolvedValue({ data: [] });
      mockOctokit.rest.issues.createComment.mockResolvedValue({ data: { id: 1 } });

      core.getInput.mockImplementation((name) => {
        const inputs = {
          'github-token': 'fake-token',
          'token': 'fake-token',
          'sql_glob': '**/*.sql',
          'fail_on_medium': 'false',
          'override': 'false'
        };
        return inputs[name] || '';
      });

      await run();

      // Should process complex SQL and identify high-risk operations
      expect(core.setFailed).toHaveBeenCalledWith(
        expect.stringContaining('High severity drift detected')
      );

      const commentCall = mockOctokit.rest.issues.createComment.mock.calls[0];
      const body = commentCall[0].body;
      
      expect(body).toContain('DROP TABLE: legacy_users');
      expect(body).toContain('Explanation');
      expect(body).toContain('Consider backing up data');
    });
  });
  
  describe('Correlation Analysis', () => {
    test('should detect API-database entity correlations with high confidence', () => {
      const apiResult = {
        type: 'api',
        file: 'api/users.js',
        endpoints: ['/users', '/users/{id}'],
        metadata: extractMetadata({ type: 'api', endpoints: ['/users'] }, [])
      };
      
      const dbResult = {
        type: 'database',
        entities: ['users'],
        changes: ['CREATE TABLE users (id INT, name VARCHAR(100))'],
        metadata: extractMetadata({ type: 'database', entities: ['users'] }, [])
      };
      
      // Test entity variation matching
      const apiEntity = 'users';
      const dbEntity = 'user'; // Singular form
      
      const apiVars = generateEntityVariations(apiEntity);
      const dbVars = generateEntityVariations(dbEntity);
      const match = findBestMatch(apiVars, dbVars);
      
      expect(match.confidence).toBeGreaterThan(0.8);
    });
    
    test('should detect operation correlations between API and database', () => {
      // API with CRUD operations
      const apiOps = detectApiOperations('/users', {
        changes: ['POST /users', 'GET /users', 'PUT /users/{id}', 'DELETE /users/{id}']
      });
      
      // Database with corresponding operations
      const dbOps = detectDbOperations('CREATE TABLE users; INSERT INTO users; SELECT FROM users; UPDATE users; DELETE FROM users;');
      
      expect(apiOps).toContain('create');
      expect(apiOps).toContain('read');
      expect(apiOps).toContain('update');
      expect(apiOps).toContain('delete');
      
      expect(dbOps).toContain('create');
      expect(dbOps).toContain('read');
      expect(dbOps).toContain('update');
      expect(dbOps).toContain('delete');
      
      expect(operationsCorrelate(apiOps, dbOps)).toBe(true);
    });
    
    test('should upgrade severity based on correlation impact', () => {
      const result = {
        type: 'api',
        file: 'api/users.js',
        severity: 'low',
        changes: ['API change']
      };
      
      const correlations = [
        { source: result, target: { file: 'db/users.sql' }, confidence: 0.9, relationship: 'api_uses_table' },
        { source: result, target: { file: 'config/db.js' }, confidence: 0.8, relationship: 'dependency' },
        { source: { file: 'package.json' }, target: result, confidence: 0.75, relationship: 'dependency_affects_api' }
      ];
      
      const riskScorer = require('../src/risk-scorer');
      riskScorer.assessCorrelationImpact(result, correlations);
      
      // Should upgrade from low to medium due to 2 components affected
      expect(result.severity).toBe('medium');
      expect(result.correlationImpact.cascade).toBe(2);
      expect(result.reasoning).toContainEqual(expect.stringContaining('cross-layer components'));
    });
    
    test('should handle complex entity name variations', () => {
      // Test various naming convention conversions
      const testCases = [
        { input: 'user_profiles', expected: ['user_profiles', 'user_profile', 'userprofiles'] },
        { input: 'UserProfile', expected: ['userprofile', 'userprofiles', 'user_profile'] },
        { input: 'tbl_users', expected: ['tbl_users', 'tbl_user', 'tblusers'] },
        { input: 'categories', expected: ['categories', 'category', 'categorie'] }
      ];
      
      testCases.forEach(({ input, expected }) => {
        const variations = generateEntityVariations(input);
        expected.forEach(exp => {
          expect(variations).toContain(exp);
        });
      });
    });
    
    test('should correctly identify root causes in correlation graph', () => {
      const result1 = { id: 1, type: 'configuration', file: 'package.json' };
      const result2 = { id: 2, type: 'api', file: 'api/users.js' };
      const result3 = { id: 3, type: 'database', file: 'db/migrations/001.sql' };
      
      const correlations = [
        { source: result1, target: result2, confidence: 0.8 }, // package affects API
        { source: result1, target: result3, confidence: 0.7 }, // package affects DB
        { source: result2, target: result3, confidence: 0.9 }  // API relates to DB
      ];
      
      const rootCauses = identifyRootCauses(correlations, [result1, result2, result3]);
      
      // result1 (package.json) should be identified as root cause (only outgoing edges)
      expect(rootCauses).toHaveLength(1);
      expect(rootCauses[0].result).toBe(result1);
      expect(rootCauses[0].type).toBe('root_cause');
    });
    
    test('should apply user-defined correlation rules with confidence 1.0', async () => {
      const { correlateAcrossLayers } = require('../src/index');
      
      const driftResults = [
        { type: 'api', file: 'api/users.yml', endpoints: ['/v1/users/{userId}'], metadata: { entities: ['users'] } },
        { type: 'database', file: 'migrations/001.sql', entities: ['application_users'], changes: ['CREATE TABLE application_users'] }
      ];
      
      const correlationConfig = {
        correlationRules: [
          {
            type: 'api_to_db',
            source: '/v1/users/{userId}',
            apiRoute: '/v1/users/{userId}', // Add apiRoute for matching
            target: 'application_users',
            description: 'User API to DB mapping',
            confidence: 1.0,
            userDefined: true
          }
        ]
      };
      
      const correlations = await correlateAcrossLayers(driftResults, [], correlationConfig);
      
      // Should find the user-defined correlation
      const userDefinedCorr = correlations.find(c => c.userDefined);
      expect(userDefinedCorr).toBeDefined();
      expect(userDefinedCorr.confidence).toBe(1.0);
      expect(userDefinedCorr.relationship).toBe('api_to_db');
    });
    
    test('should ignore specified correlation pairs', async () => {
      const { correlateAcrossLayers } = require('../src/index');
      
      const driftResults = [
        { type: 'configuration', file: 'package-lock.json', changes: ['Dependencies updated'] },
        { type: 'api', file: 'openapi.yml', changes: ['API spec updated'] }
      ];
      
      const correlationConfig = {
        correlationRules: [
          {
            type: 'ignore',
            source: 'package-lock.json',
            target: 'openapi.yml',
            reason: 'Dependency updates rarely affect API',
            confidence: 1.0,
            userDefined: true
          }
        ]
      };
      
      const correlations = await correlateAcrossLayers(driftResults, [], correlationConfig);
      
      // Should not create correlation for ignored pair
      const ignoredCorr = correlations.find(c => 
        c.source.file === 'package-lock.json' && c.target.file === 'openapi.yml'
      );
      expect(ignoredCorr).toBeUndefined();
    });
    
    test('should upgrade severity for user-defined correlations', () => {
      const riskScorer = require('../src/risk-scorer');
      
      const result = {
        type: 'api',
        file: 'api/users.yml',
        severity: 'low',
        changes: ['API endpoint modified']
      };
      
      const correlations = [
        {
          source: result,
          target: { file: 'db/users.sql' },
          confidence: 1.0,
          userDefined: true,
          relationship: 'api_to_db',
          rule: { description: 'Critical user data correlation' }
        }
      ];
      
      riskScorer.assessCorrelationImpact(result, correlations);
      
      // Should upgrade severity due to user-defined correlation
      expect(result.severity).toBe('medium');
      expect(result.reasoning).toContainEqual(expect.stringContaining('user-defined correlation'));
    });
  });
});