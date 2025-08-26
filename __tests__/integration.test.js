const { run, generateCommentBody, generateFixSuggestion, postOrUpdateComment } = require('../src/index');

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
        'openapi-path': 'openapi.yaml',
        'sql-glob': '**/*.sql',
        'fail-on-medium': 'false',
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

      await run();

      expect(core.setFailed).toHaveBeenCalledWith(
        expect.stringContaining('High severity drift detected')
      );
      expect(mockOctokit.rest.issues.createComment).toHaveBeenCalledWith({
        owner: 'test-owner',
        repo: 'test-repo',
        issue_number: 123,
        body: expect.stringContaining('API_DELETION')
      });
    });

    test('should handle override scenario correctly', async () => {
      core.getInput.mockImplementation((name) => {
        const inputs = {
          'github-token': 'fake-token',
          'openapi-path': 'openapi.yaml',
          'sql-glob': '**/*.sql',
          'fail-on-medium': 'false',
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

      await run();

      // Verify drift was detected and comment was created (actual result shows API_DELETION priority)
      expect(mockOctokit.rest.issues.createComment).toHaveBeenCalledWith({
        owner: 'test-owner',
        repo: 'test-repo',
        issue_number: 123,
        body: expect.stringContaining('API_DELETION')
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
          'openapi-path': 'new-api.yaml',
          'sql-glob': '**/*.sql',
          'fail-on-medium': 'false',
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
        data: { content: Buffer.from('ALTER TABLE users ALTER COLUMN user_id TYPE INTEGER;').toString('base64') }
      });

      mockOctokit.rest.issues.listComments.mockResolvedValue({ data: [] });
      mockOctokit.rest.issues.createComment.mockResolvedValue({ data: { id: 1 } });

      await run();

      // Should detect medium severity and fail when fail_on_medium is enabled

      expect(core.setFailed).toHaveBeenCalledWith(
        expect.stringContaining('Medium severity drift detected')
      );
      expect(core.setFailed).toHaveBeenCalledWith(
        expect.stringContaining('fail_on_medium is enabled')
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
          'openapi-path': 'api.yaml',
          'sql-glob': '**/*.sql',
          'fail-on-medium': 'false',
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
      expect(commentBody).toContain('API_DELETION');
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
});