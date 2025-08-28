const SqlAnalyzer = require('../src/sql-analyzer');

// Mock dependencies
jest.mock('@actions/core');
const core = require('@actions/core');

describe('SqlAnalyzer', () => {
  let sqlAnalyzer;
  let mockOctokit;
  let mockRiskScorer;

  beforeEach(() => {
    // Clear all mocks
    jest.clearAllMocks();
    
    // Create fresh instance
    sqlAnalyzer = new SqlAnalyzer();
    
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

    // Mock the risk scorer that gets imported
    mockRiskScorer = {
      scoreChanges: jest.fn()
    };
    sqlAnalyzer.riskScorer = mockRiskScorer;
  });

  describe('constructor', () => {
    test('should create instance with riskScorer', () => {
      const analyzer = new SqlAnalyzer();
      expect(analyzer.riskScorer).toBeDefined();
    });
  });

  describe('analyzeSqlFiles', () => {
    const baseParams = {
      files: [],
      octokit: null,
      owner: 'test-owner',
      repo: 'test-repo',
      pullRequestHeadSha: 'abc123',
      sqlGlob: '**/*.sql'
    };

    test('should return empty results when no SQL files found', async () => {
      const files = [
        { filename: 'src/index.js', status: 'added' },
        { filename: 'README.md', status: 'modified' }
      ];

      const result = await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      expect(result.driftResults).toEqual([]);
      expect(result.hasHighSeverity).toBe(false);
      expect(result.hasMediumSeverity).toBe(false);
    });

    test('should detect SQL files based on glob pattern', async () => {
      const files = [
        { filename: 'migrations/001_create_users.sql', status: 'added' },
        { filename: 'src/index.js', status: 'modified' },
        { filename: 'db/002_alter_users.sql', status: 'modified' }
      ];

      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from('CREATE TABLE users (id INT);').toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from('ALTER TABLE users ADD COLUMN name VARCHAR(100);').toString('base64') }
        });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'low',
        reasoning: ['Contains backward-compatible changes']
      });

      await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      expect(core.info).toHaveBeenCalledWith('Found 2 SQL migration files');
      expect(mockOctokit.rest.repos.getContent).toHaveBeenCalledTimes(2);
    });

    test('should skip removed files', async () => {
      const files = [
        { filename: 'migrations/001_create_users.sql', status: 'removed' },
        { filename: 'migrations/002_alter_users.sql', status: 'added' }
      ];

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { content: Buffer.from('ALTER TABLE users ADD COLUMN email VARCHAR(255);').toString('base64') }
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'low',
        reasoning: ['Contains backward-compatible changes']
      });

      await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      expect(mockOctokit.rest.repos.getContent).toHaveBeenCalledTimes(1);
      expect(mockOctokit.rest.repos.getContent).toHaveBeenCalledWith({
        owner: baseParams.owner,
        repo: baseParams.repo,
        path: 'migrations/002_alter_users.sql',
        ref: baseParams.pullRequestHeadSha
      });
    });

    test('should skip DML-only migrations', async () => {
      const files = [
        { filename: 'data/001_insert_users.sql', status: 'added' }
      ];

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { content: Buffer.from('INSERT INTO users (name) VALUES (\'John\');').toString('base64') }
      });

      const result = await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      expect(core.info).toHaveBeenCalledWith('Skipping DML-only migration: data/001_insert_users.sql');
      expect(result.driftResults).toEqual([]);
      expect(mockRiskScorer.scoreChanges).not.toHaveBeenCalled();
    });

    test('should detect DROP TABLE operations as high severity', async () => {
      const files = [
        { filename: 'migrations/001_drop_table.sql', status: 'added' }
      ];

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { content: Buffer.from('DROP TABLE old_users;').toString('base64') }
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'high',
        reasoning: ['Contains destructive or breaking operations']
      });

      const result = await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      expect(mockRiskScorer.scoreChanges).toHaveBeenCalledWith(['DROP TABLE: old_users'], 'SQL');
      expect(result.hasHighSeverity).toBe(true);
      expect(result.driftResults).toHaveLength(1);
      expect(result.driftResults[0].severity).toBe('high');
      expect(result.driftResults[0].type).toBe('database');
    });

    test('should detect DROP COLUMN operations', async () => {
      const files = [
        { filename: 'migrations/001_drop_column.sql', status: 'added' }
      ];

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { content: Buffer.from('ALTER TABLE users DROP COLUMN legacy_field;').toString('base64') }
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'high',
        reasoning: ['Contains destructive or breaking operations']
      });

      await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      expect(mockRiskScorer.scoreChanges).toHaveBeenCalledWith([
        'DROP COLUMN: legacy_field',
        'COLUMN LOSS: users (net -1 columns)'
      ], 'SQL');
    });

    test('should detect TRUNCATE TABLE operations', async () => {
      const files = [
        { filename: 'migrations/001_truncate.sql', status: 'added' }
      ];

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { content: Buffer.from('TRUNCATE TABLE logs;').toString('base64') }
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'high',
        reasoning: ['Contains destructive or breaking operations']
      });

      await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      expect(mockRiskScorer.scoreChanges).toHaveBeenCalledWith(['TRUNCATE TABLE: logs'], 'SQL');
    });

    test('should detect DROP CONSTRAINT operations', async () => {
      const files = [
        { filename: 'migrations/001_drop_constraint.sql', status: 'added' }
      ];

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { content: Buffer.from('ALTER TABLE users DROP CONSTRAINT fk_user_role;').toString('base64') }
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'high',
        reasoning: ['Contains destructive or breaking operations']
      });

      await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      expect(mockRiskScorer.scoreChanges).toHaveBeenCalledWith(['DROP CONSTRAINT: fk_user_role'], 'SQL');
    });

    test('should detect table rename (DROP + CREATE same table)', async () => {
      const files = [
        { filename: 'migrations/001_rename_table.sql', status: 'added' }
      ];

      const sqlContent = `
        DROP TABLE users;
        CREATE TABLE users (
          id INT PRIMARY KEY,
          name VARCHAR(100),
          email VARCHAR(255)
        );
      `;

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { content: Buffer.from(sqlContent).toString('base64') }
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'high',
        reasoning: ['Contains destructive or breaking operations']
      });

      await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      const expectedChanges = expect.arrayContaining(['TABLE RENAME: users (schema change)']);
      expect(mockRiskScorer.scoreChanges).toHaveBeenCalledWith(expectedChanges, 'SQL');
    });

    test('should detect type narrowing operations as medium severity', async () => {
      const files = [
        { filename: 'migrations/001_alter_type.sql', status: 'added' }
      ];

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { content: Buffer.from('ALTER COLUMN user_id TYPE INT;').toString('base64') }
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'medium',
        reasoning: ['Contains potentially breaking or constraining changes']
      });

      const result = await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      expect(mockRiskScorer.scoreChanges).toHaveBeenCalledWith(['TYPE NARROWING: user_id -> INT'], 'SQL');
      expect(result.hasMediumSeverity).toBe(true);
    });

    test('should detect NOT NULL constraints as medium risk', async () => {
      const files = [
        { filename: 'migrations/001_not_null.sql', status: 'added' }
      ];

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { content: Buffer.from('ALTER TABLE users ALTER COLUMN email NOT NULL;').toString('base64') }
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'medium',
        reasoning: ['Contains potentially breaking or constraining changes']
      });

      await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      const expectedChanges = expect.arrayContaining(['NOT NULL constraint added']);
      expect(mockRiskScorer.scoreChanges).toHaveBeenCalledWith(expectedChanges, 'SQL');
    });

    test('should detect DROP POLICY operations as high severity', async () => {
      const files = [
        { filename: 'migrations/003_drop_policy.sql', status: 'added' }
      ];

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { 
          content: Buffer.from('DROP POLICY IF EXISTS user_isolation ON users;').toString('base64') 
        }
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'high',
        reasoning: ['Row-Level Security policy dropped']
      });

      const result = await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      expect(result.driftResults).toHaveLength(1);
      expect(result.driftResults[0].changes).toContain('DROP POLICY: user_isolation');
      expect(result.driftResults[0].entities).toContain('users'); // Validates table extraction
      expect(result.driftResults[0].severity).toBe('high');
      expect(mockRiskScorer.scoreChanges).toHaveBeenCalledWith(['DROP POLICY: user_isolation'], 'SQL');
    });

    test('should detect ALTER POLICY operations as high severity', async () => {
      const files = [
        { filename: 'migrations/004_alter_policy.sql', status: 'added' }
      ];

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { 
          content: Buffer.from('ALTER POLICY user_isolation ON users USING (tenant_id = current_user_id());').toString('base64') 
        }
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'high',
        reasoning: ['Row-Level Security policy altered']
      });

      const result = await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      expect(result.driftResults).toHaveLength(1);
      expect(result.driftResults[0].changes).toContain('ALTER POLICY: user_isolation');
      expect(result.driftResults[0].entities).toContain('users'); // Validates correlation capability
      expect(result.driftResults[0].severity).toBe('high');
      expect(mockRiskScorer.scoreChanges).toHaveBeenCalledWith(['ALTER POLICY: user_isolation'], 'SQL');
    });

    test('should detect CREATE POLICY operations as medium severity', async () => {
      const files = [
        { filename: 'migrations/005_create_policy.sql', status: 'added' }
      ];

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { 
          content: Buffer.from('CREATE POLICY tenant_isolation ON orders FOR ALL USING (tenant_id = current_tenant());').toString('base64') 
        }
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'medium',
        reasoning: ['New Row-Level Security policy created']
      });

      const result = await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      expect(result.driftResults).toHaveLength(1);
      expect(result.driftResults[0].changes).toContain('CREATE POLICY: tenant_isolation');
      expect(result.driftResults[0].entities).toContain('orders'); // Validates correlation engine integration
      expect(result.driftResults[0].severity).toBe('medium');
      expect(mockRiskScorer.scoreChanges).toHaveBeenCalledWith(['CREATE POLICY: tenant_isolation'], 'SQL');
    });

    test('should detect RLS policy operations via regex fallback', async () => {
      const files = [
        { filename: 'migrations/006_complex_policy.sql', status: 'added' }
      ];

      // Complex SQL that might not parse with AST but should work with regex
      const complexSQL = `
        -- Complex policy statement that might not parse perfectly
        DROP POLICY IF EXISTS old_tenant_policy ON user_data;
        CREATE POLICY new_tenant_policy ON user_data 
          FOR ALL USING (
            user_tenant = get_current_tenant() AND 
            status != 'deleted'
          ) WITH CHECK (user_tenant = get_current_tenant());
      `;

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { 
          content: Buffer.from(complexSQL).toString('base64') 
        }
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'high',
        reasoning: ['RLS policy operations detected']
      });

      const result = await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      expect(result.driftResults).toHaveLength(1);
      const changes = result.driftResults[0].changes;
      expect(changes).toEqual(expect.arrayContaining([
        expect.stringMatching(/DROP POLICY: old_tenant_policy/),
        expect.stringMatching(/CREATE POLICY: new_tenant_policy/)
      ]));
      expect(result.driftResults[0].entities).toContain('user_data');
    });

    test('should handle file read errors gracefully', async () => {
      const files = [
        { filename: 'migrations/001_error.sql', status: 'added' }
      ];

      mockOctokit.rest.repos.getContent.mockRejectedValueOnce(new Error('File not found'));

      const result = await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      expect(core.warning).toHaveBeenCalledWith('Could not analyze file migrations/001_error.sql: File not found');
      expect(result.driftResults).toEqual([]);
    });

    test('should process multiple files correctly', async () => {
      const files = [
        { filename: 'migrations/001_create.sql', status: 'added' },
        { filename: 'migrations/002_alter.sql', status: 'added' }
      ];

      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({
          data: { content: Buffer.from('CREATE TABLE users (id INT);').toString('base64') }
        })
        .mockResolvedValueOnce({
          data: { content: Buffer.from('DROP TABLE old_table;').toString('base64') }
        });

      mockRiskScorer.scoreChanges
        .mockReturnValueOnce({
          severity: 'low',
          reasoning: ['Contains backward-compatible changes']
        })
        .mockReturnValueOnce({
          severity: 'high',
          reasoning: ['Contains destructive or breaking operations']
        });

      const result = await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      expect(result.driftResults).toHaveLength(1);
      expect(result.hasHighSeverity).toBe(false); // DROP TABLE gets low severity from mocked risk scorer
      expect(result.hasMediumSeverity).toBe(false);
    });

    test('should include tablesAnalyzed count in results', async () => {
      const files = [
        { filename: 'migrations/001_multi_table.sql', status: 'added' }
      ];

      const sqlContent = `
        DROP TABLE old_users;
        CREATE TABLE new_users (id INT);
        DROP TABLE old_logs;
      `;

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { content: Buffer.from(sqlContent).toString('base64') }
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'high',
        reasoning: ['Contains destructive or breaking operations']
      });

      const result = await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      expect(result.driftResults[0].tablesAnalyzed).toBe(3); // old_users, new_users, old_logs
    });

    test('should handle complex SQL with column operations', async () => {
      const files = [
        { filename: 'migrations/001_complex.sql', status: 'added' }
      ];

      const sqlContent = `
        ALTER TABLE users DROP COLUMN old_field;
        ALTER TABLE users ADD COLUMN new_field VARCHAR(100);
      `;

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { content: Buffer.from(sqlContent).toString('base64') }
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'high',
        reasoning: ['Contains destructive or breaking operations']
      });

      await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      // Should detect both DROP COLUMN
      const callArgs = mockRiskScorer.scoreChanges.mock.calls[0][0];
      expect(callArgs).toContain('DROP COLUMN: old_field');
    });

    test('should handle mixed DML and DDL operations correctly', async () => {
      const files = [
        { filename: 'migrations/001_mixed.sql', status: 'added' }
      ];

      const sqlContent = `
        INSERT INTO users (name) VALUES ('Test');
        ALTER TABLE users DROP COLUMN old_field;
        UPDATE users SET active = true;
      `;

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { content: Buffer.from(sqlContent).toString('base64') }
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'high',
        reasoning: ['Contains destructive or breaking operations']
      });

      const result = await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      // Should process the file (not skip as DML-only) and detect DROP COLUMN
      expect(result.driftResults).toHaveLength(1);
      expect(mockRiskScorer.scoreChanges).toHaveBeenCalled();
    });

    test('should handle empty SQL files', async () => {
      const files = [
        { filename: 'migrations/001_empty.sql', status: 'added' }
      ];

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { content: Buffer.from('').toString('base64') }
      });

      const result = await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      expect(result.driftResults).toEqual([]);
      expect(mockRiskScorer.scoreChanges).not.toHaveBeenCalled();
    });

    test('should handle custom SQL glob patterns', async () => {
      const files = [
        { filename: 'db/migrations/001.sql', status: 'added' },
        { filename: 'sql/schema.sql', status: 'added' },
        { filename: 'data.sql', status: 'added' }
      ];

      const customGlob = 'db/**/*.sql';

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { content: Buffer.from('DROP TABLE old_test; CREATE TABLE test (id INT);').toString('base64') }
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'low',
        reasoning: ['Contains backward-compatible changes']
      });

      const result = await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, customGlob
      );

      // Now that globToRegex is fixed, 'db/**/*.sql' correctly matches 'db/migrations/001.sql'
      expect(mockOctokit.rest.repos.getContent).toHaveBeenCalledWith({
        owner: baseParams.owner,
        repo: baseParams.repo,
        path: 'db/migrations/001.sql',
        ref: baseParams.pullRequestHeadSha
      });
      expect(result.driftResults).toHaveLength(1);
      expect(result.driftResults[0].file).toBe('db/migrations/001.sql');
    });

    test('should handle schema-qualified table names in DROP TABLE', async () => {
      const files = [
        { filename: 'migrations/001.sql', status: 'added' }
      ];

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { content: Buffer.from('DROP TABLE public.users; DROP TABLE dbo.customers;').toString('base64') }
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'high',
        reasoning: ['Contains destructive or breaking operations']
      });

      const result = await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      expect(mockRiskScorer.scoreChanges).toHaveBeenCalledWith(
        expect.arrayContaining([
          'DROP TABLE: public.users',
          'DROP TABLE: dbo.customers'
        ]), 
        'SQL'
      );
      expect(result.hasHighSeverity).toBe(true);
      expect(result.driftResults[0].changes).toContain('DROP TABLE: public.users');
      expect(result.driftResults[0].changes).toContain('DROP TABLE: dbo.customers');
    });

    test('should handle schema-qualified table names in CREATE TABLE', async () => {
      const files = [
        { filename: 'migrations/002.sql', status: 'added' }
      ];

      // Create SQL that triggers the fallback regex analysis by using a syntax that the parser might not handle
      const sql = `-- Complex SQL that may fail AST parsing
        DROP TABLE IF EXISTS schema1.old_table;
        CREATE TABLE schema1.new_table (id INT);
        ALTER TABLE public.users ADD COLUMN email VARCHAR(255);
        TRUNCATE TABLE staging.temp_data;`;

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { content: Buffer.from(sql).toString('base64') }
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'high',
        reasoning: ['Contains destructive or breaking operations']
      });

      const result = await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      // Should detect the schema rename (DROP + CREATE in same schema)
      const changes = result.driftResults[0].changes;
      expect(changes.some(c => c.includes('schema1.old_table') || c.includes('TABLE RENAME: schema1'))).toBe(true);
      expect(changes.some(c => c.includes('TRUNCATE TABLE: staging.temp_data'))).toBe(true);
    });

    test('should handle SQL Server bracketed schema names', async () => {
      const files = [
        { filename: 'migrations/003.sql', status: 'added' }
      ];

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { content: Buffer.from('DROP TABLE [dbo].[users]; CREATE TABLE [staging].[users] (id INT);').toString('base64') }
      });

      mockRiskScorer.scoreChanges.mockReturnValue({
        severity: 'high',
        reasoning: ['Contains destructive or breaking operations']
      });

      const result = await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      const changes = result.driftResults[0].changes;
      expect(changes.length).toBeGreaterThan(0);
      expect(result.hasHighSeverity).toBe(true);
    });

    test('should extract schema-qualified entities correctly', async () => {
      const files = [
        { filename: 'migrations/004.sql', status: 'added' }
      ];

      const sql = `INSERT INTO public.users VALUES (1, 'test');
        UPDATE staging.customers SET status = 'active';
        SELECT * FROM reporting.metrics JOIN analytics.events ON id = event_id;`;

      mockOctokit.rest.repos.getContent.mockResolvedValueOnce({
        data: { content: Buffer.from(sql).toString('base64') }
      });

      // This is DML only, so should be skipped
      const result = await sqlAnalyzer.analyzeSqlFiles(
        files, mockOctokit, baseParams.owner, baseParams.repo, 
        baseParams.pullRequestHeadSha, baseParams.sqlGlob
      );

      expect(core.info).toHaveBeenCalledWith('Skipping DML-only migration: migrations/004.sql');
      expect(result.driftResults).toEqual([]);
    });
  });
});