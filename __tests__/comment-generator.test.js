const { generateCommentBody, generateFixSuggestion } = require('../src/comment-generator');

// Mock Date for consistent timestamps in tests
const mockDate = new Date('2023-01-01T12:00:00.000Z');
global.Date = jest.fn(() => mockDate);
Date.now = jest.fn(() => mockDate.getTime());

describe('Comment Generator', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('generateCommentBody', () => {
    test('should generate basic comment with no issues', async () => {
      const driftResults = [];
      const isOverride = false;

      const result = await generateCommentBody(driftResults, isOverride);

      expect(result).toContain('<!-- driftcontrol:comment -->');
      expect(result).toContain('## 🔍 DriftControl Analysis Report');
      expect(result).toContain('**Summary**: 0 drift issues detected');
      expect(result).toContain('📊 *Analysis completed at 2023-01-01T12:00:00.000Z*');
    });

    test('should include override notice when override is active', async () => {
      const driftResults = [];
      const isOverride = true;

      const result = await generateCommentBody(driftResults, isOverride);

      expect(result).toContain('⚠️ **Policy Override Active**');
      expect(result).toContain('Drift detected but merge allowed with audit trail');
    });

    test('should generate summary with correct counts', async () => {
      const driftResults = [
        { severity: 'high', type: 'database', file: 'test1.sql', changes: ['DROP TABLE'], reasoning: ['High risk'] },
        { severity: 'high', type: 'api', file: 'test2.yaml', changes: ['API_DELETION'], reasoning: ['High risk'] },
        { severity: 'medium', type: 'database', file: 'test3.sql', changes: ['TYPE NARROWING'], reasoning: ['Medium risk'] },
        { severity: 'low', type: 'api', file: 'test4.yaml', changes: ['New field'], reasoning: ['Low risk'] }
      ];

      const result = await generateCommentBody(driftResults, false);

      expect(result).toContain('**Summary**: 4 drift issues detected');
      expect(result).toContain('🔴 2 High severity');
      expect(result).toContain('🟡 1 Medium severity');
      expect(result).toContain('🟢 1 Low severity');
    });

    test('should use singular form for single issue', async () => {
      const driftResults = [
        { severity: 'high', type: 'database', file: 'test.sql', changes: ['DROP TABLE'], reasoning: ['High risk'] }
      ];

      const result = await generateCommentBody(driftResults, false);

      expect(result).toContain('**Summary**: 1 drift issue detected');
    });

    test('should generate collapsible sections for each severity', async () => {
      const driftResults = [
        { severity: 'high', type: 'database', file: 'migrations/001.sql', changes: ['DROP TABLE users'], reasoning: ['Destructive operation'] },
        { severity: 'medium', type: 'api', file: 'openapi.yaml', changes: ['REQUIRED field'], reasoning: ['Potentially breaking'] }
      ];

      const result = await generateCommentBody(driftResults, false);

      expect(result).toContain('<details>');
      expect(result).toContain('<summary><strong>🔴 HIGH Severity Issues (1)</strong></summary>');
      expect(result).toContain('<summary><strong>🟡 MEDIUM Severity Issues (1)</strong></summary>');
      expect(result).toContain('</details>');
    });

    test('should include file context and metadata', async () => {
      const driftResults = [
        {
          severity: 'high',
          type: 'database',
          file: 'migrations/001.sql',
          changes: ['DROP TABLE users'],
          reasoning: ['Destructive operation'],
          tablesAnalyzed: 3,
          renamed: { from: 'old.sql', to: 'migrations/001.sql' }
        }
      ];

      const result = await generateCommentBody(driftResults, false);

      expect(result).toContain('#### DATABASE Drift: `migrations/001.sql`');
      expect(result).toContain('📋 **Context**: Renamed from `old.sql` • Analyzed 3 table(s)');
    });

    test('should include fix suggestions for each change', async () => {
      const driftResults = [
        {
          severity: 'high',
          type: 'database',
          file: 'test.sql',
          changes: ['DROP TABLE users', 'TRUNCATE TABLE logs'],
          reasoning: ['Destructive operations']
        }
      ];

      const result = await generateCommentBody(driftResults, false);

      expect(result).toContain('- DROP TABLE users');
      expect(result).toContain('💡 **Fix suggestion**: Consider backing up data before dropping tables');
      expect(result).toContain('- TRUNCATE TABLE logs');
      expect(result).toContain('💡 **Fix suggestion**: Verify this is intentional data loss');
    });

    test('should show risk assessment reasoning', async () => {
      const driftResults = [
        {
          severity: 'medium',
          type: 'api',
          file: 'openapi.yaml',
          changes: ['REQUIRED field added'],
          reasoning: ['Contains potentially breaking changes', 'New constraints added']
        }
      ];

      const result = await generateCommentBody(driftResults, false);

      expect(result).toContain('🎯 **Risk Assessment**: Contains potentially breaking changes, New constraints added');
    });

    test('should display override information when present', async () => {
      const driftResults = [
        {
          severity: 'high',
          type: 'database',
          file: 'test.sql',
          changes: ['DROP TABLE users'],
          reasoning: ['Destructive operation'],
          override: {
            applied: true,
            reason: 'Emergency hotfix approved by CTO',
            originalSeverity: 'high',
            timestamp: '2023-01-01T10:00:00.000Z'
          }
        }
      ];

      const result = await generateCommentBody(driftResults, false);

      expect(result).toContain('⚠️ **Override Applied**: Emergency hotfix approved by CTO');
      expect(result).toContain('📅 *Original severity: high • 2023-01-01T10:00:00.000Z*');
    });

    test('should include merge blocking notice for high severity', async () => {
      const driftResults = [
        { severity: 'high', type: 'database', file: 'test.sql', changes: ['DROP TABLE'], reasoning: ['High risk'] }
      ];

      const result = await generateCommentBody(driftResults, false);

      expect(result).toContain('**Merge Blocked**: High severity drift detected');
      expect(result).toContain('To override this block, comment `/driftcontrol override: <reason>` on this PR');
    });

    test('should not show merge blocking notice when override is active', async () => {
      const driftResults = [
        { severity: 'high', type: 'database', file: 'test.sql', changes: ['DROP TABLE'], reasoning: ['High risk'] }
      ];

      const result = await generateCommentBody(driftResults, true);

      expect(result).not.toContain('**Merge Blocked**');
      expect(result).not.toContain('To override this block');
    });

    test('should handle empty changes array', async () => {
      const driftResults = [
        {
          severity: 'low',
          type: 'api',
          file: 'openapi.yaml',
          changes: [],
          reasoning: ['No specific changes detected']
        }
      ];

      const result = await generateCommentBody(driftResults, false);

      expect(result).toContain('#### API Drift: `openapi.yaml`');
      expect(result).toContain('🎯 **Risk Assessment**: No specific changes detected');
    });

    test('should handle missing reasoning array', async () => {
      const driftResults = [
        {
          severity: 'low',
          type: 'api',
          file: 'openapi.yaml',
          changes: ['New endpoint added']
        }
      ];

      const result = await generateCommentBody(driftResults, false);

      expect(result).toContain('- New endpoint added');
      expect(result).not.toContain('🎯 **Risk Assessment**');
    });

    test('should handle all severity levels in correct order', async () => {
      const driftResults = [
        { severity: 'low', type: 'api', file: 'low.yaml', changes: ['Minor change'], reasoning: ['Low risk'] },
        { severity: 'high', type: 'database', file: 'high.sql', changes: ['DROP TABLE'], reasoning: ['High risk'] },
        { severity: 'medium', type: 'api', file: 'medium.yaml', changes: ['REQUIRED field'], reasoning: ['Medium risk'] }
      ];

      const result = await generateCommentBody(driftResults, false);

      // Check that sections appear in high -> medium -> low order
      const highIndex = result.indexOf('HIGH Severity Issues');
      const mediumIndex = result.indexOf('MEDIUM Severity Issues');
      const lowIndex = result.indexOf('LOW Severity Issues');

      expect(highIndex).toBeLessThan(mediumIndex);
      expect(mediumIndex).toBeLessThan(lowIndex);
    });

    test('should skip severity sections with no issues', async () => {
      const driftResults = [
        { severity: 'high', type: 'database', file: 'test.sql', changes: ['DROP TABLE'], reasoning: ['High risk'] }
      ];

      const result = await generateCommentBody(driftResults, false);

      expect(result).toContain('HIGH Severity Issues (1)');
      expect(result).not.toContain('MEDIUM Severity Issues');
      expect(result).not.toContain('LOW Severity Issues');
    });

    test('should format database vs API drift differently', async () => {
      const driftResults = [
        { severity: 'high', type: 'database', file: 'db.sql', changes: ['DROP TABLE'], reasoning: ['DB risk'] },
        { severity: 'high', type: 'api', file: 'api.yaml', changes: ['API_DELETION'], reasoning: ['API risk'] }
      ];

      const result = await generateCommentBody(driftResults, false);

      expect(result).toContain('#### DATABASE Drift: `db.sql`');
      expect(result).toContain('#### API Drift: `api.yaml`');
    });

    test('should handle metadata conditionally', async () => {
      const driftResults = [
        {
          severity: 'low',
          type: 'database',
          file: 'test1.sql',
          changes: ['ADD COLUMN'],
          reasoning: ['Low risk'],
          tablesAnalyzed: 2
        },
        {
          severity: 'low',
          type: 'api',
          file: 'test2.yaml',
          changes: ['New endpoint'],
          reasoning: ['Low risk'],
          renamed: { from: 'old.yaml', to: 'test2.yaml' }
        },
        {
          severity: 'low',
          type: 'api',
          file: 'test3.yaml',
          changes: ['New field'],
          reasoning: ['Low risk']
        }
      ];

      const result = await generateCommentBody(driftResults, false);

      expect(result).toContain('Analyzed 2 table(s)');
      expect(result).toContain('Renamed from `old.yaml`');
      // Third result should not have context section since no metadata
      const test3Index = result.indexOf('test3.yaml');
      const contextAfterTest3 = result.substring(test3Index).indexOf('📋 **Context**');
      expect(contextAfterTest3).toBe(-1);
    });
  });

  describe('generateFixSuggestion', () => {
    test('should return database DROP TABLE suggestion', () => {
      const result = generateFixSuggestion('DROP TABLE users', 'database', 'high');
      expect(result).toContain('Consider backing up data before dropping tables');
      expect(result).toContain('CREATE TABLE ... AS SELECT');
    });

    test('should return database DROP COLUMN suggestion', () => {
      const result = generateFixSuggestion('DROP COLUMN name', 'database', 'high');
      expect(result).toContain('Create a backup of affected data');
      expect(result).toContain('Consider deprecating the column first');
    });

    test('should return database COLUMN LOSS suggestion', () => {
      const result = generateFixSuggestion('COLUMN LOSS detected', 'database', 'high');
      expect(result).toContain('Review if dropped columns contain important data');
      expect(result).toContain('Add data migration script');
    });

    test('should return database TYPE NARROWING suggestion', () => {
      const result = generateFixSuggestion('TYPE NARROWING: varchar to int', 'database', 'medium');
      expect(result).toContain('Validate existing data compatibility');
      expect(result).toContain('Add data cleaning script');
    });

    test('should return database NOT NULL suggestion', () => {
      const result = generateFixSuggestion('NOT NULL constraint added', 'database', 'medium');
      expect(result).toContain('Ensure all existing rows have values');
      expect(result).toContain('Add default values');
    });

    test('should return database TRUNCATE TABLE suggestion', () => {
      const result = generateFixSuggestion('TRUNCATE TABLE logs', 'database', 'high');
      expect(result).toContain('Verify this is intentional data loss');
      expect(result).toContain('Consider using DELETE with WHERE clause');
    });

    test('should return API BREAKING_CHANGE suggestion', () => {
      const result = generateFixSuggestion('BREAKING_CHANGE: removed endpoint', 'api', 'high');
      expect(result).toContain('Implement API versioning (v1, v2)');
      expect(result).toContain('Add deprecation notices');
    });

    test('should return API REMOVED suggestion', () => {
      const result = generateFixSuggestion('REMOVED: /users endpoint', 'api', 'high');
      expect(result).toContain('Implement API versioning (v1, v2)');
      expect(result).toContain('Add deprecation notices');
    });

    test('should return API_DELETION suggestion', () => {
      const result = generateFixSuggestion('API_DELETION: specification removed', 'api', 'high');
      expect(result).toContain('Notify API consumers in advance');
      expect(result).toContain('Provide migration path');
    });

    test('should return API REQUIRED suggestion', () => {
      const result = generateFixSuggestion('REQUIRED field added', 'api', 'medium');
      expect(result).toContain('Make new required fields optional initially');
      expect(result).toContain('Provide default values');
    });

    test('should return API MODIFIED suggestion for medium severity', () => {
      const result = generateFixSuggestion('MODIFIED: schema changed', 'api', 'medium');
      expect(result).toContain('Document API changes in changelog');
      expect(result).toContain('Update client SDKs');
    });

    test('should return generic high severity suggestion', () => {
      const result = generateFixSuggestion('Unknown high risk change', 'unknown', 'high');
      expect(result).toContain('High impact change detected');
      expect(result).toContain('Consider phased rollout and rollback plan');
    });

    test('should return generic medium severity suggestion', () => {
      const result = generateFixSuggestion('Unknown medium risk change', 'unknown', 'medium');
      expect(result).toContain('Monitor for issues after deployment');
      expect(result).toContain('Have rollback procedure ready');
    });

    test('should return null for low severity with no specific pattern', () => {
      const result = generateFixSuggestion('ADD COLUMN optional_field', 'database', 'low');
      expect(result).toBeNull();
    });

    test('should return null for unknown patterns', () => {
      const result = generateFixSuggestion('CREATE INDEX', 'database', 'low');
      expect(result).toBeNull();
    });

    test('should be case insensitive for pattern matching', () => {
      const result1 = generateFixSuggestion('drop table users', 'database', 'high');
      const result2 = generateFixSuggestion('DROP TABLE users', 'database', 'high');
      const result3 = generateFixSuggestion('Drop Table users', 'database', 'high');

      expect(result1).toBe(result2);
      expect(result2).toBe(result3);
      expect(result1).toContain('Consider backing up data');
    });

    test('should handle partial matches in change strings', () => {
      const result = generateFixSuggestion('The operation will DROP TABLE users from schema', 'database', 'high');
      expect(result).toContain('Consider backing up data before dropping tables');
    });

    test('should prioritize specific patterns over generic ones', () => {
      // Should match DROP TABLE specifically, not generic high severity
      const result = generateFixSuggestion('DROP TABLE users', 'database', 'high');
      expect(result).toContain('CREATE TABLE ... AS SELECT');
      expect(result).not.toContain('Consider phased rollout');
    });

    test('should handle API MODIFIED for non-medium severity', () => {
      const result = generateFixSuggestion('MODIFIED: minor change', 'api', 'low');
      expect(result).toBeNull();
    });

    test('should handle empty change string', () => {
      const result = generateFixSuggestion('', 'database', 'high');
      expect(result).toContain('High impact change detected');
    });

    test('should handle null change string', () => {
      const result = generateFixSuggestion(null, 'api', 'medium');
      expect(result).toContain('Monitor for issues after deployment');
    });
  });

  describe('module exports', () => {
    test('should export both functions', () => {
      expect(typeof generateCommentBody).toBe('function');
      expect(typeof generateFixSuggestion).toBe('function');
    });
  });
});