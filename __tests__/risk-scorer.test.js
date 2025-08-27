const riskScorer = require('../src/risk-scorer');

describe('Risk Scorer', () => {
  describe('assessHighSeverity', () => {
    test('should return true for DROP TABLE operations', () => {
      expect(riskScorer.assessHighSeverity('DROP TABLE', [])).toBe(true);
      expect(riskScorer.assessHighSeverity('drop table users', [])).toBe(true);
    });

    test('should return true for DROP COLUMN operations', () => {
      expect(riskScorer.assessHighSeverity('DROP COLUMN', [])).toBe(true);
      expect(riskScorer.assessHighSeverity('alter table drop column name', [])).toBe(true);
    });

    test('should return true for TRUNCATE TABLE operations', () => {
      expect(riskScorer.assessHighSeverity('TRUNCATE TABLE', [])).toBe(true);
      expect(riskScorer.assessHighSeverity('truncate table logs', [])).toBe(true);
    });

    test('should return true for DROP CONSTRAINT operations', () => {
      expect(riskScorer.assessHighSeverity('DROP CONSTRAINT', [])).toBe(true);
      expect(riskScorer.assessHighSeverity('alter drop constraint fk_user', [])).toBe(true);
    });

    test('should return true for COLUMN LOSS indicator', () => {
      expect(riskScorer.assessHighSeverity('COLUMN LOSS', [])).toBe(true);
      expect(riskScorer.assessHighSeverity('analysis shows column loss', [])).toBe(true);
    });

    test('should return true for API_DELETION operations', () => {
      expect(riskScorer.assessHighSeverity('API_DELETION', [])).toBe(true);
      expect(riskScorer.assessHighSeverity('detected api_deletion event', [])).toBe(true);
    });

    test('should return true for BREAKING_CHANGE operations', () => {
      expect(riskScorer.assessHighSeverity('BREAKING_CHANGE', [])).toBe(true);
      expect(riskScorer.assessHighSeverity('this is a breaking_change', [])).toBe(true);
    });

    test('should return true when high risk indicators found in details array', () => {
      expect(riskScorer.assessHighSeverity('MODIFY', ['DROP TABLE users'])).toBe(true);
      expect(riskScorer.assessHighSeverity('CHANGE', ['column loss detected', 'other info'])).toBe(true);
      expect(riskScorer.assessHighSeverity('UPDATE', ['api_deletion: /users endpoint'])).toBe(true);
    });

    test('should return false for non-high risk operations', () => {
      expect(riskScorer.assessHighSeverity('ADD COLUMN', [])).toBe(false);
      expect(riskScorer.assessHighSeverity('CREATE TABLE', [])).toBe(false);
      expect(riskScorer.assessHighSeverity('INSERT INTO', [])).toBe(false);
    });

    test('should return false when no high risk indicators in details', () => {
      expect(riskScorer.assessHighSeverity('MODIFY', ['ADD COLUMN name', 'CREATE INDEX'])).toBe(false);
      expect(riskScorer.assessHighSeverity('CHANGE', [])).toBe(false);
    });

    test('should handle null/undefined details gracefully', () => {
      expect(riskScorer.assessHighSeverity('MODIFY', null)).toBe(false);
      expect(riskScorer.assessHighSeverity('MODIFY', undefined)).toBe(false);
    });

    test('should handle empty details array', () => {
      expect(riskScorer.assessHighSeverity('MODIFY', [])).toBe(false);
    });

    test('should be case insensitive', () => {
      expect(riskScorer.assessHighSeverity('drop table', [])).toBe(true);
      expect(riskScorer.assessHighSeverity('DROP TABLE', [])).toBe(true);
      expect(riskScorer.assessHighSeverity('Drop Table', [])).toBe(true);
    });

    test('should return true for MAJOR_VERSION_BUMP', () => {
      expect(riskScorer.assessHighSeverity('MAJOR_VERSION_BUMP', [])).toBe(true);
      expect(riskScorer.assessHighSeverity('detected major_version_bump', [])).toBe(true);
    });

    test('should return true for SECURITY_VULNERABILITY', () => {
      expect(riskScorer.assessHighSeverity('SECURITY_VULNERABILITY', [])).toBe(true);
      expect(riskScorer.assessHighSeverity('security_vulnerability found', [])).toBe(true);
    });

    test('should return true for CVE_DETECTED', () => {
      expect(riskScorer.assessHighSeverity('CVE_DETECTED', [])).toBe(true);
      expect(riskScorer.assessHighSeverity('cve_detected in dependencies', [])).toBe(true);
    });

    test('should return true for INTEGRITY_MISMATCH', () => {
      expect(riskScorer.assessHighSeverity('INTEGRITY_MISMATCH', [])).toBe(true);
      expect(riskScorer.assessHighSeverity('integrity_mismatch detected', [])).toBe(true);
    });

    test('should return true for TRANSITIVE_MAJOR_BUMP', () => {
      expect(riskScorer.assessHighSeverity('TRANSITIVE_MAJOR_BUMP', [])).toBe(true);
      expect(riskScorer.assessHighSeverity('transitive_major_bump found', [])).toBe(true);
    });
  });

  describe('assessMediumSeverity', () => {
    test('should return true for TYPE NARROWING operations', () => {
      expect(riskScorer.assessMediumSeverity('TYPE NARROWING', [])).toBe(true);
      expect(riskScorer.assessMediumSeverity('varchar to int type narrowing', [])).toBe(true);
    });

    test('should return true for NOT NULL constraints', () => {
      expect(riskScorer.assessMediumSeverity('NOT NULL', [])).toBe(true);
      expect(riskScorer.assessMediumSeverity('add column not null', [])).toBe(true);
    });

    test('should return true for REQUIRED field additions', () => {
      expect(riskScorer.assessMediumSeverity('REQUIRED', [])).toBe(true);
      expect(riskScorer.assessMediumSeverity('new required field added', [])).toBe(true);
    });

    test('should return true for COLUMN RENAME operations', () => {
      expect(riskScorer.assessMediumSeverity('COLUMN RENAME', [])).toBe(true);
      expect(riskScorer.assessMediumSeverity('detected column rename', [])).toBe(true);
    });

    test('should return true for BREAKING CHANGE operations', () => {
      expect(riskScorer.assessMediumSeverity('BREAKING CHANGE', [])).toBe(true);
      expect(riskScorer.assessMediumSeverity('potential breaking change', [])).toBe(true);
    });

    test('should return true for ADD CONSTRAINT operations', () => {
      expect(riskScorer.assessMediumSeverity('ADD CONSTRAINT', [])).toBe(true);
      expect(riskScorer.assessMediumSeverity('alter table add constraint fk', [])).toBe(true);
    });

    test('should return true when medium risk indicators found in details array', () => {
      expect(riskScorer.assessMediumSeverity('MODIFY', ['TYPE NARROWING: varchar to int'])).toBe(true);
      expect(riskScorer.assessMediumSeverity('CHANGE', ['not null constraint', 'other info'])).toBe(true);
      expect(riskScorer.assessMediumSeverity('UPDATE', ['required: new field'])).toBe(true);
    });

    test('should return false for non-medium risk operations', () => {
      expect(riskScorer.assessMediumSeverity('ADD COLUMN', [])).toBe(false);
      expect(riskScorer.assessMediumSeverity('CREATE TABLE', [])).toBe(false);
      expect(riskScorer.assessMediumSeverity('INSERT INTO', [])).toBe(false);
    });

    test('should return false when no medium risk indicators in details', () => {
      expect(riskScorer.assessMediumSeverity('MODIFY', ['ADD COLUMN name', 'CREATE INDEX'])).toBe(false);
      expect(riskScorer.assessMediumSeverity('CHANGE', [])).toBe(false);
    });

    test('should handle null/undefined details gracefully', () => {
      expect(riskScorer.assessMediumSeverity('MODIFY', null)).toBe(false);
      expect(riskScorer.assessMediumSeverity('MODIFY', undefined)).toBe(false);
    });

    test('should be case insensitive', () => {
      expect(riskScorer.assessMediumSeverity('type narrowing', [])).toBe(true);
      expect(riskScorer.assessMediumSeverity('TYPE NARROWING', [])).toBe(true);
      expect(riskScorer.assessMediumSeverity('Type Narrowing', [])).toBe(true);
    });

    test('should return true for MINOR_VERSION_BUMP', () => {
      expect(riskScorer.assessMediumSeverity('MINOR_VERSION_BUMP', [])).toBe(true);
      expect(riskScorer.assessMediumSeverity('minor_version_bump detected', [])).toBe(true);
    });

    test('should return true for LICENSE_CHANGE', () => {
      expect(riskScorer.assessMediumSeverity('LICENSE_CHANGE', [])).toBe(true);
      expect(riskScorer.assessMediumSeverity('license_change detected', [])).toBe(true);
    });

    test('should return true for DEPRECATED_PACKAGE', () => {
      expect(riskScorer.assessMediumSeverity('DEPRECATED_PACKAGE', [])).toBe(true);
      expect(riskScorer.assessMediumSeverity('deprecated_package warning', [])).toBe(true);
    });

    test('should return true for TRANSITIVE_DEPENDENCIES_CHANGED', () => {
      expect(riskScorer.assessMediumSeverity('TRANSITIVE_DEPENDENCIES_CHANGED', [])).toBe(true);
      expect(riskScorer.assessMediumSeverity('transitive_dependencies_changed', [])).toBe(true);
    });

    test('should return true for NEW_LOCK_FILE', () => {
      expect(riskScorer.assessMediumSeverity('NEW_LOCK_FILE', [])).toBe(true);
      expect(riskScorer.assessMediumSeverity('new_lock_file created', [])).toBe(true);
    });

    test('should return true for DEPENDENCY_REMOVED', () => {
      expect(riskScorer.assessMediumSeverity('DEPENDENCY_REMOVED', [])).toBe(true);
      expect(riskScorer.assessMediumSeverity('dependency_removed from project', [])).toBe(true);
    });
  });

  describe('scoreChanges', () => {
    test('should return high severity for high risk changes', () => {
      const result = riskScorer.scoreChanges(['DROP TABLE users'], 'SQL');
      expect(result.severity).toBe('high');
      expect(result.reasoning).toContain('Contains destructive or breaking operations');
      expect(result.changes).toEqual(['DROP TABLE users']);
    });

    test('should return medium severity for medium risk changes', () => {
      const result = riskScorer.scoreChanges(['TYPE NARROWING: varchar to int'], 'API');
      expect(result.severity).toBe('medium');
      expect(result.reasoning).toContain('Contains potentially breaking or constraining changes');
      expect(result.changes).toEqual(['TYPE NARROWING: varchar to int']);
    });

    test('should return low severity for low risk changes', () => {
      const result = riskScorer.scoreChanges(['ADD COLUMN optional_field'], 'SQL');
      expect(result.severity).toBe('low');
      expect(result.reasoning).toContain('Contains backward-compatible changes');
      expect(result.changes).toEqual(['ADD COLUMN optional_field']);
    });

    test('should prioritize high severity over medium when both present', () => {
      const changes = ['DROP TABLE users', 'TYPE NARROWING: varchar to int'];
      const result = riskScorer.scoreChanges(changes, 'SQL');
      expect(result.severity).toBe('high');
      expect(result.reasoning).toContain('Contains destructive or breaking operations');
    });

    test('should handle empty changes array', () => {
      const result = riskScorer.scoreChanges([], 'SQL');
      expect(result.severity).toBe('low');
      expect(result.reasoning).toEqual([]);
      expect(result.changes).toEqual([]);
    });

    test('should handle null/undefined changes', () => {
      const result = riskScorer.scoreChanges(null, 'SQL');
      expect(result.severity).toBe('low');
      expect(result.reasoning).toEqual([]);
      expect(result.changes).toBeNull();
    });

    test('should use default changeType when not provided', () => {
      const result = riskScorer.scoreChanges(['ADD COLUMN test']);
      expect(result.severity).toBe('low');
      expect(result.reasoning).toContain('Contains backward-compatible changes');
    });

    test('should return proper structure with all required fields', () => {
      const result = riskScorer.scoreChanges(['DROP TABLE test'], 'SQL');
      expect(result).toHaveProperty('severity');
      expect(result).toHaveProperty('reasoning');
      expect(result).toHaveProperty('changes');
      expect(Array.isArray(result.reasoning)).toBe(true);
    });
  });

  describe('applyOverride', () => {
    test('should apply override with reason and timestamp', () => {
      const originalResult = {
        severity: 'high',
        reasoning: ['Contains destructive operations'],
        changes: ['DROP TABLE users']
      };
      
      const result = riskScorer.applyOverride(originalResult, 'Emergency hotfix required');
      
      expect(result.override.applied).toBe(true);
      expect(result.override.reason).toBe('Emergency hotfix required');
      expect(result.override.originalSeverity).toBe('high');
      expect(result.override.timestamp).toBeDefined();
      expect(result.allowMerge).toBe(true);
      
      // Should be a valid ISO timestamp
      expect(new Date(result.override.timestamp).toISOString()).toBe(result.override.timestamp);
    });

    test('should not modify result when no override reason provided', () => {
      const originalResult = {
        severity: 'high',
        reasoning: ['Contains destructive operations'],
        changes: ['DROP TABLE users']
      };
      
      const result = riskScorer.applyOverride(originalResult);
      
      expect(result.override).toBeUndefined();
      expect(result.allowMerge).toBeUndefined();
      expect(result).toBe(originalResult); // Should return same object
    });

    test('should not modify result when null override reason provided', () => {
      const originalResult = {
        severity: 'medium',
        reasoning: ['Type narrowing detected'],
        changes: ['TYPE NARROWING: varchar to int']
      };
      
      const result = riskScorer.applyOverride(originalResult, null);
      
      expect(result.override).toBeUndefined();
      expect(result.allowMerge).toBeUndefined();
      expect(result).toBe(originalResult);
    });

    test('should not modify result when empty string override reason provided', () => {
      const originalResult = {
        severity: 'medium',
        reasoning: ['Type narrowing detected'],
        changes: ['TYPE NARROWING: varchar to int']
      };
      
      const result = riskScorer.applyOverride(originalResult, '');
      
      expect(result.override).toBeUndefined();
      expect(result.allowMerge).toBeUndefined();
      expect(result).toBe(originalResult);
    });

    test('should preserve all original properties when applying override', () => {
      const originalResult = {
        severity: 'high',
        reasoning: ['Contains destructive operations'],
        changes: ['DROP TABLE users'],
        customField: 'should be preserved'
      };
      
      const result = riskScorer.applyOverride(originalResult, 'Test override');
      
      expect(result.severity).toBe('high');
      expect(result.reasoning).toEqual(['Contains destructive operations']);
      expect(result.changes).toEqual(['DROP TABLE users']);
      expect(result.customField).toBe('should be preserved');
      expect(result.allowMerge).toBe(true);
    });

    test('should work with different severity levels', () => {
      const mediumResult = {
        severity: 'medium',
        reasoning: ['Potentially breaking changes'],
        changes: ['REQUIRED field added']
      };
      
      const result = riskScorer.applyOverride(mediumResult, 'Product owner approval');
      
      expect(result.override.originalSeverity).toBe('medium');
      expect(result.override.reason).toBe('Product owner approval');
      expect(result.allowMerge).toBe(true);
    });

    test('should create timestamp within reasonable time window', () => {
      const originalResult = {
        severity: 'high',
        reasoning: ['Test'],
        changes: ['TEST']
      };
      
      const beforeTime = Date.now();
      const result = riskScorer.applyOverride(originalResult, 'Test reason');
      const afterTime = Date.now();
      
      const resultTime = new Date(result.override.timestamp).getTime();
      expect(resultTime).toBeGreaterThanOrEqual(beforeTime);
      expect(resultTime).toBeLessThanOrEqual(afterTime);
    });
  });

  describe('module export', () => {
    test('should export all required methods', () => {
      expect(typeof riskScorer.assessHighSeverity).toBe('function');
      expect(typeof riskScorer.assessMediumSeverity).toBe('function');
      expect(typeof riskScorer.scoreChanges).toBe('function');
      expect(typeof riskScorer.applyOverride).toBe('function');
    });

    test('should be an object with expected structure', () => {
      expect(typeof riskScorer).toBe('object');
      expect(riskScorer).not.toBeNull();
      expect(Object.keys(riskScorer)).toHaveLength(5); // Updated to include assessCorrelationImpact
    });
  });
});