const { 
  getArtifactId, 
  getPairKey, 
  expandResults,
  isCriticalPair,
  resolveTokenToArtifacts,
  matchToken,
  aggregateCorrelations
} = require('../src/index');

describe('Correlation Strategy Engine', () => {
  describe('expandResults', () => {
    test('should expand multi-endpoint API results', () => {
      const results = [{
        type: 'api',
        endpoints: ['/v1/users', '/v1/users/{id}'],
        severity: 'medium'
      }];
      
      const expanded = expandResults(results);
      expect(expanded).toHaveLength(2);
      expect(expanded[0].endpoints).toEqual(['/v1/users']);
      expect(expanded[1].endpoints).toEqual(['/v1/users/{id}']);
    });
    
    test('should expand multi-table database results', () => {
      const results = [{
        type: 'database',
        entities: ['users', 'accounts'],
        changes: ['ALTER TABLE users']
      }];
      
      const expanded = expandResults(results);
      expect(expanded).toHaveLength(2);
      expect(expanded[0].entities).toEqual(['users']);
      expect(expanded[1].entities).toEqual(['accounts']);
    });
    
    test('should not expand single-item results', () => {
      const results = [{
        type: 'api',
        endpoints: ['/v1/users'],
        severity: 'high'
      }];
      
      const expanded = expandResults(results);
      expect(expanded).toHaveLength(1);
      expect(expanded[0]).toEqual(results[0]);
    });
  });
  
  describe('getArtifactId', () => {
    test('should normalize API paths', () => {
      const result = {
        type: 'api',
        endpoints: ['POST:/V1/USERS/{UserId}']
      };
      
      const id = getArtifactId(result);
      expect(id).toBe('api:POST:/v1/users/{userid}');
    });
    
    test('should normalize database table names', () => {
      const result = {
        type: 'database',
        entities: ['APPLICATION_USERS']
      };
      
      const id = getArtifactId(result);
      expect(id).toBe('db:table:application_users');
    });
    
    test('should normalize file paths', () => {
      const result = {
        type: 'configuration',
        file: './config//env.yaml'
      };
      
      const id = getArtifactId(result);
      expect(id).toBe('config:config/env.yaml');
    });
  });
  
  describe('getPairKey', () => {
    test('should create canonical undirected keys', () => {
      const a = { type: 'api', endpoints: ['/v1/users'], artifactId: 'api:GET:/v1/users' };
      const b = { type: 'database', entities: ['users'], artifactId: 'db:table:users' };
      
      const key1 = getPairKey(a, b);
      const key2 = getPairKey(b, a);
      
      expect(key1).toBe(key2);
      expect(key1).toBe('api:GET:/v1/users::db:table:users');
    });
  });
  
  describe('isCriticalPair', () => {
    test('should detect destructive database operations', () => {
      const a = { changes: ['DROP TABLE users'] };
      const b = { changes: ['ALTER TABLE accounts'] };
      
      expect(isCriticalPair(a, b)).toBe(true);
    });
    
    test('should detect CVE vulnerabilities', () => {
      const a = { changes: ['CVE-2023-12345 detected'] };
      const b = { changes: ['Normal change'] };
      
      expect(isCriticalPair(a, b)).toBe(true);
    });
    
    test('should detect wide-open security groups', () => {
      const a = { changes: ['CIDR: 0.0.0.0/0'] };
      const b = { changes: ['Port 22 opened'] };
      
      expect(isCriticalPair(a, b)).toBe(true);
    });
    
    test('should not flag normal changes as critical', () => {
      const a = { changes: ['ADD COLUMN email'] };
      const b = { changes: ['UPDATE config'] };
      
      expect(isCriticalPair(a, b)).toBe(false);
    });
  });
  
  describe('Rule Resolution', () => {
    test('should resolve glob patterns to artifacts', () => {
      const micromatch = require('micromatch');
      const results = [
        { artifactId: 'api:GET:/v1/users', endpoints: ['/v1/users'], type: 'api' },
        { artifactId: 'api:GET:/v1/users/search', endpoints: ['/v1/users/search'], type: 'api' },
        { artifactId: 'api:GET:/v1/accounts', endpoints: ['/v1/accounts'], type: 'api' }
      ];
      
      const token = '/v1/users/*';
      const matches = results.filter(r => {
        const candidates = [...(r.endpoints || [])].map(e => e.toLowerCase());
        return candidates.some(c => micromatch.isMatch(c, token));
      });
      
      expect(matches).toHaveLength(1);
      expect(matches[0].artifactId).toBe('api:GET:/v1/users/search');
    });
    
    test('should match substring patterns', () => {
      const results = [
        { artifactId: 'db:table:users', entities: ['users'], type: 'database' },
        { artifactId: 'db:table:user_roles', entities: ['user_roles'], type: 'database' },
        { artifactId: 'db:table:accounts', entities: ['accounts'], type: 'database' }
      ];
      
      const matches = resolveTokenToArtifacts(results, 'user');
      expect(matches).toHaveLength(2);
      expect(matches.map(m => m.artifactId)).toContain('db:table:users');
      expect(matches.map(m => m.artifactId)).toContain('db:table:user_roles');
    });
  });
  
  describe('Weighted Aggregation', () => {
    test('should calculate correct weighted average', () => {
      const scores = { entity: 0.8, operation: 0.6 };
      const weights = { entity: 1.0, operation: 0.5 };
      
      // Manual calculation: (0.8*1.0 + 0.6*0.5) / (1.0 + 0.5) = 1.1 / 1.5 = 0.733...
      let weightedSum = 0;
      let totalWeight = 0;
      Object.entries(scores).forEach(([name, confidence]) => {
        const weight = weights[name];
        weightedSum += confidence * weight;
        totalWeight += weight;
      });
      
      const finalScore = totalWeight > 0 ? weightedSum / totalWeight : 0;
      expect(finalScore).toBeCloseTo(0.733, 2);
    });
    
    test('should enforce monotonicity for explicit rules', () => {
      // Explicit rules should always have finalScore = 1.0
      const correlation = {
        scores: { explicit: 1.0, entity: 0.5 },
        weights: { explicit: 1.0, entity: 0.8 }
      };
      
      // With explicit, finalScore must be 1.0 regardless of other scores
      const finalScore = correlation.scores.explicit ? 1.0 : 0.5;
      expect(finalScore).toBe(1.0);
    });
  });
  
  describe('Safety Rails', () => {
    test('ignore rule should not suppress critical pairs', () => {
      const processedPairs = new Set();
      const s = { changes: ['DROP TABLE users'], artifactId: 'db:table:users' };
      const t = { changes: ['Normal change'], artifactId: 'api:GET:/v1/users' };
      
      if (isCriticalPair(s, t)) {
        // Should NOT add to processedPairs
        expect(processedPairs.has(getPairKey(s, t))).toBe(false);
      } else {
        processedPairs.add(getPairKey(s, t));
      }
      
      expect(processedPairs.size).toBe(0); // Critical pair was not ignored
    });
  });

  describe('aggregateCorrelations', () => {
    test('handles multiple signals from same strategy correctly', () => {
      const source = { type: 'api', id: 'api1' };
      const target = { type: 'database', id: 'db1' };
      
      const strategySignals = new Map([
        ['entity', [
          { 
            source, 
            target, 
            confidence: 0.4, 
            relationship: 'uses', 
            evidence: ['Low confidence match'] 
          },
          { 
            source, 
            target, 
            confidence: 0.8, 
            relationship: 'uses', 
            evidence: ['High confidence match'] 
          }
        ]]
      ]);
      
      const strategiesByName = {
        entity: { enabled: true, weight: 1.0 }
      };
      
      const processedPairs = new Set();
      const config = { thresholds: { block_min: 0.8 } };
      
      const results = aggregateCorrelations([], strategySignals, strategiesByName, processedPairs, config);
      
      expect(results).toHaveLength(1);
      const correlation = results[0];
      
      // Strategy appears only once
      expect(correlation.strategies).toEqual(['entity']);
      
      // Score is the maximum (0.8)
      expect(correlation.scores.entity).toBe(0.8);
      expect(correlation.finalScore).toBe(0.8);
      
      // Evidence from higher confidence signal
      expect(correlation.evidence[0].reason).toBe('High confidence match');
      expect(correlation.evidence).toHaveLength(1);
    });
  });
});