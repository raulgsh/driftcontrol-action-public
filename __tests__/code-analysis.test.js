const { CodeAnalysisStrategy } = require('../src/index');
const { analyzeChangedFiles } = require('../src/code-analysis');

describe('CodeAnalysisStrategy', () => {
  let strategy;
  
  beforeEach(() => {
    strategy = new CodeAnalysisStrategy({ enabled: true, budget: 'medium' });
  });
  
  describe('constructor', () => {
    test('should initialize with correct default config', () => {
      expect(strategy.name).toBe('code');
      expect(strategy.enabled).toBe(true);
      expect(strategy.budget).toBe('medium');
      expect(strategy.weight).toBe(1.0);
    });
    
    test('should accept custom config', () => {
      const customStrategy = new CodeAnalysisStrategy({
        enabled: false,
        budget: 'high',
        weight: 0.8
      });
      
      expect(customStrategy.enabled).toBe(false);
      expect(customStrategy.budget).toBe('high');
      expect(customStrategy.weight).toBe(0.8);
    });
  });
  
  describe('run', () => {
    const mockFiles = [
      { filename: 'src/routes/users.js', status: 'modified' },
      { filename: 'src/services/userService.js', status: 'modified' },
      { filename: 'README.md', status: 'modified' } // Should be ignored
    ];
    
    const mockApiResult = {
      type: 'api',
      endpoints: ['GET:/v1/users/{id}'],
      file: 'openapi.yaml',
      artifactId: 'api:GET:/v1/users/{id}'
    };
    
    const mockDbResult = {
      type: 'database',
      entities: ['users'],
      changes: ['ALTER TABLE users ADD COLUMN email VARCHAR(255)'],
      artifactId: 'db:table:users'
    };
    
    const mockDriftResults = [mockApiResult, mockDbResult];
    
    test('should return empty correlations when no JS files changed', async () => {
      const filesWithoutJs = [
        { filename: 'README.md', status: 'modified' },
        { filename: 'schema.sql', status: 'modified' }
      ];
      
      const result = await strategy.run({
        driftResults: mockDriftResults,
        files: filesWithoutJs,
        config: {},
        processedPairs: new Set(),
        candidatePairs: null
      });
      
      expect(result).toEqual([]);
    });
    
    test('should return empty correlations when no handlers or DB refs found', async () => {
      // Mock analyzeChangedFiles to return empty results
      const originalAnalyze = require('../src/code-analysis').analyzeChangedFiles;
      require('../src/code-analysis').analyzeChangedFiles = jest.fn().mockResolvedValue({
        handlers: [],
        dbRefs: [],
        calls: []
      });
      
      const result = await strategy.run({
        driftResults: mockDriftResults,
        files: mockFiles,
        config: {},
        processedPairs: new Set(),
        candidatePairs: null
      });
      
      expect(result).toEqual([]);
      
      // Restore original function
      require('../src/code-analysis').analyzeChangedFiles = originalAnalyze;
    });
    
    test('should create correlation when API handler uses database table', async () => {
      // Mock analyzeChangedFiles to return matching handler and DB ref
      const originalAnalyze = require('../src/code-analysis').analyzeChangedFiles;
      require('../src/code-analysis').analyzeChangedFiles = jest.fn().mockResolvedValue({
        handlers: [{
          method: 'GET',
          path: '/v1/users/{id}',
          file: 'src/routes/users.js',
          symbol: 'getUserById',
          line: 15
        }],
        dbRefs: [{
          orm: 'prisma',
          table: 'users',
          op: 'findUnique',
          file: 'src/routes/users.js',
          symbol: 'getUserById',
          line: 17
        }],
        calls: []
      });
      
      const result = await strategy.run({
        driftResults: mockDriftResults,
        files: mockFiles,
        config: {},
        processedPairs: new Set(),
        candidatePairs: null
      });
      
      expect(result).toHaveLength(1);
      expect(result[0]).toMatchObject({
        source: mockApiResult,
        target: mockDbResult,
        relationship: 'api_uses_table',
        confidence: expect.any(Number)
      });
      expect(result[0].confidence).toBeGreaterThan(0.8); // High confidence for same function
      expect(result[0].evidence).toBeDefined();
      expect(result[0].evidence[0]).toMatchObject({
        file: 'src/routes/users.js',
        line: 17,
        reason: expect.stringContaining('prisma.users.findUnique')
      });
      
      // Restore original function
      require('../src/code-analysis').analyzeChangedFiles = originalAnalyze;
    });
    
    test('should respect candidate gating for medium budget strategy', async () => {
      const processedPairs = new Set();
      const candidatePairs = new Set(); // Empty candidate set
      
      // Mock analyzeChangedFiles
      const originalAnalyze = require('../src/code-analysis').analyzeChangedFiles;
      require('../src/code-analysis').analyzeChangedFiles = jest.fn().mockResolvedValue({
        handlers: [{
          method: 'GET',
          path: '/v1/users/{id}',
          file: 'src/routes/users.js',
          symbol: 'getUserById',
          line: 15
        }],
        dbRefs: [{
          orm: 'prisma',
          table: 'users',
          op: 'findUnique',
          file: 'src/routes/users.js',
          symbol: 'getUserById',
          line: 17
        }],
        calls: []
      });
      
      const result = await strategy.run({
        driftResults: mockDriftResults,
        files: mockFiles,
        config: {},
        processedPairs,
        candidatePairs
      });
      
      // Should return empty because pair is not in candidate set
      expect(result).toEqual([]);
      
      // Restore original function
      require('../src/code-analysis').analyzeChangedFiles = originalAnalyze;
    });
    
    test('should skip already processed pairs', async () => {
      const processedPairs = new Set(['api:GET:/v1/users/{id}::db:table:users']);
      
      // Mock analyzeChangedFiles
      const originalAnalyze = require('../src/code-analysis').analyzeChangedFiles;
      require('../src/code-analysis').analyzeChangedFiles = jest.fn().mockResolvedValue({
        handlers: [{
          method: 'GET',
          path: '/v1/users/{id}',
          file: 'src/routes/users.js',
          symbol: 'getUserById',
          line: 15
        }],
        dbRefs: [{
          orm: 'prisma',
          table: 'users',
          op: 'findUnique',
          file: 'src/routes/users.js',
          symbol: 'getUserById',
          line: 17
        }],
        calls: []
      });
      
      const result = await strategy.run({
        driftResults: mockDriftResults,
        files: mockFiles,
        config: {},
        processedPairs,
        candidatePairs: null
      });
      
      // Should return empty because pair was already processed
      expect(result).toEqual([]);
      
      // Restore original function
      require('../src/code-analysis').analyzeChangedFiles = originalAnalyze;
    });
    
    test('should handle analysis errors gracefully', async () => {
      // Mock analyzeChangedFiles to throw error
      const originalAnalyze = require('../src/code-analysis').analyzeChangedFiles;
      require('../src/code-analysis').analyzeChangedFiles = jest.fn().mockRejectedValue(
        new Error('Parse error')
      );
      
      const result = await strategy.run({
        driftResults: mockDriftResults,
        files: mockFiles,
        config: {},
        processedPairs: new Set(),
        candidatePairs: null
      });
      
      // Should return empty array instead of throwing
      expect(result).toEqual([]);
      
      // Restore original function
      require('../src/code-analysis').analyzeChangedFiles = originalAnalyze;
    });
  });
  
  describe('helper methods', () => {
    test('parseEndpoint should extract method and path', () => {
      expect(strategy.parseEndpoint('GET:/v1/users')).toEqual({
        method: 'GET',
        path: '/v1/users'
      });
      
      expect(strategy.parseEndpoint('/v1/users')).toEqual({
        method: 'GET',
        path: '/v1/users'
      });
    });
    
    test('normalizePath should normalize API paths', () => {
      expect(strategy.normalizePath('/v1/users/{id}')).toBe('/v1/users/{id}');
      expect(strategy.normalizePath('/V1/Users/{UserId}')).toBe('/v1/users/{id}');
      expect(strategy.normalizePath('/v1//users/')).toBe('/v1/users');
    });
    
    test('tablesMatch should match table name variations', () => {
      expect(strategy.tablesMatch('users', 'users')).toBe(true);
      expect(strategy.tablesMatch('user', 'users')).toBe(true);
      expect(strategy.tablesMatch('users', 'user')).toBe(true);
      expect(strategy.tablesMatch('userAccount', 'user_accounts')).toBe(true);
      expect(strategy.tablesMatch('posts', 'comments')).toBe(false);
    });
    
    test('extractTableFromDbResult should extract table names', () => {
      const dbResultWithEntities = {
        entities: ['users', 'profiles'],
        changes: []
      };
      expect(strategy.extractTableFromDbResult(dbResultWithEntities)).toBe('users');
      
      const dbResultWithChanges = {
        entities: [],
        changes: ['ALTER TABLE user_profiles ADD COLUMN age INT']
      };
      expect(strategy.extractTableFromDbResult(dbResultWithChanges)).toBe('user_profiles');
      
      const emptyResult = { entities: [], changes: [] };
      expect(strategy.extractTableFromDbResult(emptyResult)).toBeNull();
    });
  });
});

describe('Code Analysis Integration', () => {
  test('analyzeChangedFiles should filter to JS files only', async () => {
    const mixedFiles = [
      { filename: 'src/app.js', status: 'modified' },
      { filename: 'src/routes/users.ts', status: 'added' },
      { filename: 'README.md', status: 'modified' },
      { filename: 'package.json', status: 'modified' },
      { filename: 'src/components/User.jsx', status: 'modified' }
    ];
    
    // Mock file reading to avoid actual file system access
    const fs = require('fs');
    const originalExistsSync = fs.existsSync;
    const originalReadFileSync = fs.readFileSync;
    
    fs.existsSync = jest.fn().mockReturnValue(false);
    fs.readFileSync = jest.fn().mockReturnValue('// mock content');
    
    const result = await analyzeChangedFiles({ files: mixedFiles, changedOnly: true });
    
    // Should process JS/TS files but return empty results due to mock content
    expect(result).toEqual({
      handlers: [],
      dbRefs: [],
      calls: []
    });
    
    // Restore original functions
    fs.existsSync = originalExistsSync;
    fs.readFileSync = originalReadFileSync;
  });
});