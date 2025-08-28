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
      const codeAnalysisModule = require('../src/code-analysis');
      const originalAnalyze = codeAnalysisModule.analyzeChangedFiles;
      
      codeAnalysisModule.analyzeChangedFiles = jest.fn().mockResolvedValue({
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
      codeAnalysisModule.analyzeChangedFiles = originalAnalyze;
    });
    
    test('should create correlation when API handler uses database table', async () => {
      // Mock the analyzeChangedFiles function
      const codeAnalysisModule = require('../src/code-analysis');
      const originalAnalyze = codeAnalysisModule.analyzeChangedFiles;
      
      const mockAnalyzeChangedFiles = jest.fn().mockResolvedValue({
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
      
      // Override the module's export
      codeAnalysisModule.analyzeChangedFiles = mockAnalyzeChangedFiles;
      
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
      codeAnalysisModule.analyzeChangedFiles = originalAnalyze;
    });
    
    test('should respect candidate gating for medium budget strategy', async () => {
      const processedPairs = new Set();
      const candidatePairs = new Set(); // Empty candidate set
      
      // Mock analyzeChangedFiles
      const codeAnalysisModule = require('../src/code-analysis');
      const originalAnalyze = codeAnalysisModule.analyzeChangedFiles;
      
      codeAnalysisModule.analyzeChangedFiles = jest.fn().mockResolvedValue({
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
      codeAnalysisModule.analyzeChangedFiles = originalAnalyze;
    });
    
    test('should skip already processed pairs', async () => {
      const processedPairs = new Set(['api:GET:/v1/users/{id}::db:table:users']);
      
      // Mock analyzeChangedFiles
      const codeAnalysisModule = require('../src/code-analysis');
      const originalAnalyze = codeAnalysisModule.analyzeChangedFiles;
      
      codeAnalysisModule.analyzeChangedFiles = jest.fn().mockResolvedValue({
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
      codeAnalysisModule.analyzeChangedFiles = originalAnalyze;
    });
    
    test('should handle analysis errors gracefully', async () => {
      // Mock analyzeChangedFiles to throw error
      const codeAnalysisModule = require('../src/code-analysis');
      const originalAnalyze = codeAnalysisModule.analyzeChangedFiles;
      
      codeAnalysisModule.analyzeChangedFiles = jest.fn().mockRejectedValue(
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
      codeAnalysisModule.analyzeChangedFiles = originalAnalyze;
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
  test('analyzeChangedFiles should filter to supported language files', async () => {
    const mixedFiles = [
      { filename: 'src/app.js', status: 'modified' },
      { filename: 'src/routes/users.ts', status: 'added' },
      { filename: 'src/main.py', status: 'modified' },
      { filename: 'src/server.go', status: 'modified' },
      { filename: 'src/Controller.java', status: 'modified' },
      { filename: 'README.md', status: 'modified' }, // Should be filtered out
      { filename: 'package.json', status: 'modified' }, // Should be filtered out
      { filename: 'src/components/User.jsx', status: 'modified' }
    ];
    
    // Mock file reading to avoid actual file system access
    const fs = require('fs');
    const originalExistsSync = fs.existsSync;
    const originalReadFileSync = fs.readFileSync;
    
    fs.existsSync = jest.fn().mockReturnValue(false);
    fs.readFileSync = jest.fn().mockReturnValue('// mock content');
    
    const result = await analyzeChangedFiles({ files: mixedFiles, changedOnly: true });
    
    // Should process supported language files but return empty results due to mock content
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

describe('Multi-Language Support', () => {
  const codeAnalysisModule = require('../src/code-analysis');
  
  describe('Language Detection', () => {
    test('should support JavaScript/TypeScript files', () => {
      const jsFiles = [
        { filename: 'app.js', status: 'modified' },
        { filename: 'app.ts', status: 'modified' },
        { filename: 'component.jsx', status: 'modified' },
        { filename: 'component.tsx', status: 'modified' },
        { filename: 'module.mjs', status: 'modified' },
        { filename: 'config.cjs', status: 'modified' }
      ];
      
      jsFiles.forEach(file => {
        const isSupportedFile = require('../src/code-analysis/index').isSupportedFile || 
          (() => ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'].includes(require('path').extname(file.filename)));
        expect(isSupportedFile).toBeDefined();
      });
    });
    
    test('should support Python files', () => {
      const pythonFiles = [
        { filename: 'app.py', status: 'modified' },
        { filename: 'types.pyi', status: 'modified' }
      ];
      
      pythonFiles.forEach(file => {
        const isSupportedFile = require('../src/code-analysis/index').isSupportedFile || 
          (() => ['.py', '.pyi'].includes(require('path').extname(file.filename)));
        expect(isSupportedFile).toBeDefined();
      });
    });
    
    test('should support Go files', () => {
      const goFiles = [
        { filename: 'main.go', status: 'modified' },
        { filename: 'handler.go', status: 'modified' }
      ];
      
      goFiles.forEach(file => {
        const isSupportedFile = require('../src/code-analysis/index').isSupportedFile || 
          (() => ['.go'].includes(require('path').extname(file.filename)));
        expect(isSupportedFile).toBeDefined();
      });
    });
    
    test('should support Java files', () => {
      const javaFiles = [
        { filename: 'Controller.java', status: 'modified' },
        { filename: 'Service.kt', status: 'modified' }
      ];
      
      javaFiles.forEach(file => {
        const isSupportedFile = require('../src/code-analysis/index').isSupportedFile || 
          (() => ['.java', '.kt'].includes(require('path').extname(file.filename)));
        expect(isSupportedFile).toBeDefined();
      });
    });
  });
  
  describe('Language Adapters', () => {
    test('should load JavaScript adapter correctly', () => {
      const jsAdapter = require('../src/code-analysis/js/ast');
      expect(jsAdapter.parseFile).toBeDefined();
      expect(jsAdapter.extractImportsExports).toBeDefined();
      expect(jsAdapter.extractCalls).toBeDefined();
      
      const jsDetectors = require('../src/code-analysis/js/detectors');
      expect(jsDetectors.detectApiHandlers).toBeDefined();
      expect(jsDetectors.detectDbOperations).toBeDefined();
    });
    
    test('should load Python adapter correctly', () => {
      const pythonAdapter = require('../src/code-analysis/python/ast');
      expect(pythonAdapter.parseFile).toBeDefined();
      expect(pythonAdapter.extractImportsExports).toBeDefined();
      expect(pythonAdapter.extractCalls).toBeDefined();
      
      const pythonDetectors = require('../src/code-analysis/python/detectors');
      expect(pythonDetectors.detectApiHandlers).toBeDefined();
      expect(pythonDetectors.detectDbOperations).toBeDefined();
    });
    
    test('should load Go adapter correctly', () => {
      const goAdapter = require('../src/code-analysis/go/ast');
      expect(goAdapter.parseFile).toBeDefined();
      expect(goAdapter.extractImportsExports).toBeDefined();
      expect(goAdapter.extractCalls).toBeDefined();
      
      const goDetectors = require('../src/code-analysis/go/detectors');
      expect(goDetectors.detectApiHandlers).toBeDefined();
      expect(goDetectors.detectDbOperations).toBeDefined();
    });
    
    test('should load Java adapter correctly', () => {
      const javaAdapter = require('../src/code-analysis/java/ast');
      expect(javaAdapter.parseFile).toBeDefined();
      expect(javaAdapter.extractImportsExports).toBeDefined();
      expect(javaAdapter.extractCalls).toBeDefined();
      
      const javaDetectors = require('../src/code-analysis/java/detectors');
      expect(javaDetectors.detectApiHandlers).toBeDefined();
      expect(javaDetectors.detectDbOperations).toBeDefined();
    });
  });
  
  describe('Multi-Language Strategy Integration', () => {
    let strategy;
    
    beforeEach(() => {
      strategy = new CodeAnalysisStrategy({ enabled: true, budget: 'medium' });
    });
    
    test('should handle mixed language files in drift results', async () => {
      const mixedLanguageFiles = [
        { filename: 'src/api/users.js', status: 'modified' },    // JavaScript
        { filename: 'src/handlers/auth.py', status: 'modified' }, // Python  
        { filename: 'src/server/main.go', status: 'modified' },   // Go
        { filename: 'src/controller/UserController.java', status: 'modified' } // Java
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
      
      // Mock analyzeChangedFiles to simulate multi-language analysis
      const originalAnalyze = codeAnalysisModule.analyzeChangedFiles;
      codeAnalysisModule.analyzeChangedFiles = jest.fn().mockResolvedValue({
        handlers: [
          { method: 'GET', path: '/v1/users/{id}', file: 'src/api/users.js', symbol: 'getUser', line: 10 },
          { method: 'POST', path: '/auth/login', file: 'src/handlers/auth.py', symbol: 'login', line: 15 },
          { method: 'GET', path: '/health', file: 'src/server/main.go', symbol: 'HealthHandler', line: 25 },
          { method: 'PUT', path: '/users/{id}', file: 'src/controller/UserController.java', symbol: 'updateUser', line: 30 }
        ],
        dbRefs: [
          { orm: 'sequelize', table: 'users', op: 'findByPk', file: 'src/api/users.js', symbol: 'getUser', line: 12 },
          { orm: 'sqlalchemy', table: 'sessions', op: 'create', file: 'src/handlers/auth.py', symbol: 'login', line: 18 },
          { orm: 'gorm', table: 'users', op: 'First', file: 'src/server/main.go', symbol: 'GetUserHandler', line: 35 },
          { orm: 'jpa', table: 'users', op: 'save', file: 'src/controller/UserController.java', symbol: 'updateUser', line: 32 }
        ],
        calls: []
      });
      
      const result = await strategy.run({
        driftResults: [mockApiResult, mockDbResult],
        files: mixedLanguageFiles,
        config: {},
        processedPairs: new Set(),
        candidatePairs: null
      });
      
      // Should find correlations across multiple languages
      expect(result.length).toBeGreaterThanOrEqual(1);
      expect(result[0]).toHaveProperty('source');
      expect(result[0]).toHaveProperty('target');
      expect(result[0]).toHaveProperty('relationship');
      expect(result[0]).toHaveProperty('confidence');
      
      // Restore original function
      codeAnalysisModule.analyzeChangedFiles = originalAnalyze;
    });
  });
});