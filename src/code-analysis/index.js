// Main code analysis orchestrator
const fs = require('fs');
const path = require('path');
const { parseFile, extractImportsExports, extractFunctions, extractCalls } = require('./js/ast');
const { detectApiHandlers, detectDbOperations } = require('./js/detectors');

// File cache to avoid re-parsing unchanged files
const fileCache = new Map(); // filepath -> { hash, ast, handlers, dbRefs, calls }

// Main analysis function
async function analyzeChangedFiles({ files, changedOnly = true, depth = 2 }) {
  const handlers = []; // ApiHandler[]
  const dbRefs = [];   // DbRef[]
  const calls = [];    // CallEdge[]
  
  // Filter to JS/TS files only
  const jsFiles = files.filter(file => 
    isJavaScriptFile(file.filename) && 
    (!changedOnly || ['added', 'modified'].includes(file.status))
  );
  
  if (jsFiles.length === 0) {
    return { handlers, dbRefs, calls };
  }
  
  // Process each file
  for (const file of jsFiles) {
    try {
      const fileContent = await readFileContent(file.filename);
      if (!fileContent) continue;
      
      // Check cache
      const contentHash = simpleHash(fileContent);
      const cached = fileCache.get(file.filename);
      
      if (cached && cached.hash === contentHash) {
        // Use cached results
        handlers.push(...cached.handlers);
        dbRefs.push(...cached.dbRefs);
        calls.push(...cached.calls);
        continue;
      }
      
      // Parse and analyze
      const ast = parseFile(fileContent, file.filename);
      if (!ast) continue;
      
      // Extract API handlers
      const fileHandlers = detectApiHandlers(ast, file.filename);
      
      // Extract DB operations
      const fileDbRefs = detectDbOperations(ast, file.filename);
      
      // Extract function calls for call graph
      const fileCalls = extractCalls(ast);
      const imports = extractImportsExports(ast, file.filename);
      
      // Build cross-file call edges (simplified for v1)
      const crossFileCalls = buildCrossFileCalls(fileCalls, imports, file.filename);
      
      // Cache results
      fileCache.set(file.filename, {
        hash: contentHash,
        handlers: fileHandlers,
        dbRefs: fileDbRefs,
        calls: [...fileCalls, ...crossFileCalls]
      });
      
      // Collect results
      handlers.push(...fileHandlers);
      dbRefs.push(...fileDbRefs);
      calls.push(...fileCalls, ...crossFileCalls);
      
    } catch (error) {
      // Log error but continue processing other files
      console.warn(`Code analysis failed for ${file.filename}:`, error.message);
    }
  }
  
  return { handlers, dbRefs, calls };
}

// Helper: Check if file is JavaScript/TypeScript
function isJavaScriptFile(filename) {
  const ext = path.extname(filename).toLowerCase();
  return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'].includes(ext);
}

// Helper: Read file content (in GitHub Action context, files might need to be fetched)
async function readFileContent(filename) {
  try {
    // In production, files might be fetched via GitHub API
    // For now, try to read from local filesystem
    if (fs.existsSync(filename)) {
      return fs.readFileSync(filename, 'utf8');
    }
    return null;
  } catch (error) {
    return null;
  }
}

// Helper: Simple string hash for caching
function simpleHash(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return hash.toString();
}

// Helper: Build cross-file call edges (simplified)
function buildCrossFileCalls(fileCalls, imports, filename) {
  const crossCalls = [];
  
  // For each import, if we call it, create a cross-file edge
  fileCalls.forEach(call => {
    // Check if the callee matches an import
    const matchingImport = imports.imports.find(imp => 
      imp.local === call.callee || 
      call.callee.startsWith(imp.local + '.')
    );
    
    if (matchingImport) {
      crossCalls.push({
        from: { file: filename, symbol: call.caller },
        to: { file: resolveImportPath(matchingImport.source, filename), symbol: call.callee },
        confidence: 0.8 // Cross-file calls have slightly lower confidence
      });
    }
  });
  
  return crossCalls;
}

// Helper: Resolve relative import paths
function resolveImportPath(importPath, fromFile) {
  if (importPath.startsWith('.')) {
    // Relative import
    const fromDir = path.dirname(fromFile);
    return path.resolve(fromDir, importPath + '.js'); // Simplified
  }
  // Absolute or node_modules import - return as-is
  return importPath;
}

// Build shallow call graph for BFS traversal
function buildCallGraph(calls) {
  const graph = new Map(); // symbol -> Set of connected symbols
  
  calls.forEach(call => {
    const from = `${call.from?.file || ''}:${call.from?.symbol || call.caller}`;
    const to = `${call.to?.file || ''}:${call.to?.symbol || call.callee}`;
    
    if (!graph.has(from)) graph.set(from, new Set());
    graph.get(from).add(to);
  });
  
  return graph;
}

// BFS traversal to find reachable symbols within depth limit
function bfsSymbols(startHandler, calls, maxDepth) {
  const graph = buildCallGraph(calls);
  const visited = new Set();
  const queue = [{ symbol: `${startHandler.file}:${startHandler.symbol}`, depth: 0 }];
  const reachable = [];
  
  while (queue.length > 0) {
    const { symbol, depth } = queue.shift();
    
    if (visited.has(symbol) || depth > maxDepth) continue;
    visited.add(symbol);
    reachable.push(symbol);
    
    // Add neighbors
    const neighbors = graph.get(symbol) || new Set();
    neighbors.forEach(neighbor => {
      if (!visited.has(neighbor)) {
        queue.push({ symbol: neighbor, depth: depth + 1 });
      }
    });
  }
  
  return reachable;
}

// Match DB references against reachable symbols
function matchDbRefs(reachableSymbols, allDbRefs) {
  const matches = [];
  
  reachableSymbols.forEach(symbol => {
    allDbRefs.forEach(dbRef => {
      const dbSymbol = `${dbRef.file}:${dbRef.symbol}`;
      if (symbol === dbSymbol || symbol.endsWith(`:${dbRef.symbol}`)) {
        matches.push(dbRef);
      }
    });
  });
  
  return matches;
}

module.exports = {
  analyzeChangedFiles,
  bfsSymbols,
  matchDbRefs
};