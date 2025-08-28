// AST parsing utilities using tree-sitter for Go
let TreeSitter, Go, parser;

try {
  TreeSitter = require('tree-sitter');
  Go = require('tree-sitter-go');
  
  // Initialize parser
  parser = new TreeSitter();
  parser.setLanguage(Go);
} catch (error) {
  console.warn('Go tree-sitter dependencies not found. Go code analysis will be disabled.');
  parser = null;
}

// Parse Go file into AST
function parseFile(content, filename) {
  if (!parser) {
    console.warn('Go parser not available. Skipping Go file:', filename);
    return null;
  }
  
  try {
    return parser.parse(content);
  } catch (error) {
    console.warn(`Go parsing failed for ${filename}:`, error.message);
    return null;
  }
}

// Extract imports for call graph
function extractImportsExports(ast, filename) {
  const imports = []; // { local: 'foo', source: 'github.com/foo/bar', imported: 'foo' }
  const exports = []; // Track exported functions/types
  
  if (!ast) return { imports, exports, requires: [] };
  
  const content = getContent(filename);
  
  walkNode(ast.rootNode, (node) => {
    // import "package"
    if (node.type === 'import_declaration') {
      const import_specs = node.namedChildren.filter(child => child.type === 'import_spec');
      import_specs.forEach(spec => {
        const path_node = spec.namedChildren.find(child => child.type === 'interpreted_string_literal');
        if (path_node) {
          const importPath = getNodeText(path_node, content).replace(/"/g, '');
          const package_name = importPath.split('/').pop();
          
          // Check for alias
          const identifier_node = spec.namedChildren.find(child => child.type === 'package_identifier');
          const local_name = identifier_node ? getNodeText(identifier_node, content) : package_name;
          
          imports.push({
            local: local_name,
            source: importPath,
            imported: 'package',
            line: spec.startPosition.row + 1
          });
        }
      });
    }
    
    // Track exported functions (capitalized names)
    if (node.type === 'function_declaration') {
      const name_node = node.namedChildren.find(child => child.type === 'identifier');
      if (name_node) {
        const funcName = getNodeText(name_node, content);
        if (isExported(funcName)) {
          exports.push({
            local: funcName,
            exported: funcName,
            line: name_node.startPosition.row + 1
          });
        }
      }
    }
  });
  
  return { imports, exports, requires: [] };
}

// Extract function calls for call graph
function extractCalls(ast, content) {
  const calls = []; // { caller: 'function_name', callee: 'called_function', line: 42 }
  
  if (!ast) return calls;
  
  let currentFunction = null;
  const sourceText = content || '';
  
  walkNode(ast.rootNode, (node) => {
    // Track current function context
    if (node.type === 'function_declaration') {
      const name_node = node.namedChildren.find(child => child.type === 'identifier');
      if (name_node) {
        currentFunction = getNodeText(name_node, sourceText);
      }
    }
    
    // Track method declarations too
    if (node.type === 'method_declaration') {
      const name_node = node.namedChildren.find(child => child.type === 'field_identifier');
      if (name_node) {
        currentFunction = getNodeText(name_node, sourceText);
      }
    }
    
    // Find function calls
    if (node.type === 'call_expression') {
      const function_node = node.namedChild(0);
      if (function_node) {
        const callee = extractCalleeFromNode(function_node, sourceText);
        if (callee && currentFunction) {
          calls.push({
            caller: currentFunction,
            callee: callee,
            line: node.startPosition.row + 1
          });
        }
      }
    }
  });
  
  return calls;
}

// Helper: Walk AST node recursively
function walkNode(node, callback) {
  callback(node);
  for (let i = 0; i < node.namedChildCount; i++) {
    walkNode(node.namedChild(i), callback);
  }
}

// Helper: Get text content of a node
function getNodeText(node, sourceText) {
  return sourceText.slice(node.startIndex, node.endIndex);
}

// Helper: Get file content (stub)
function getContent(filename) {
  // In a real implementation, this would get the file content
  return '';
}

// Helper: Check if identifier is exported (starts with capital letter in Go)
function isExported(name) {
  return name && name[0] === name[0].toUpperCase();
}

// Helper: Extract function name from call expression
function extractCalleeFromNode(node, content) {
  if (node.type === 'identifier') {
    return getNodeText(node, content);
  } else if (node.type === 'selector_expression') {
    // For package.Function or obj.Method calls, return the method name
    const field_node = node.namedChildren.find(child => child.type === 'field_identifier');
    if (field_node) {
      return getNodeText(field_node, content);
    }
  }
  return null;
}

module.exports = {
  parseFile,
  extractImportsExports,
  extractCalls
};