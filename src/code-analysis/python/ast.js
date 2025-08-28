// AST parsing utilities using tree-sitter for Python
let TreeSitter, Python, parser;

try {
  TreeSitter = require('tree-sitter');
  Python = require('tree-sitter-python');
  
  // Initialize parser
  parser = new TreeSitter();
  parser.setLanguage(Python);
} catch (error) {
  console.warn('Python tree-sitter dependencies not found. Python code analysis will be disabled.');
  parser = null;
}

// Parse Python file into AST
function parseFile(content, filename) {
  if (!parser) {
    console.warn('Python parser not available. Skipping Python file:', filename);
    return null;
  }
  
  try {
    return parser.parse(content);
  } catch (error) {
    console.warn(`Python parsing failed for ${filename}:`, error.message);
    return null;
  }
}

// Extract imports for call graph
function extractImportsExports(ast, filename, content) {
  const imports = []; // { local: 'foo', source: 'bar', imported: 'foo' }
  const exports = []; // Python doesn't have explicit exports, track __all__ or module-level definitions
  
  if (!ast) return { imports, exports, requires: [] };
  
  // Walk the AST to find import statements
  walkNode(ast.rootNode, (node) => {
    // import foo
    if (node.type === 'import_statement') {
      const dotted_names = node.namedChildren.filter(child => child.type === 'dotted_name' || child.type === 'identifier');
      dotted_names.forEach(dotted_name => {
        const moduleName = getNodeText(dotted_name, content);
        imports.push({
          local: moduleName.split('.').pop(), // Last part as local name
          source: moduleName,
          imported: 'module',
          line: dotted_name.startPosition.row + 1
        });
      });
    }
    
    // from foo import bar, baz
    if (node.type === 'import_from_statement') {
      const module_name = node.namedChildren.find(child => child.type === 'dotted_name' || child.type === 'identifier');
      const import_list = node.namedChildren.find(child => child.type === 'import_list');
      
      if (module_name && import_list) {
        const moduleName = getNodeText(module_name, content);
        const imported_names = import_list.namedChildren.filter(child => 
          child.type === 'import_star' || child.type === 'identifier' || child.type === 'aliased_import'
        );
        
        imported_names.forEach(imported => {
          if (imported.type === 'import_star') {
            imports.push({
              local: '*',
              source: moduleName,
              imported: '*',
              line: imported.startPosition.row + 1
            });
          } else if (imported.type === 'identifier') {
            const importName = getNodeText(imported, content);
            imports.push({
              local: importName,
              source: moduleName,
              imported: importName,
              line: imported.startPosition.row + 1
            });
          } else if (imported.type === 'aliased_import') {
            const name_node = imported.namedChildren.find(child => child.type === 'identifier');
            const alias_node = imported.namedChildren.find(child => child.type === 'identifier' && child !== name_node);
            if (name_node) {
              const importName = getNodeText(name_node, content);
              const localName = alias_node ? getNodeText(alias_node, content) : importName;
              imports.push({
                local: localName,
                source: moduleName,
                imported: importName,
                line: imported.startPosition.row + 1
              });
            }
          }
        });
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
    if (node.type === 'function_definition') {
      const name_node = node.namedChildren.find(child => child.type === 'identifier');
      if (name_node) {
        currentFunction = getNodeText(name_node, sourceText);
      }
    }
    
    // Find function calls
    if (node.type === 'call') {
      const function_node = node.namedChild(0); // First child is the function being called
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

// Helper: Extract function name from call expression
function extractCalleeFromNode(node, content) {
  if (node.type === 'identifier') {
    return getNodeText(node, content);
  } else if (node.type === 'attribute') {
    // For obj.method calls, return the method name
    const attribute_node = node.namedChildren.find(child => child.type === 'identifier');
    if (attribute_node) {
      return getNodeText(attribute_node, content);
    }
  }
  return null;
}

module.exports = {
  parseFile,
  extractImportsExports,
  extractCalls
};