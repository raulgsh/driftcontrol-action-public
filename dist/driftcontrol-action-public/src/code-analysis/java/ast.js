// AST parsing utilities using tree-sitter for Java
let TreeSitter, Java, parser;

try {
  TreeSitter = require('tree-sitter');
  Java = require('tree-sitter-java');
  
  // Initialize parser
  parser = new TreeSitter();
  parser.setLanguage(Java);
} catch (error) {
  console.warn('Java tree-sitter dependencies not found. Java code analysis will be disabled.');
  parser = null;
}

// Parse Java file into AST
function parseFile(content, filename) {
  if (!parser) {
    console.warn('Java parser not available. Skipping Java file:', filename);
    return null;
  }
  
  try {
    return parser.parse(content);
  } catch (error) {
    console.warn(`Java parsing failed for ${filename}:`, error.message);
    return null;
  }
}

// Extract imports for call graph
function extractImportsExports(ast, filename) {
  const imports = []; // { local: 'List', source: 'java.util.List', imported: 'List' }
  const exports = []; // Track public classes/methods
  
  if (!ast) return { imports, exports, requires: [] };
  
  const content = getContent(filename);
  
  walkNode(ast.rootNode, (node) => {
    // import statements
    if (node.type === 'import_declaration') {
      const scoped_identifier = node.namedChildren.find(child => 
        child.type === 'scoped_identifier' || child.type === 'identifier'
      );
      
      if (scoped_identifier) {
        const importPath = getNodeText(scoped_identifier, content);
        const className = importPath.split('.').pop();
        
        imports.push({
          local: className,
          source: importPath,
          imported: className,
          line: node.startPosition.row + 1
        });
      }
    }
    
    // static imports: import static java.util.Collections.*
    if (node.type === 'import_declaration') {
      const static_keyword = node.namedChildren.find(child => child.type === 'static');
      if (static_keyword) {
        const scoped_identifier = node.namedChildren.find(child => 
          child.type === 'scoped_identifier' || child.type === 'identifier'
        );
        
        if (scoped_identifier) {
          const importPath = getNodeText(scoped_identifier, content);
          const methodName = importPath.split('.').pop();
          
          imports.push({
            local: methodName,
            source: importPath,
            imported: methodName,
            line: node.startPosition.row + 1
          });
        }
      }
    }
    
    // Track public classes and methods as exports
    if (node.type === 'class_declaration') {
      const modifiers = node.namedChildren.filter(child => child.type === 'modifiers');
      const has_public = modifiers.some(mod => 
        mod.namedChildren.some(child => child.type === 'public')
      );
      
      if (has_public) {
        const name_node = node.namedChildren.find(child => child.type === 'identifier');
        if (name_node) {
          const className = getNodeText(name_node, content);
          exports.push({
            local: className,
            exported: className,
            line: name_node.startPosition.row + 1
          });
        }
      }
    }
    
    // Track public methods
    if (node.type === 'method_declaration') {
      const modifiers = node.namedChildren.filter(child => child.type === 'modifiers');
      const has_public = modifiers.some(mod => 
        mod.namedChildren.some(child => child.type === 'public')
      );
      
      if (has_public) {
        const name_node = node.namedChildren.find(child => child.type === 'identifier');
        if (name_node) {
          const methodName = getNodeText(name_node, content);
          exports.push({
            local: methodName,
            exported: methodName,
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
  const calls = []; // { caller: 'methodName', callee: 'calledMethod', line: 42 }
  
  if (!ast) return calls;
  
  let currentMethod = null;
  const sourceText = content || '';
  
  walkNode(ast.rootNode, (node) => {
    // Track current method context
    if (node.type === 'method_declaration') {
      const name_node = node.namedChildren.find(child => child.type === 'identifier');
      if (name_node) {
        currentMethod = getNodeText(name_node, sourceText);
      }
    }
    
    // Track constructor context
    if (node.type === 'constructor_declaration') {
      const name_node = node.namedChildren.find(child => child.type === 'identifier');
      if (name_node) {
        currentMethod = getNodeText(name_node, sourceText);
      }
    }
    
    // Find method invocations
    if (node.type === 'method_invocation') {
      const name_node = node.namedChildren.find(child => child.type === 'identifier');
      if (name_node && currentMethod) {
        const callee = getNodeText(name_node, sourceText);
        calls.push({
          caller: currentMethod,
          callee: callee,
          line: node.startPosition.row + 1
        });
      }
    }
    
    // Constructor calls
    if (node.type === 'object_creation_expression') {
      const type_node = node.namedChildren.find(child => 
        child.type === 'type_identifier' || child.type === 'generic_type'
      );
      if (type_node && currentMethod) {
        let callee;
        if (type_node.type === 'type_identifier') {
          callee = getNodeText(type_node, content);
        } else {
          // For generic types, get the base type
          const base_type = type_node.namedChildren.find(child => child.type === 'type_identifier');
          if (base_type) {
            callee = getNodeText(base_type, content);
          }
        }
        
        if (callee) {
          calls.push({
            caller: currentMethod,
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

module.exports = {
  parseFile,
  extractImportsExports,
  extractCalls
};