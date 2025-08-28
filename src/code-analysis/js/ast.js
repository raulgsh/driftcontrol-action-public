// AST parsing utilities using acorn
const acorn = require('acorn');
const walk = require('acorn-walk');

// Parse JS/TS file into AST
function parseFile(content, filename) {
  try {
    return acorn.parse(content, {
      ecmaVersion: 2022,
      sourceType: 'module',
      allowReturnOutsideFunction: true,
      allowImportExportEverywhere: true,
      locations: true
    });
  } catch (e) {
    // Try as CommonJS if module parsing fails
    try {
      return acorn.parse(content, {
        ecmaVersion: 2022,
        sourceType: 'script',
        allowReturnOutsideFunction: true,
        locations: true
      });
    } catch (e2) {
      // Both failed - likely syntax error or unsupported syntax
      return null;
    }
  }
}

// Extract imports and exports for call graph
function extractImportsExports(ast, filename, content) {
  const imports = []; // { local: 'foo', source: './bar', imported: 'default' }
  const exports = []; // { local: 'foo', exported: 'foo' }
  const requires = []; // { local: 'foo', source: './bar' }
  
  if (!ast) return { imports, exports, requires };
  
  walk.simple(ast, {
    ImportDeclaration(node) {
      const source = node.source.value;
      node.specifiers.forEach(spec => {
        if (spec.type === 'ImportDefaultSpecifier') {
          imports.push({
            local: spec.local.name,
            source,
            imported: 'default',
            line: spec.loc?.start.line
          });
        } else if (spec.type === 'ImportSpecifier') {
          imports.push({
            local: spec.local.name,
            source,
            imported: spec.imported.name,
            line: spec.loc?.start.line
          });
        } else if (spec.type === 'ImportNamespaceSpecifier') {
          imports.push({
            local: spec.local.name,
            source,
            imported: '*',
            line: spec.loc?.start.line
          });
        }
      });
    },
    
    ExportNamedDeclaration(node) {
      if (node.specifiers) {
        node.specifiers.forEach(spec => {
          exports.push({
            local: spec.local?.name,
            exported: spec.exported.name,
            line: spec.loc?.start.line
          });
        });
      }
      if (node.declaration) {
        // export function foo() {} or export const foo = {}
        if (node.declaration.type === 'FunctionDeclaration') {
          exports.push({
            local: node.declaration.id.name,
            exported: node.declaration.id.name,
            line: node.declaration.loc?.start.line
          });
        } else if (node.declaration.type === 'VariableDeclaration') {
          node.declaration.declarations.forEach(decl => {
            if (decl.id.name) {
              exports.push({
                local: decl.id.name,
                exported: decl.id.name,
                line: decl.loc?.start.line
              });
            }
          });
        }
      }
    },
    
    ExportDefaultDeclaration(node) {
      exports.push({
        local: node.declaration.name || 'default',
        exported: 'default',
        line: node.loc?.start.line
      });
    },
    
    // Handle CommonJS require() calls
    CallExpression(node) {
      if (node.callee.name === 'require' && 
          node.arguments.length === 1 && 
          node.arguments[0].type === 'Literal') {
        
        // Find assignment: const foo = require('./bar')
        let parent = node;
        while (parent && parent.type !== 'VariableDeclarator' && parent.type !== 'AssignmentExpression') {
          parent = parent.parent;
        }
        
        if (parent && parent.type === 'VariableDeclarator' && parent.id.name) {
          requires.push({
            local: parent.id.name,
            source: node.arguments[0].value,
            line: node.loc?.start.line
          });
        }
      }
    }
  });
  
  return { imports, exports, requires };
}

// Find function definitions
function extractFunctions(ast) {
  const functions = []; // { name: 'foo', line: 42, params: ['a', 'b'] }
  
  if (!ast) return functions;
  
  walk.simple(ast, {
    FunctionDeclaration(node) {
      functions.push({
        name: node.id.name,
        line: node.loc?.start.line,
        params: node.params.map(p => p.name),
        type: 'function'
      });
    },
    
    VariableDeclarator(node) {
      // const foo = function() {} or const foo = () => {}
      if ((node.init?.type === 'FunctionExpression' || node.init?.type === 'ArrowFunctionExpression') && 
          node.id.name) {
        functions.push({
          name: node.id.name,
          line: node.loc?.start.line,
          params: node.init.params?.map(p => p.name) || [],
          type: node.init.type === 'ArrowFunctionExpression' ? 'arrow' : 'function'
        });
      }
    }
  });
  
  return functions;
}

// Extract function calls for building call graph
function extractCalls(ast, content) {
  const calls = []; // { caller: 'foo', callee: 'bar', line: 42, args: 2 }
  
  if (!ast) return calls;
  
  walk.ancestor(ast, {
    CallExpression(node, ancestors) {
      // Find containing function
      let containingFunction = null;
      for (let i = ancestors.length - 1; i >= 0; i--) {
        const ancestor = ancestors[i];
        if (ancestor.type === 'FunctionDeclaration' && ancestor.id) {
          containingFunction = ancestor.id.name;
          break;
        } else if (ancestor.type === 'VariableDeclarator' && 
                   (ancestor.init?.type === 'FunctionExpression' || ancestor.init?.type === 'ArrowFunctionExpression')) {
          containingFunction = ancestor.id.name;
          break;
        }
      }
      
      // Extract callee name
      let calleeName = null;
      if (node.callee.type === 'Identifier') {
        calleeName = node.callee.name;
      } else if (node.callee.type === 'MemberExpression') {
        // obj.method() -> 'obj.method'
        if (node.callee.object.name && node.callee.property.name) {
          calleeName = `${node.callee.object.name}.${node.callee.property.name}`;
        }
      }
      
      if (calleeName && containingFunction) {
        calls.push({
          caller: containingFunction,
          callee: calleeName,
          line: node.loc?.start.line,
          args: node.arguments.length
        });
      }
    }
  });
  
  return calls;
}

module.exports = {
  parseFile,
  extractImportsExports,
  extractFunctions,
  extractCalls
};