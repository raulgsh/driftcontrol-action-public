// API and database detection for Python via tree-sitter AST traversal

// Detect API handlers in Python (Flask, FastAPI, Django)
function detectApiHandlers(ast, filename, content) {
  const handlers = []; // { method: 'GET', path: '/users', file: filename, symbol: 'get_users', line: 42 }
  
  if (!ast || !ast.rootNode) return handlers;
  
  let currentFunction = null;
  
  walkNode(ast.rootNode, (node) => {
    // Track current function
    if (node.type === 'function_definition') {
      const name_node = node.namedChildren.find(child => child.type === 'identifier');
      if (name_node) {
        currentFunction = getNodeText(name_node, content);
      }
    }
    
    // Flask patterns: @app.route('/path', methods=['GET'])
    if (node.type === 'decorator') {
      const decorator_call = node.namedChild(0);
      if (decorator_call && decorator_call.type === 'call') {
        const function_node = decorator_call.namedChild(0);
        
        // Check for Flask route decorators
        if (function_node && function_node.type === 'attribute') {
          const attr_text = getNodeText(function_node, content);
          if (attr_text.includes('.route')) {
            const { path, methods } = extractFlaskRouteInfo(decorator_call, content);
            if (path) {
              methods.forEach(method => {
                handlers.push({
                  method: method.toUpperCase(),
                  path: path,
                  file: filename,
                  symbol: currentFunction || 'anonymous',
                  line: node.startPosition.row + 1
                });
              });
            }
          }
        }
        
        // Check for Flask method-specific decorators: @app.get('/path')
        if (function_node && function_node.type === 'attribute') {
          const attr_text = getNodeText(function_node, content);
          const method_match = attr_text.match(/\.(get|post|put|patch|delete|head|options)$/i);
          if (method_match) {
            const method = method_match[1].toUpperCase();
            const path = extractPathFromArguments(decorator_call, content);
            if (path) {
              handlers.push({
                method: method,
                path: path,
                file: filename,
                symbol: currentFunction || 'anonymous',
                line: node.startPosition.row + 1
              });
            }
          }
        }
      }
    }
    
    // FastAPI patterns: @app.get("/items/{item_id}")
    if (node.type === 'decorator') {
      const decorator_call = node.namedChild(0);
      if (decorator_call && decorator_call.type === 'call') {
        const function_node = decorator_call.namedChild(0);
        
        if (function_node && function_node.type === 'attribute') {
          const attr_text = getNodeText(function_node, content);
          const fastapi_match = attr_text.match(/\.(get|post|put|patch|delete|head|options)$/i);
          if (fastapi_match) {
            const method = fastapi_match[1].toUpperCase();
            const path = extractPathFromArguments(decorator_call, content);
            if (path) {
              handlers.push({
                method: method,
                path: path,
                file: filename,
                symbol: currentFunction || 'anonymous',
                line: node.startPosition.row + 1
              });
            }
          }
        }
      }
    }
  });
  
  return handlers;
}

// Detect database operations in Python (SQLAlchemy, Django ORM)
function detectDbOperations(ast, filename, content) {
  const dbRefs = []; // { orm: 'sqlalchemy', table: 'users', op: 'query', file: filename, symbol: 'get_users', line: 42 }
  
  if (!ast || !ast.rootNode) return dbRefs;
  
  let currentFunction = null;
  
  walkNode(ast.rootNode, (node) => {
    // Track current function
    if (node.type === 'function_definition') {
      const name_node = node.namedChildren.find(child => child.type === 'identifier');
      if (name_node) {
        currentFunction = getNodeText(name_node, content);
      }
    }
    
    // SQLAlchemy patterns: User.query.filter(), session.query(User)
    if (node.type === 'call') {
      const function_node = node.namedChild(0);
      
      // Model.query.method() patterns
      if (function_node && function_node.type === 'attribute') {
        const attr_chain = extractAttributeChain(function_node, content);
        const sqlalchemy_match = attr_chain.match(/^(\w+)\.query\.(\w+)/);
        if (sqlalchemy_match) {
          const [, model, operation] = sqlalchemy_match;
          if (isSQLAlchemyOperation(operation)) {
            dbRefs.push({
              orm: 'sqlalchemy',
              table: camelToSnake(model),
              op: operation,
              file: filename,
              symbol: currentFunction || 'anonymous',
              line: node.startPosition.row + 1
            });
          }
        }
      }
      
      // session.query(Model) patterns
      if (function_node && function_node.type === 'attribute') {
        const attr_text = getNodeText(function_node, content);
        if (attr_text.includes('.query')) {
          const argument_list = node.namedChildren.find(child => child.type === 'argument_list');
          if (argument_list) {
            const model_arg = argument_list.namedChildren.find(child => child.type === 'identifier');
            if (model_arg) {
              const model = getNodeText(model_arg, content);
              dbRefs.push({
                orm: 'sqlalchemy',
                table: camelToSnake(model),
                op: 'query',
                file: filename,
                symbol: currentFunction || 'anonymous',
                line: node.startPosition.row + 1
              });
            }
          }
        }
      }
    }
    
    // Django ORM patterns: User.objects.filter(), User.objects.create()
    if (node.type === 'call') {
      const function_node = node.namedChild(0);
      
      if (function_node && function_node.type === 'attribute') {
        const attr_chain = extractAttributeChain(function_node, content);
        const django_match = attr_chain.match(/^(\w+)\.objects\.(\w+)/);
        if (django_match) {
          const [, model, operation] = django_match;
          if (isDjangoOperation(operation)) {
            dbRefs.push({
              orm: 'django',
              table: camelToSnake(model),
              op: operation,
              file: filename,
              symbol: currentFunction || 'anonymous',
              line: node.startPosition.row + 1
            });
          }
        }
      }
    }
    
    // Peewee ORM patterns: User.select().where(), User.get(), User.create()
    if (node.type === 'call') {
      const function_node = node.namedChild(0);
      
      // Direct model operations: User.get(), User.create()
      if (function_node && function_node.type === 'attribute') {
        const attr_chain = extractAttributeChain(function_node, content);
        const peewee_direct_match = attr_chain.match(/^(\w+)\.(\w+)$/);
        if (peewee_direct_match) {
          const [, model, operation] = peewee_direct_match;
          if (isPeeweeOperation(operation) && isCapitalized(model)) {
            dbRefs.push({
              orm: 'peewee',
              table: camelToSnake(model),
              op: operation,
              file: filename,
              symbol: currentFunction || 'anonymous',
              line: node.startPosition.row + 1
            });
          }
        }
        
        // Chained operations: User.select().where()
        const peewee_chain_match = attr_chain.match(/^(\w+)\.select\.(\w+)/);
        if (peewee_chain_match) {
          const [, model, operation] = peewee_chain_match;
          if (['where', 'limit', 'order_by', 'join'].includes(operation)) {
            dbRefs.push({
              orm: 'peewee',
              table: camelToSnake(model),
              op: 'select',
              file: filename,
              symbol: currentFunction || 'anonymous',
              line: node.startPosition.row + 1
            });
          }
        }
      }
    }
  });
  
  return dbRefs;
}

// Helper functions
function walkNode(node, callback, content) {
  callback(node, content);
  for (let i = 0; i < node.namedChildCount; i++) {
    walkNode(node.namedChild(i), callback, content);
  }
}

function getNodeText(node, sourceText) {
  return sourceText.slice(node.startIndex, node.endIndex);
}

function getContent(filename) {
  // Content is passed from the main orchestrator via the content parameter
  // This function is kept for compatibility but shouldn't be used
  return '';
}

function extractFlaskRouteInfo(decorator_call, content) {
  let path = null;
  let methods = ['GET']; // Default to GET
  
  const argument_list = decorator_call.namedChildren.find(child => child.type === 'argument_list');
  if (argument_list) {
    argument_list.namedChildren.forEach(arg => {
      if (arg.type === 'string') {
        path = getNodeText(arg, content).replace(/['"]/g, '');
      } else if (arg.type === 'keyword_argument') {
        const name_node = arg.namedChildren.find(child => child.type === 'identifier');
        const value_node = arg.namedChildren.find(child => child.type !== 'identifier');
        
        if (name_node && getNodeText(name_node, content) === 'methods' && value_node) {
          if (value_node.type === 'list') {
            methods = [];
            value_node.namedChildren.forEach(item => {
              if (item.type === 'string') {
                methods.push(getNodeText(item, content).replace(/['"]/g, ''));
              }
            });
          }
        }
      }
    });
  }
  
  return { path, methods };
}

function extractPathFromArguments(decorator_call, content) {
  const argument_list = decorator_call.namedChildren.find(child => child.type === 'argument_list');
  if (argument_list) {
    const first_arg = argument_list.namedChild(0);
    if (first_arg && first_arg.type === 'string') {
      return getNodeText(first_arg, content).replace(/['"]/g, '');
    }
  }
  return null;
}

function extractAttributeChain(node, content) {
  let chain = '';
  
  function buildChain(n) {
    if (n.type === 'identifier') {
      return getNodeText(n, content);
    } else if (n.type === 'attribute') {
      const object_node = n.namedChild(0);
      const attribute_node = n.namedChildren.find(child => child.type === 'identifier');
      if (object_node && attribute_node) {
        return buildChain(object_node) + '.' + getNodeText(attribute_node, content);
      }
    }
    return '';
  }
  
  return buildChain(node);
}

function isSQLAlchemyOperation(operation) {
  return ['query', 'filter', 'filter_by', 'all', 'first', 'get', 'count', 'delete', 'update'].includes(operation);
}

function isDjangoOperation(operation) {
  return ['filter', 'get', 'create', 'update', 'delete', 'all', 'first', 'count', 'exists'].includes(operation);
}

function isPeeweeOperation(operation) {
  return ['select', 'insert', 'update', 'delete', 'get', 'get_or_create', 'create', 'save'].includes(operation);
}

function isCapitalized(str) {
  return str && str.charAt(0) === str.charAt(0).toUpperCase();
}

function camelToSnake(str) {
  return str.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`).replace(/^_/, '').toLowerCase();
}

module.exports = {
  detectApiHandlers,
  detectDbOperations
};